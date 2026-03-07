# HPC Admin — Software Specification

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Authentication & Route Protection](#2-authentication--route-protection)
3. [Shared Infrastructure](#3-shared-infrastructure)
4. [TimescaleDB Schema](#4-timescaledb-schema)
5. [etcd Key Structure](#5-etcd-key-structure)
6. [Status Derivation Logic](#6-status-derivation-logic)
7. [Dual-Write Pattern](#7-dual-write-pattern)
8. [Config Snapshot JSONB Format](#8-config-snapshot-jsonb-format)
9. [API Routes — Full Logic](#9-api-routes--full-logic)
10. [Frontend Pages](#10-frontend-pages)
11. [Environment Variables](#11-environment-variables)

---

## 1. System Overview

### HPC Pipeline Architecture

```
Compute Nodes
     │  (gRPC)
     ▼
Collect Agents  ──────────────────────────────────────────────────────┐
     │  (Kafka produce)                                                │
     ▼                                                                 │
  Kafka                                                                │
   ├──► InfluxDB          (real-time raw metrics)                      │
   └──► TimescaleDB       (aggregated hourly — continuous aggregate)   │
                                                                       │
                          Admin Web App                                │
                          ┌────────────────────────────────────────┐  │
                          │  Next.js 16 App Router (TypeScript)    │  │
                          │                                        │  │
                          │  reads:  TimescaleDB (pg pool)         │  │
                          │  reads:  etcd (current config state)   │  │
                          │  writes: TimescaleDB (admin tables)    │◄─┘
                          │  writes: etcd (config KV)              │
                          │  embeds: Grafana iframes               │
                          └────────────────────────────────────────┘
```

### Data Flow Summary

| Direction | Path | Purpose |
|-----------|------|---------|
| Ingest | Compute Node → gRPC → Collect Agent | Raw metrics stream |
| Ingest | Collect Agent → Kafka | Fan-out to storage |
| Storage | Kafka → InfluxDB | Real-time raw data |
| Storage | Kafka → TimescaleDB | Hourly continuous aggregates |
| Config read | Admin UI → TimescaleDB | Read admin tables (nodes, rules, etc.) |
| Config read | Admin UI → etcd | Read current live config state |
| Config write | Admin UI → TimescaleDB | Persist rule/node changes |
| Config write | Admin UI → etcd | Push config to live agents (non-fatal) |
| Config apply | etcd → Collect Agents | Agents watch keys, reload without restart |
| Visualisation | Admin UI → Grafana (iframe) | Metric dashboards |

### External Services

| Service | Role | Client Library |
|---------|------|----------------|
| TimescaleDB | Admin tables + aggregated metrics | `pg` (node-postgres) |
| InfluxDB | Real-time raw metrics (Phase 3) | `@influxdata/influxdb-client` |
| etcd | Live config KV store for agents | `etcd3` |
| Grafana | Metric dashboard iframes | HTTP iframe embed |

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | Next.js 16 App Router |
| Language | TypeScript |
| Styling | Tailwind v4 (`@import "tailwindcss"` + `@theme` in globals.css) |
| Auth | Auth.js v5 / next-auth@beta |
| DB client | node-postgres (`pg`) |
| etcd client | `etcd3` |
| UI state | React hooks (`useState`, `useEffect`) |

---

## 2. Authentication & Route Protection

### Credentials Model

Authentication uses a **single admin account** configured via environment variables:

```
ADMIN_EMAIL     — the login email
ADMIN_PASSWORD  — the login password (plain text, compared at runtime)
```

There are no user accounts in the database for the admin web app. All authenticated sessions represent the same administrator.

### Auth.js v5 Credentials Provider (`src/auth.ts`)

```
authorize(credentials) {
  if credentials.email === ADMIN_EMAIL && credentials.password === ADMIN_PASSWORD
    return { id: "1", email: ADMIN_EMAIL, name: "Admin" }
  else
    return null  // triggers sign-in failure
}
```

- Session strategy: **JWT** (stateless — no database sessions table)
- Token signed with `NEXTAUTH_SECRET`
- Auth.js exports `{ auth, handlers, signIn, signOut }`

### Middleware Route Guard (`src/proxy.ts`)

Exports `{ auth as proxy }` and is mounted as Next.js middleware at the root.

**Allow-list** (bypass auth check):
- `/api/auth/**` — Auth.js internal routes (login POST, session GET, CSRF)
- `/_next/**` — Static assets and HMR
- `/login` — Login page itself

All other routes (every page under `/(protected)/` and every API route) require a valid JWT session. Unauthenticated requests are redirected to `/login`.

### Protected Layout (`src/app/(protected)/layout.tsx`)

Server component. Calls `auth()` from Auth.js; if the session is `null`, calls `redirect("/login")`. This provides a secondary server-side guard on top of the middleware.

### Login Flow

```
User submits form (/login)
  │
  ▼
signIn("credentials", { email, password, redirectTo: "/dashboard" })
  │
  ├─ success → Auth.js sets JWT cookie → redirect to /dashboard
  └─ failure → redirect to /login?error=CredentialsSignin
```

---

## 3. Shared Infrastructure

### DB Pool (`src/lib/db.ts`)

```typescript
import { Pool } from "pg";
export const pool = new Pool({ connectionString: process.env.TIMESCALE_URL });
```

**Usage pattern in every route handler:**

```typescript
const client = await pool.connect();
try {
  const result = await client.query(SQL, [params]);
  return NextResponse.json(result.rows);
} catch (err) {
  return NextResponse.json({ error: "..." }, { status: 500 });
} finally {
  client.release();   // always release back to pool
}
```

The pool is module-level (singleton) — Node.js module caching ensures a single pool across the entire process.

### etcd Client (`src/lib/etcd.ts`)

```typescript
import { Etcd3 } from "etcd3";
export const etcd = new Etcd3({ hosts: process.env.ETCD_URL ?? "http://localhost:2379" });
```

All etcd operations are async. Routes catch etcd errors independently from DB errors so a DB write is never blocked by etcd availability.

---

## 4. TimescaleDB Schema

All tables are in the default `public` schema. `db/schema.sql` contains the full DDL.

### Admin Tables (read + write)

#### `nodes` — Compute Node Registry

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | TEXT | PRIMARY KEY |
| `name` | TEXT | NOT NULL |
| `ip` | TEXT | |
| `group_name` | TEXT | |
| `collect_agent` | TEXT | which agent handles this node |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() |

#### `hpc_users` — HPC User Accounts

| Column | Type | Constraints |
|--------|------|-------------|
| `uid` | INT | PRIMARY KEY — matches Linux UID from pipeline |
| `username` | TEXT | NOT NULL |
| `email` | TEXT | |
| `group_name` | TEXT | |

#### `collection_settings` — Per-Node Collection Configuration

| Column | Type | Constraints |
|--------|------|-------------|
| `node_id` | TEXT | PRIMARY KEY, FK → nodes(id) |
| `interval_seconds` | INT | DEFAULT 10 |
| `window_seconds` | INT | DEFAULT 60 |
| `collect_agent` | TEXT | |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() |

#### `pipeline_rules` — Preprocessing Rules

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() |
| `name` | TEXT | NOT NULL |
| `type` | TEXT | CHECK IN ('filter', 'aggregate', 'derive') |
| `resource` | TEXT | e.g. 'cpu', 'mem', 'gpu' |
| `condition` | TEXT | expression string |
| `enabled` | BOOL | DEFAULT TRUE |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() |

#### `alert_rules` — Threshold Alert Rules

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID | PRIMARY KEY |
| `name` | TEXT | NOT NULL |
| `node_group` | TEXT | target node group |
| `resource` | TEXT | e.g. 'cpu', 'mem', 'gpu', 'disk', 'net' |
| `operator` | TEXT | CHECK IN ('>', '<', '>=', '<=') |
| `threshold` | FLOAT | |
| `severity` | TEXT | CHECK IN ('info', 'warning', 'critical') |
| `enabled` | BOOL | DEFAULT TRUE |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() |

#### `notifications` — Alert Instances

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID | PRIMARY KEY |
| `rule_id` | UUID | FK → alert_rules(id) |
| `severity` | TEXT | |
| `message` | TEXT | |
| `node_id` | TEXT | FK → nodes(id) |
| `acknowledged` | BOOL | DEFAULT FALSE |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() |

#### `config_versions` — Versioned Config Snapshots

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID | PRIMARY KEY |
| `version` | TEXT | semantic version string, e.g. "1.3.0" |
| `author` | TEXT | |
| `description` | TEXT | |
| `config_snapshot` | JSONB | full config at time of snapshot |
| `active` | BOOL | only one row active at a time |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() |

#### `audit_logs` — Admin Action Trail

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID | PRIMARY KEY |
| `actor` | TEXT | admin email |
| `action` | TEXT | CHECK IN ('CREATE', 'UPDATE', 'DELETE', 'ROLLOUT', 'LOGIN') |
| `target` | TEXT | affected resource |
| `detail` | TEXT | human-readable description |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() |

#### `custom_dashboards` — Saved Chart Panels

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID | PRIMARY KEY |
| `title` | TEXT | NOT NULL |
| `user_uids` | INT[] | array of HPC user UIDs shown in panel |
| `resource` | TEXT | e.g. 'cpu', 'mem', 'gpu', 'disk' |
| `chart_type` | TEXT | e.g. 'line', 'bar', 'stacked' |
| `pinned` | BOOL | DEFAULT FALSE |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() |

---

### Pipeline Source Table (READ-ONLY)

#### `user_app_hourly` — TimescaleDB Continuous Aggregate

1-hour bucket aggregate over raw process metrics. The web app only reads this table; it is maintained by TimescaleDB automatically.

| Column | Type | Description |
|--------|------|-------------|
| `uid` | INT | Linux user UID |
| `comm` | TEXT | process command name (application) |
| `total_cpu_time_seconds` | FLOAT | sum of CPU time in bucket |
| `max_rss_memory_bytes` | BIGINT | peak RSS memory in bucket |
| `max_gpu_memory_mib` | FLOAT | peak GPU memory usage in bucket |
| `total_read_bytes` | BIGINT | total disk read bytes in bucket |
| `total_write_bytes` | BIGINT | total disk write bytes in bucket |
| `process_count` | INT | number of distinct process samples in bucket |
| `bucket_time` | TIMESTAMPTZ | start of the 1-hour bucket |

---

## 5. etcd Key Structure

All keys use the prefix `/config/`. Collect agents watch these prefixes and reload configuration live when any key changes.

### Compute Node Configuration

```
/config/compute_node/{nodeId}/target_collect_agent   → string: agent ID
/config/compute_node/{nodeId}/window                 → string: integer seconds
/config/compute_node/{nodeId}/heartbeat_interval     → string: integer seconds
/config/compute_node/{nodeId}/status                 → "running" | "stopped"
```

**Key path index reference** (for parsing flat KV result):

```
index:  0       1               2         3         4
path:  ""  / "config" / "compute_node" / nodeId / fieldName
```

### Collect Agent Configuration

```
/config/collect_agent/{agentId}/kafka_brokers        → JSON: ["host:port", ...]
/config/collect_agent/{agentId}/kafka_topic          → string
/config/collect_agent/{agentId}/grpc_port            → string: port number
/config/collect_agent/{agentId}/threshold_rules      → JSON: { resource_key: { max: N }, ... }
/config/collect_agent/{agentId}/pipeline_rules       → JSON: Rule[]
```

**Key path index reference:**

```
index:  0       1           2        3         4
path:  ""  / "config" / "collect_agent" / agentId / fieldName
```

### threshold_rules Object Shape

```json
{
  "cpu_usage_percent":    { "max": 90 },
  "memory_usage_percent": { "max": 85 },
  "gpu_max_utilization_percent": { "max": 95 },
  "disk_usage_percent":   { "max": 80 }
}
```

---

## 6. Status Derivation Logic

Node status is derived at runtime by combining the DB record (proves the node exists in the registry) with the etcd state (proves the node is actively configured).

```
etcd /config/compute_node/{nodeId}/status   →   UI NodeStatus
─────────────────────────────────────────────────────────────
"running"                                   →   "active"   (green dot)
"stopped"                                   →   "down"     (red dot)
key absent / node not in etcd               →   "idle"     (yellow dot)
```

**"idle"** means: the node is registered in the admin DB but has never been pushed to etcd, or its etcd keys were deleted. The node is not actively being monitored.

**buildSummary()** helper (used in dashboard + nodes list):

```
For each node in DB:
  etcdEntry = etcdMap.get(node.id)
  if !etcdEntry        → status = "idle"
  elif etcdEntry.status === "running"  → status = "active"
  else                 → status = "down"
```

---

## 7. Dual-Write Pattern

Several write operations must update both TimescaleDB (permanent record) and etcd (live config for agents). The invariant is:

> **DB is always the source of truth. etcd push is always non-fatal.**

Implementation pattern:

```typescript
// 1. Write to DB (required — fails the request if this fails)
await client.query("INSERT INTO ... / UPDATE ...", [...]);

// 2. Push to etcd (optional — logged but never fails the HTTP response)
etcd.put(key).value(val).exec().catch((err) => {
  console.error("etcd push failed (non-fatal):", err);
});
```

This means:
- If etcd is unreachable, the DB write still completes and a 200 is returned.
- The admin UI can show a warning that etcd may be out of sync.
- Operators can re-sync by using the "Push All" or "Push to Agents" buttons.

---

## 8. Config Snapshot JSONB Format

The `config_snapshot` column in `config_versions` stores a complete point-in-time snapshot of the cluster configuration. This is the format replayed during `rollout`.

```json
{
  "collection_settings": [
    {
      "node_id":          "node-01",
      "window_seconds":   60,
      "interval_seconds": 10,
      "collect_agent":    "agent-a"
    }
  ],
  "pipeline_rules": [
    {
      "id":        "uuid-...",
      "name":      "Drop zero-CPU",
      "type":      "filter",
      "resource":  "cpu",
      "condition": "value == 0"
    }
  ],
  "threshold_rules": {
    "cpu_usage_percent":           { "max": 90 },
    "memory_usage_percent":        { "max": 85 },
    "gpu_max_utilization_percent": { "max": 95 },
    "disk_usage_percent":          { "max": 80 }
  }
}
```

During `rollout`, the snapshot is replayed as follows:
- `collection_settings[]` → write `window`, `heartbeat_interval`, `target_collect_agent` per node in etcd
- `pipeline_rules[]` → write JSON array to `/config/collect_agent/{agentId}/pipeline_rules` for every discovered agent
- `threshold_rules` → write JSON object to `/config/collect_agent/{agentId}/threshold_rules` for every discovered agent

---

## 9. API Routes — Full Logic

All routes are under `src/app/api/`. Route handlers use the Next.js 16 App Router conventions:
- File: `route.ts` exporting named functions `GET`, `POST`, `PUT`, `DELETE`
- Dynamic segment params: `params` is a `Promise` → `const { nodeId } = await params`
- All responses: `NextResponse.json(data, { status: N })`

---

### Node Registry

#### `GET /api/nodes`

**Purpose:** List all compute nodes from the DB.

```sql
SELECT * FROM nodes ORDER BY name
```

Returns: `Node[]`

---

#### `POST /api/nodes`

**Purpose:** Register a new compute node.

**Body:** `{ id, name, ip?, group_name?, collect_agent? }`

```sql
INSERT INTO nodes (id, name, ip, group_name, collect_agent)
VALUES ($1, $2, $3, $4, $5)
RETURNING *
```

Returns: `Node` — 201 on success, 409 if `id` already exists (unique violation).

---

#### `GET /api/nodes/[nodeId]`

**Purpose:** Fetch a single node record.

```sql
SELECT * FROM nodes WHERE id = $1
```

Returns: `Node` — 404 if not found.

---

#### `PUT /api/nodes/[nodeId]`

**Purpose:** Update node metadata.

**Body:** `{ name?, ip?, group_name?, collect_agent? }`

```sql
UPDATE nodes
SET name=$2, ip=$3, group_name=$4, collect_agent=$5
WHERE id = $1
RETURNING *
```

Returns: `Node` — 404 if not found.

---

#### `DELETE /api/nodes/[nodeId]`

**Purpose:** Remove a node from the registry.

```sql
DELETE FROM nodes WHERE id = $1
```

Returns: `{ success: true }` — 404 if not found.

---

### etcd — Compute Node Config

#### `GET /api/etcd/nodes`

**Purpose:** Read all compute node configs from etcd.

1. `etcd.getAll().prefix("/config/compute_node/").strings()` → flat `{ key: value }` map
2. Parse: split each key on `/`, group by `keyParts[3]` (nodeId), collect `keyParts[4]` as field name
3. Build `EtcdNodeConfig[]`:
   ```
   {
     nodeId:             string,
     target_collect_agent: string,
     window:             string,
     heartbeat_interval: string,
     status:             "running" | "stopped"
   }
   ```

Returns: `EtcdNodeConfig[]`

---

#### `POST /api/etcd/nodes`

**Purpose:** Register a compute node in etcd with initial stopped state.

**Body:** `{ nodeId, target_collect_agent, window?, heartbeat_interval? }`

Writes 4 keys atomically via `Promise.all`:

```
/config/compute_node/{nodeId}/target_collect_agent  = body.target_collect_agent
/config/compute_node/{nodeId}/window                = body.window ?? "60"
/config/compute_node/{nodeId}/heartbeat_interval    = body.heartbeat_interval ?? "10"
/config/compute_node/{nodeId}/status                = "stopped"
```

Returns: `{ success: true, nodeId }`

---

#### `GET /api/etcd/nodes/[nodeId]`

**Purpose:** Read config for a single node from etcd.

1. Prefix-scan `/config/compute_node/{nodeId}/`
2. If result map is empty → 404
3. Return parsed `EtcdNodeConfig`

---

#### `PUT /api/etcd/nodes/[nodeId]`

**Purpose:** Update selected config fields for a node in etcd.

**Body:** `{ target_collect_agent?, window?, heartbeat_interval? }` (partial)

Only writes keys that are present in the request body:

```typescript
const writes = [];
if (body.target_collect_agent !== undefined)
  writes.push(etcd.put(`/config/compute_node/${nodeId}/target_collect_agent`).value(body.target_collect_agent));
if (body.window !== undefined)
  writes.push(etcd.put(`/config/compute_node/${nodeId}/window`).value(String(body.window)));
if (body.heartbeat_interval !== undefined)
  writes.push(etcd.put(`/config/compute_node/${nodeId}/heartbeat_interval`).value(String(body.heartbeat_interval)));
await Promise.all(writes);
```

Returns: `{ success: true, updated: string[] }` — 400 if no fields provided.

---

#### `DELETE /api/etcd/nodes/[nodeId]`

**Purpose:** Remove all etcd keys for a node.

```typescript
await etcd.delete().prefix(`/config/compute_node/${nodeId}/`).exec();
```

Returns: `{ success: true }`

---

#### `GET /api/etcd/nodes/[nodeId]/status`

**Purpose:** Read the live status of a single node.

```typescript
const status = await etcd.get(`/config/compute_node/${nodeId}/status`).string();
```

Returns: `{ nodeId, status: "running" | "stopped" | null }`

---

#### `PUT /api/etcd/nodes/[nodeId]/status`

**Purpose:** Start or stop collection for a node (single key write).

**Body:** `{ status: "running" | "stopped" }`

Validation: reject if status is not one of the two allowed values.

```typescript
await etcd.put(`/config/compute_node/${nodeId}/status`).value(body.status).exec();
```

Returns: `{ success: true, nodeId, status }`

---

### etcd — Collect Agent Config

#### `GET /api/etcd/agents`

**Purpose:** List all collect agent configs from etcd.

1. Prefix-scan `/config/collect_agent/` → flat KV map
2. Group by `keyParts[3]` (agentId), field name at `keyParts[4]`
3. JSON-parse `kafka_brokers` (array) and `threshold_rules` (object) fields
4. Return `EtcdAgentConfig[]`

---

#### `POST /api/etcd/agents`

**Purpose:** Register a new collect agent in etcd.

**Body:** `{ agentId, kafka_brokers: string[], kafka_topic, grpc_port, threshold_rules? }`

Writes 4 keys:

```
/config/collect_agent/{agentId}/kafka_brokers    = JSON.stringify(kafka_brokers)
/config/collect_agent/{agentId}/kafka_topic      = kafka_topic
/config/collect_agent/{agentId}/grpc_port        = String(grpc_port)
/config/collect_agent/{agentId}/threshold_rules  = JSON.stringify(threshold_rules ?? defaultThresholds)
```

Default `threshold_rules`:
```json
{
  "cpu_usage_percent":           { "max": 90 },
  "memory_usage_percent":        { "max": 85 },
  "gpu_max_utilization_percent": { "max": 95 },
  "disk_usage_percent":          { "max": 80 }
}
```

Returns: `{ success: true, agentId }`

---

#### `GET /api/etcd/agents/[agentId]`

**Purpose:** Read config for a single agent.

Prefix-scan `/config/collect_agent/{agentId}/`. Returns parsed `EtcdAgentConfig` — 404 if empty.

---

#### `PUT /api/etcd/agents/[agentId]`

**Purpose:** Update non-threshold fields for an agent.

**Body:** `{ kafka_brokers?, kafka_topic?, grpc_port? }` (partial, `threshold_rules` has its own sub-route)

Conditional write — only writes keys present in body. `kafka_brokers` is JSON-stringified.

---

#### `DELETE /api/etcd/agents/[agentId]`

**Purpose:** Remove all etcd keys for an agent.

```typescript
await etcd.delete().prefix(`/config/collect_agent/${agentId}/`).exec();
```

---

#### `GET /api/etcd/agents/[agentId]/threshold-rules`

**Purpose:** Read the threshold rules for a single agent.

```typescript
const raw = await etcd.get(`/config/collect_agent/${agentId}/threshold_rules`).string();
return JSON.parse(raw);
```

Returns: `ThresholdRules` object or 404 if key absent.

---

#### `PUT /api/etcd/agents/[agentId]/threshold-rules`

**Purpose:** Overwrite the threshold rules for a single agent.

**Body:** `ThresholdRules` object

```typescript
await etcd.put(`/config/collect_agent/${agentId}/threshold_rules`).value(JSON.stringify(body)).exec();
```

Returns: `{ success: true, agentId }`

---

### Collection Settings

#### `GET /api/config/collection`

**Purpose:** Return all nodes with their current collection settings merged in.

```sql
SELECT
  n.id, n.name, n.ip, n.group_name, n.collect_agent,
  COALESCE(cs.interval_seconds, 10)  AS interval_seconds,
  COALESCE(cs.window_seconds,   60)  AS window_seconds,
  cs.updated_at
FROM nodes n
LEFT JOIN collection_settings cs ON n.id = cs.node_id
ORDER BY n.name
```

Returns: `CollectionSettingsRow[]` (every node appears, defaults applied if no settings row).

---

#### `PUT /api/config/collection/[nodeId]`

**Purpose:** Save collection settings for a node (DB primary, etcd secondary).

**Body:** `{ interval_seconds, window_seconds, collect_agent? }`

**Step 1 — DB upsert (required):**

```sql
INSERT INTO collection_settings (node_id, interval_seconds, window_seconds, collect_agent, updated_at)
VALUES ($1, $2, $3, $4, NOW())
ON CONFLICT (node_id) DO UPDATE
  SET interval_seconds = EXCLUDED.interval_seconds,
      window_seconds   = EXCLUDED.window_seconds,
      collect_agent    = EXCLUDED.collect_agent,
      updated_at       = NOW()
RETURNING *
```

**Step 2 — etcd push (non-fatal):**

```typescript
Promise.all([
  etcd.put(`/config/compute_node/${nodeId}/window`).value(String(body.window_seconds)),
  etcd.put(`/config/compute_node/${nodeId}/heartbeat_interval`).value(String(body.interval_seconds)),
  ...(body.collect_agent
    ? [etcd.put(`/config/compute_node/${nodeId}/target_collect_agent`).value(body.collect_agent)]
    : [])
]).catch(console.error);
```

Returns: saved `CollectionSettings` row.

---

### Pipeline Rules

#### `GET /api/config/pipeline`

```sql
SELECT * FROM pipeline_rules ORDER BY created_at
```

Returns: `PipelineRule[]`

---

#### `POST /api/config/pipeline`

**Body:** `{ name, type, resource, condition, enabled? }`

```sql
INSERT INTO pipeline_rules (name, type, resource, condition, enabled)
VALUES ($1, $2, $3, $4, COALESCE($5, TRUE))
RETURNING *
```

Returns: `PipelineRule` — 201.

---

#### `PUT /api/config/pipeline/[id]`

**Body:** `{ name, type, resource, condition, enabled }`

```sql
UPDATE pipeline_rules
SET name=$2, type=$3, resource=$4, condition=$5, enabled=$6, updated_at=NOW()
WHERE id = $1
RETURNING *
```

Returns: updated `PipelineRule` — 404 if not found.

---

#### `DELETE /api/config/pipeline/[id]`

```sql
DELETE FROM pipeline_rules WHERE id = $1
```

Returns: `{ success: true }` — 404 if not found.

---

#### `POST /api/config/pipeline/push-to-etcd`

**Purpose:** Push all enabled pipeline rules to every known collect agent.

**Step 1 — Load enabled rules:**

```sql
SELECT * FROM pipeline_rules WHERE enabled = TRUE ORDER BY created_at
```

**Step 2 — Discover agents:**

```typescript
const kv = await etcd.getAll().prefix("/config/collect_agent/").strings();
const agentIds = [...new Set(
  Object.keys(kv).map(k => k.split("/")[3]).filter(Boolean)
)];
```

**Step 3 — Push to all agents:**

```typescript
await Promise.all(
  agentIds.map(agentId =>
    etcd.put(`/config/collect_agent/${agentId}/pipeline_rules`)
        .value(JSON.stringify(rules))
        .exec()
  )
);
```

Returns: `{ success: true, pushed_to_agents: string[], rule_count: number }`

---

### Alert Rules

#### `GET /api/config/alerts`

```sql
SELECT * FROM alert_rules ORDER BY created_at
```

Returns: `AlertRule[]`

---

#### `POST /api/config/alerts`

**Body:** `{ name, node_group?, resource, operator, threshold, severity, enabled? }`

```sql
INSERT INTO alert_rules (name, node_group, resource, operator, threshold, severity, enabled)
VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, TRUE))
RETURNING *
```

Returns: `AlertRule` — 201.

---

#### `PUT /api/config/alerts/[id]`

Full field update:

```sql
UPDATE alert_rules
SET name=$2, node_group=$3, resource=$4, operator=$5,
    threshold=$6, severity=$7, enabled=$8, updated_at=NOW()
WHERE id = $1
RETURNING *
```

---

#### `DELETE /api/config/alerts/[id]`

```sql
DELETE FROM alert_rules WHERE id = $1
```

---

#### `POST /api/config/alerts/push-to-etcd`

**Purpose:** Push threshold rules derived from enabled upper-bound alert rules to every agent.

**Step 1 — Load eligible rules:**

```sql
SELECT * FROM alert_rules
WHERE enabled = TRUE AND operator IN ('>', '>=')
```

Only upper-bound operators are meaningful for `{ max: N }` threshold enforcement. Lower-bound (`<`, `<=`) rules are tracked in DB only.

**Step 2 — Resource → etcd key mapping:**

| `resource` value | etcd key |
|-----------------|----------|
| `cpu` | `cpu_usage_percent` |
| `mem` | `memory_usage_percent` |
| `gpu` | `gpu_max_utilization_percent` |
| `disk` | `disk_usage_percent` |
| `net` | *(skipped — no etcd mapping)* |

**Step 3 — Most restrictive wins:**

```typescript
const thresholdMap: Record<string, number> = {};
for (const rule of eligibleRules) {
  const key = resourceToEtcdKey(rule.resource);
  if (!key) continue;  // skip "net"
  if (thresholdMap[key] === undefined || rule.threshold < thresholdMap[key]) {
    thresholdMap[key] = rule.threshold;
  }
}
const thresholdRules = Object.fromEntries(
  Object.entries(thresholdMap).map(([k, v]) => [k, { max: v }])
);
```

**Step 4 — Discover agents + push:**

Same agent discovery as pipeline push. Writes to `/config/collect_agent/{agentId}/threshold_rules`.

Returns: `{ success: true, threshold_rules, pushed_to_agents, skipped_rules }`

---

### Governance

#### `GET /api/config/governance/versions`

```sql
SELECT * FROM config_versions ORDER BY created_at DESC
```

Returns: `ConfigVersion[]`

---

#### `POST /api/config/governance/versions`

**Purpose:** Manually save a named config version (no etcd push).

**Body:** `{ version, author?, description?, config_snapshot? }`

```sql
INSERT INTO config_versions (version, author, description, config_snapshot, active)
VALUES ($1, $2, $3, $4, FALSE)
RETURNING *
```

Returns: `ConfigVersion` — 201.

---

#### `GET /api/config/governance/audit`

```sql
SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100
```

Returns: `AuditLog[]` (last 100 entries)

---

#### `POST /api/config/governance/rollout`

**Purpose:** Activate a specific config version and replay its snapshot to etcd.

**Body:** `{ id: string }` — UUID of the version to activate.

**Step 1 — DB transaction:**

```sql
BEGIN;
UPDATE config_versions SET active = FALSE;            -- deactivate all
UPDATE config_versions SET active = TRUE WHERE id=$1  -- activate target
  RETURNING *;                                         -- 404 if 0 rows
INSERT INTO audit_logs (actor, action, target, detail)
  VALUES ($actor, 'ROLLOUT', $version, $description);
COMMIT;
```

**Step 2 — etcd replay (non-fatal, DB already committed):**

Parse `config_snapshot` JSONB:

```
collection_settings[]:
  For each entry → write window, heartbeat_interval, target_collect_agent in etcd

pipeline_rules[]:
  Discover agents → push JSON array to each agent's pipeline_rules key

threshold_rules (object):
  Discover agents → push JSON to each agent's threshold_rules key
```

Returns: `{ success: true, version, etcd_errors[] }`

---

#### `POST /api/config/governance/snapshot-and-push`

**Purpose:** Atomically snapshot the current DB config, activate it as a new version, and push everything to etcd.

**Body:** `{ author?, description? }`

**Step 1 — Gather DB state in parallel:**

```typescript
const [nodesResult, collectionResult, pipelineResult, alertResult] = await Promise.all([
  client.query("SELECT n.*, cs.interval_seconds, cs.window_seconds FROM nodes n LEFT JOIN collection_settings cs ON n.id=cs.node_id"),
  client.query("SELECT * FROM collection_settings"),
  client.query("SELECT * FROM pipeline_rules WHERE enabled=TRUE ORDER BY created_at"),
  client.query("SELECT * FROM alert_rules WHERE enabled=TRUE AND operator IN ('>','>=')"),
]);
```

**Step 2 — Build threshold_rules** (lowest max per resource wins — same logic as push-to-etcd).

**Step 3 — Compute next version:**

```typescript
function nextVersion(latest?: string): string {
  if (!latest) return "1.0.0";
  const [major, minor, patch] = latest.split(".").map(Number);
  return `${major}.${minor}.${patch + 1}`;
}
```

Query: `SELECT version FROM config_versions ORDER BY created_at DESC LIMIT 1`

**Step 4 — DB transaction:**

```sql
BEGIN;
UPDATE config_versions SET active = FALSE;
INSERT INTO config_versions (version, author, description, config_snapshot, active)
  VALUES ($version, $author, $description, $snapshot::jsonb, TRUE)
  RETURNING *;
INSERT INTO audit_logs (actor, action, target, detail)
  VALUES ($author, 'ROLLOUT', $version, 'snapshot-and-push');
COMMIT;
```

**Step 5 — etcd push (non-fatal):**

Discover all nodes and agents in etcd. Push:
- Per node: `window`, `heartbeat_interval`, `target_collect_agent`
- Per agent: `pipeline_rules` (JSON array), `threshold_rules` (JSON object)

Collect any errors into `etcd_errors[]` — never throw.

**Returns:**

```json
{
  "success": true,
  "version": { "id": "...", "version": "1.3.0", "active": true, ... },
  "pushed_to_nodes": ["node-01", "node-02"],
  "pushed_to_agents": ["agent-a", "agent-b"],
  "node_count": 2,
  "agent_count": 2,
  "rule_count": 5,
  "etcd_errors": []
}
```

---

### Notifications

#### `GET /api/notifications`

```sql
SELECT n.*, nd.name AS node_name
FROM notifications n
LEFT JOIN nodes nd ON n.node_id = nd.id
ORDER BY n.created_at DESC
```

Returns: `Notification[]` with `node_name` joined.

---

#### `POST /api/notifications`

**Purpose:** Create a new notification (typically called by the pipeline service when a threshold is breached).

**Body:** `{ severity, message, node_id?, rule_id? }`

```sql
INSERT INTO notifications (severity, message, node_id, rule_id)
VALUES ($1, $2, $3, $4)
RETURNING *
```

Returns: `Notification` — 201.

---

#### `PUT /api/notifications/[id]`

**Purpose:** Acknowledge (or un-acknowledge) a notification.

**Body:** `{ acknowledged: boolean }`

```sql
UPDATE notifications SET acknowledged = $2 WHERE id = $1 RETURNING *
```

Returns: updated `Notification` — 404 if not found.

---

### Analytics

#### `GET /api/analytics/user-usage?mode=summary&from=&to=`

**Purpose:** Aggregate resource usage per HPC user over a time range.

```sql
SELECT
  u.uid, u.username, u.group_name,
  SUM(uah.total_cpu_time_seconds)                    AS total_cpu_seconds,
  MAX(uah.max_rss_memory_bytes)                      AS peak_mem_bytes,
  MAX(uah.max_gpu_memory_mib)                        AS peak_gpu_mib,
  SUM(uah.total_read_bytes + uah.total_write_bytes)  AS total_disk_bytes
FROM user_app_hourly uah
JOIN hpc_users u ON uah.uid = u.uid
WHERE uah.bucket_time BETWEEN $from AND $to
GROUP BY u.uid, u.username, u.group_name
ORDER BY total_cpu_seconds DESC
```

`from`/`to` default to `NOW() - INTERVAL '7 days'` / `NOW()` if not provided.

---

#### `GET /api/analytics/user-usage?mode=timeseries&uid=X&resource=Y&from=&to=`

**Purpose:** Per-user resource usage over time (for chart rendering).

Resource-specific SQL (all select `bucket_time` as `t`):

| `resource` | SQL expression | Unit |
|-----------|---------------|------|
| `cpu` | `SUM(total_cpu_time_seconds) / 3600.0` | hours |
| `mem` | `MAX(max_rss_memory_bytes) / 1048576.0` | MB |
| `gpu` | `MAX(max_gpu_memory_mib)` | MiB |
| `disk` | `SUM(total_read_bytes + total_write_bytes) / 1048576.0` | MB |
| unknown | *(returns empty array)* | — |

All queries: `WHERE uid=$uid AND bucket_time BETWEEN $from AND $to GROUP BY bucket_time ORDER BY bucket_time`

Returns: `{ t: ISO string, value: number }[]`

---

#### `GET /api/analytics/user-usage?mode=apps&uid=X&from=&to=`

**Purpose:** Per-application breakdown for a specific user.

```sql
SELECT
  u.username,
  uah.comm,
  SUM(uah.total_cpu_time_seconds)  AS total_cpu_seconds,
  MAX(uah.max_rss_memory_bytes)    AS peak_mem_bytes,
  SUM(uah.process_count)           AS total_process_count
FROM user_app_hourly uah
JOIN hpc_users u ON uah.uid = u.uid
WHERE uah.uid = $1 AND uah.bucket_time BETWEEN $from AND $to
GROUP BY u.username, uah.comm
ORDER BY total_cpu_seconds DESC
```

---

### Stubs (Placeholder for Future Integration)

#### `POST /api/analytics/ai-chart`

**Purpose:** Future LLM-powered chart generation. Currently returns keyword-parsed random timeseries.

**Body:** `{ prompt: string }`

Logic:
1. Parse prompt keywords: `gpu` → resource=gpu, `mem` → resource=mem, `disk` → resource=disk, `bar` → chartType=bar, `stacked` → chartType=stacked
2. Generate 12 random data points (past 12 hours, 1-hour intervals)
3. Return `{ resource, chartType, data: { t, value }[] }`

---

#### `POST /api/chat`

**Purpose:** Future LLM chatbot. Currently returns canned keyword-matched responses.

**Body:** `{ messages: { role, content }[] }`

Logic:
- Extract last user message content
- Keyword match: `cpu` → CPU usage guidance, `gpu` → GPU monitoring info, `memory` → memory info, `disk` → disk info, `alert` → alert configuration help, `node` → node management info, `user` → user analytics info
- Default: generic HPC monitoring description

Returns: `{ id, role: "assistant", content: string, timestamp: ISO string }`

---

## 10. Frontend Pages

All pages are `"use client"` components using React hooks. Data is fetched on mount via `fetch('/api/...')`.

### Color Palette

| Token | Hex | Usage |
|-------|-----|-------|
| `#0d1117` | Background | Page background |
| `#161b22` | Surface | Sidebar, panels |
| `#1c2128` | Card | Content cards |
| `#30363d` | Border | Dividers, borders |
| `#58a6ff` | Primary | Buttons, active states |

---

### `/login`

**Component:** `src/app/(auth)/login/page.tsx`

- Credentials form: email + password inputs
- Submit: `signIn("credentials", { email, password, redirectTo: "/dashboard" })`
- Error display: checks `?error=CredentialsSignin` in URL params
- On success: Auth.js sets JWT cookie and browser follows redirect to `/dashboard`

---

### `/dashboard` — Cluster Overview

**Data loading:**

```typescript
const [nodesRes, etcdRes] = await Promise.all([
  fetch('/api/nodes'),
  fetch('/api/etcd/nodes'),
]);
```

**`buildSummary(dbNodes, etcdNodes)`:**
- Merges by `db.id === etcd.nodeId`
- Counts: `active` (etcd running), `down` (etcd stopped), `idle` (absent from etcd), `total`

**Auto-refresh:** `setInterval(loadData, 30_000)` — clears on unmount.

**UI sections:**
1. Status summary grid (4 counters: active / idle / down / total)
2. Resource stat cards — CPU%, GPU%, Memory%, Disk%, Network (Phase 3 placeholder showing "—")
3. Grafana panel grid — 6 iframe placeholders with `${GRAFANA_BASE_URL}` URLs (Phase 3)

---

### `/dashboard/nodes` — Node List

**Data loading:** Same parallel fetch as dashboard.

**Node row fields:** name, IP, group, collect_agent, derived status badge, Start/Stop button, "View →" link.

**Filtering:**
- Search bar: substring match on `name` or `ip`
- Status toggle buttons: All | Active | Idle | Down

**Start/Stop button:**
```typescript
await fetch(`/api/etcd/nodes/${node.id}/status`, {
  method: 'PUT',
  body: JSON.stringify({ status: node.status === 'active' ? 'stopped' : 'running' })
});
// Optimistic update — mutate local state, no re-fetch
setNodes(prev => prev.map(n => n.id === node.id ? { ...n, status: newStatus } : n));
```

**"View →"** navigates to `/dashboard/nodes/[nodeId]`.

---

### `/dashboard/nodes/[nodeId]` — Node Detail

**Data loading:**

```typescript
const [nodeRes, etcdRes] = await Promise.all([
  fetch(`/api/nodes/${nodeId}`),
  fetch(`/api/etcd/nodes/${nodeId}`),
]);
```

**UI sections:**
1. Node metadata (name, IP, group, agent)
2. etcd config strip — window / heartbeat / targetAgent — shown only if etcd entry exists
3. Warning banner if no etcd entry: "This node has not been pushed to etcd. Go to Collection Settings to push configuration."
4. "Start Collection" / "Stop Collection" → `PUT /api/etcd/nodes/[nodeId]/status`
5. Metric rows (CPU / GPU / Memory / Disk) — Phase 3 placeholder
6. 5 Grafana panel placeholders

---

### `/analytics` — User Usage History

**On mount:**

```typescript
const summary = await fetch('/api/analytics/user-usage?mode=summary&from=7d').then(r => r.json());
// auto-select first user
setSelectedUids([summary[0].uid]);
```

**On user/resource/timeRange change:**

```typescript
const series = await Promise.all(
  selectedUids.map(uid =>
    fetch(`/api/analytics/user-usage?mode=timeseries&uid=${uid}&resource=${resource}&from=${from}&to=${to}`)
      .then(r => r.json())
  )
);
```

**`UsageChart`** (`src/components/analytics/UsageChart.tsx`):
- Recharts `LineChart` (or `BarChart` depending on `chartType` prop)
- Y-axis domain: `[0, "auto"]`
- Unit label derived from resource: cpu→"h", mem→"MB", gpu→"MiB", disk→"MB"
- Multi-series: one line per selected UID, different colors

**Summary table:**
- Shows 7-day aggregate per user (cpu hours, peak mem, peak gpu)
- Row click: toggle UID in `selectedUids`

---

### `/analytics/custom` — Custom Dashboard Builder

**State:** `ChartPanel[]` array — each panel: `{ id, title, userIds, resource, chartType, pinned }`

**Add Panel modal:**
- Title text input
- Resource select (cpu / mem / gpu / disk)
- Chart type select (line / bar / stacked)
- User multi-select (from summary list)

**Panel actions:**
- Pin/Unpin: `panel.pinned = !panel.pinned`; pinned panels sorted to top
- Remove: filter panel from array

*(Phase 3: persist panels via `POST /api/custom-dashboards` and load saved panels on mount)*

---

### `/analytics/ai-chart` — AI Chart Generator

**State:** `prompt` string, `chartSpec` (resource + chartType + data) | null, `loading` boolean

**"Generate" button:**

```typescript
setLoading(true);
const result = await fetch('/api/analytics/ai-chart', {
  method: 'POST', body: JSON.stringify({ prompt })
}).then(r => r.json());
setChartSpec(result);
setLoading(false);
```

Currently calls the stub endpoint which returns random data. Phase 3: replace stub with real LLM + DB query.

---

### `/chat` — Chatbot Assistant

**State:** `messages: Message[]` (id, role, content, timestamp)

**Send message:**

```typescript
const res = await fetch('/api/chat', {
  method: 'POST',
  body: JSON.stringify({ messages: [...messages, userMessage] })
}).then(r => r.json());
setMessages(prev => [...prev, userMessage, res]);
```

- Scroll-to-bottom on new message via `useRef` + `useEffect`
- User messages: right-aligned blue bubble; assistant: left-aligned grey bubble

---

### `/config/collection` — Collection Settings

**Data loading (3 parallel fetches):**

```typescript
const [collection, etcdNodes, etcdAgents] = await Promise.all([
  fetch('/api/config/collection').then(r => r.json()),    // DB nodes+settings
  fetch('/api/etcd/nodes').then(r => r.json()),           // etcd node configs
  fetch('/api/etcd/agents').then(r => r.json()),          // etcd agent list
]);
```

**Merge logic per node:**
- `etcdEntry = etcdMap.get(node.id)` — undefined if node not in etcd
- Status: running→active / stopped→down / undefined→idle
- etcd sync state: `inSync = etcdEntry?.window == node.window_seconds && etcdEntry?.heartbeat_interval == node.interval_seconds`

**"Push All" button** (for nodes missing from etcd):
```typescript
for (const node of missingFromEtcd) {
  await fetch('/api/etcd/nodes', { method: 'POST', body: JSON.stringify({
    nodeId: node.id,
    target_collect_agent: node.collect_agent,
    window: String(node.window_seconds),
    heartbeat_interval: String(node.interval_seconds),
  })});
}
```

**Edit modal** → `PUT /api/config/collection/[nodeId]` (dual-write).

**`dirtyAfterPush` flag:** set to `true` whenever a setting is saved; cleared after "Push All" completes. Orange badge shown in header when dirty.

---

### `/config/pipeline` — Pipeline Rules

**Load:** `GET /api/config/pipeline`

**CRUD:**
- Add rule → `POST /api/config/pipeline`
- Edit rule → `PUT /api/config/pipeline/[id]`
- Toggle enabled → `PUT /api/config/pipeline/[id]` with `{ enabled: !rule.enabled }`
- Delete → `DELETE /api/config/pipeline/[id]`

**"Push to Agents" banner:**
```typescript
const result = await fetch('/api/config/pipeline/push-to-etcd', { method: 'POST' }).then(r => r.json());
// shows: "Pushed N rules to M agents: agent-a, agent-b"
```

**`dirtyAfterPush`:** orange badge when DB has changed since last push.

---

### `/config/alerts` — Alert Rules

**Load:** `GET /api/config/alerts`

**etcd badge:** shown on rule row if `rule.enabled && ['>', '>='].includes(rule.operator) && rule.resource !== 'net'`

**"Sync to etcd" banner:**
```typescript
const result = await fetch('/api/config/alerts/push-to-etcd', { method: 'POST' }).then(r => r.json());
// shows: threshold_rules pushed, list of skipped rules
```

**Edit modal:** displays eligibility hint: "This rule will / will not be synced to etcd" based on operator + resource.

---

### `/config/governance` — Version History & Audit Log

**Two tabs:** Version History | Audit Log

**Version History tab:**
- Load: `GET /api/config/governance/versions`
- Active version: highlighted with green "Active" banner
- Per-version "Activate" button → `POST /api/config/governance/rollout` with `{ id }`
- "Push to Nodes" button → opens description modal

**"Push to Nodes" flow:**
1. User enters description text in modal
2. Submit → `POST /api/config/governance/snapshot-and-push` with `{ description }`
3. Loading state while request is in-flight
4. Result modal shows:
   - New version number
   - Nodes pushed: `result.pushed_to_nodes`
   - Agents pushed: `result.pushed_to_agents`
   - Any etcd errors: `result.etcd_errors`

**Audit Log tab:**
- Load: `GET /api/config/governance/audit`
- Read-only table: timestamp, actor, action badge, target, detail
- Last 100 entries

---

## 11. Environment Variables

All variables are set in `.env.local` at the app root (`Application/hpc-admin/.env.local`).

| Variable | Required | Description |
|----------|----------|-------------|
| `NEXTAUTH_SECRET` | Yes | Auth.js JWT signing secret — any random string ≥32 chars |
| `ADMIN_EMAIL` | Yes | Single administrator login email |
| `ADMIN_PASSWORD` | Yes | Single administrator login password |
| `TIMESCALE_URL` | Yes | PostgreSQL connection string, e.g. `postgresql://user:pass@host:5432/dbname` |
| `GRAFANA_BASE_URL` | No | Base URL for Grafana iframe embeds, e.g. `http://grafana:3000` |
| `ETCD_URL` | No | etcd endpoint — defaults to `http://localhost:2379` |

### Example `.env.local`

```dotenv
NEXTAUTH_SECRET=your-secret-here-at-least-32-characters
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=changeme

TIMESCALE_URL=postgresql://hpc_admin:password@localhost:5432/hpc_monitoring

GRAFANA_BASE_URL=http://localhost:3000
ETCD_URL=http://localhost:2379
```
