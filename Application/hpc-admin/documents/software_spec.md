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
| InfluxDB | Real-time raw metrics (future) | `@influxdata/influxdb-client` |
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

### Pipeline Source Tables (READ-ONLY)

These tables are maintained automatically by TimescaleDB continuous aggregates and the pipeline. The web app only reads them.

#### `user_app_hourly` — Per-User Per-App Hourly Aggregate

1-hour bucket aggregate over raw process metrics, grouped by Linux UID and process command name.

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

**Used by:** `/api/analytics/user-usage` (all modes).

#### `node_status_hourly` — Per-Node Hourly Aggregate

1-hour bucket aggregate over raw node-level metrics, grouped by node ID.

| Column | Type | Description |
|--------|------|-------------|
| `node_id` | TEXT | compute node identifier |
| `bucket_time` | TIMESTAMPTZ | start of the 1-hour bucket |
| `avg_cpu_usage_percent` | FLOAT | average CPU utilization across the hour |
| `max_cpu_usage_percent` | FLOAT | peak CPU utilization in the hour |
| `avg_mem_usage_percent` | FLOAT | average memory utilization |
| `max_mem_used_bytes` | BIGINT | peak memory used bytes |
| `avg_gpu_utilization` | FLOAT | average GPU utilization percent |
| `max_gpu_temperature` | FLOAT | peak GPU temperature (°C) |
| `total_gpu_power_watts` | FLOAT | cumulative GPU power draw |
| `total_disk_read_bytes` | BIGINT | total bytes read from disk |
| `total_disk_write_bytes` | BIGINT | total bytes written to disk |
| `total_net_rx_bytes` | BIGINT | total network received bytes |
| `total_net_tx_bytes` | BIGINT | total network transmitted bytes |
| `is_active` | BOOL | whether the node reported data in this bucket |

**Used by:** `/api/analytics/cluster-stats` (dashboard stat cards), `/api/nodes/[nodeId]/hourly` (node detail charts), `/api/nodes/metrics/latest` (node list status).

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

Node status is derived at runtime from etcd alone (no DB join required on the dashboard).

```
etcd /config/compute_node/{nodeId}/status   →   UI NodeStatus
─────────────────────────────────────────────────────────────
"running"                                   →   "active"   (green dot)
"stopped"                                   →   "down"     (red dot)
key absent / node not in etcd               →   "idle"     (yellow dot — always 0 on dashboard)
```

**`buildSummary()` helper** (dashboard + nodes list):

```typescript
// Dashboard — etcd only (no DB call)
function buildSummary(etcdNodes: EtcdNode[]): ClusterSummary {
  const active = etcdNodes.filter(n => n.status === "running").length
  const down   = etcdNodes.filter(n => n.status === "stopped").length
  return { totalNodes: etcdNodes.length, activeNodes: active, idleNodes: 0, downNodes: down }
}
```

> **Note:** The "idle" concept (node in DB but absent from etcd) requires a DB join and is not shown on the dashboard. The idle counter always displays 0 on `/dashboard`. The full idle derivation is used on `/dashboard/nodes` where both DB and etcd data are loaded.

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

```sql
SELECT * FROM nodes ORDER BY name
```

Returns: `Node[]`

---

#### `POST /api/nodes`

**Body:** `{ id, name, ip?, group_name?, collect_agent? }`

```sql
INSERT INTO nodes (id, name, ip, group_name, collect_agent)
VALUES ($1, $2, $3, $4, $5)
RETURNING *
```

Returns: `Node` — 201 on success, 409 if `id` already exists.

---

#### `GET /api/nodes/[nodeId]`

```sql
SELECT * FROM nodes WHERE id = $1
```

Returns: `Node` — 404 if not found.

---

#### `PUT /api/nodes/[nodeId]`

**Body:** `{ name?, ip?, group_name?, collect_agent? }`

```sql
UPDATE nodes SET name=$2, ip=$3, group_name=$4, collect_agent=$5 WHERE id=$1 RETURNING *
```

Returns: `Node` — 404 if not found.

---

#### `DELETE /api/nodes/[nodeId]`

```sql
DELETE FROM nodes WHERE id = $1
```

Returns: `{ success: true }` — 404 if not found.

---

### Analytics

#### `GET /api/analytics/cluster-stats?range=1h|6h|24h`

**Purpose:** Cluster-wide aggregated resource stats from `node_status_hourly` for the dashboard stat cards.

**Param validation:** `range` must be `1h`, `6h`, or `24h`; any other value defaults to `1h`.

```sql
SELECT
  ROUND(AVG(avg_cpu_usage_percent)::numeric, 1)                                          AS avg_cpu_pct,
  ROUND(AVG(avg_gpu_utilization)::numeric, 1)                                            AS avg_gpu_pct,
  ROUND(AVG(avg_mem_usage_percent)::numeric, 1)                                          AS avg_mem_pct,
  ROUND(((SUM(total_disk_read_bytes) + SUM(total_disk_write_bytes)) / 1048576.0)::numeric, 1) AS total_disk_mb,
  ROUND((SUM(total_net_rx_bytes) / 1048576.0)::numeric, 1)                               AS net_rx_mb,
  ROUND((SUM(total_net_tx_bytes) / 1048576.0)::numeric, 1)                               AS net_tx_mb
FROM node_status_hourly
WHERE bucket_time >= NOW() - ($1::text)::interval
```

Returns:
```json
{
  "avg_cpu_pct":   1.2,
  "avg_gpu_pct":   45.0,
  "avg_mem_pct":   67.3,
  "total_disk_mb": 1024.5,
  "net_rx_mb":     200.1,
  "net_tx_mb":     88.4
}
```

All fields are `null` when no rows exist in the selected window.

---

#### `GET /api/analytics/user-usage?mode=summary&from=&to=`

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

Resource-specific SQL (all select `bucket_time` as `t`):

| `resource` | SQL expression | Unit |
|-----------|---------------|------|
| `cpu` | `SUM(total_cpu_time_seconds) / 3600.0` | hours |
| `mem` | `MAX(max_rss_memory_bytes) / 1048576.0` | MB |
| `gpu` | `MAX(max_gpu_memory_mib)` | MiB |
| `disk` | `SUM(total_read_bytes + total_write_bytes) / 1048576.0` | MB |
| unknown | *(returns empty array)* | — |

Returns: `{ t: ISO string, value: number }[]`

---

#### `GET /api/analytics/user-usage?mode=apps&uid=A,B,...&from=&to=`

Accepts a comma-separated list of UIDs (`ANY($1::int[])`). Returns all five resources plus process count per (username, comm) pair.

```sql
SELECT
  u.username, h.comm,
  SUM(h.total_cpu_time_seconds)                               AS cpu_seconds,
  MAX(h.max_rss_memory_bytes) / 1048576.0                    AS peak_mem_mb,
  MAX(h.max_gpu_memory_mib)                                  AS peak_gpu_mib,
  SUM(h.total_read_bytes + h.total_write_bytes) / 1048576.0  AS disk_io_mb,
  SUM(h.total_net_rx_bytes + h.total_net_tx_bytes) / 1048576.0 AS net_io_mb,
  SUM(h.process_count)                                       AS total_processes
FROM user_app_hourly h
JOIN hpc_users u ON h.uid = u.uid
WHERE h.uid = ANY($1::int[])
  AND h.bucket_time >= $2
  AND h.bucket_time <= $3
GROUP BY u.username, h.comm
ORDER BY cpu_seconds DESC
```

Returns: `{ username, comm, cpu_seconds, peak_mem_mb, peak_gpu_mib, disk_io_mb, net_io_mb, total_processes }[]`

---

#### `GET /api/analytics/user-usage?mode=app-timeseries&uid=A,B,...&resource=Y&from=&to=`

Hourly time-bucketed values broken down by user × application. Used for line/bar charts in `by-app` view mode.

```sql
SELECT
  time_bucket('1 hour', h.bucket_time) AS t,
  u.username,
  h.comm,
  <resource_sql_expression>            AS value
FROM user_app_hourly h
JOIN hpc_users u ON h.uid = u.uid
WHERE h.uid = ANY($1::int[])
  AND h.bucket_time >= $2
  AND h.bucket_time <= $3
GROUP BY t, h.uid, u.username, h.comm
ORDER BY t, u.username, h.comm
```

Resource SQL expressions (same as `mode=timeseries`):

| `resource` | SQL expression | Unit |
|---|---|---|
| `cpu` | `SUM(h.total_cpu_time_seconds)` | s |
| `mem` | `MAX(h.max_rss_memory_bytes) / 1048576.0` | MB |
| `gpu` | `MAX(h.max_gpu_memory_mib)` | MiB |
| `disk` | `SUM(h.total_read_bytes + h.total_write_bytes) / 1048576.0` | MB |
| `net` | `SUM(h.total_net_rx_bytes + h.total_net_tx_bytes) / 1048576.0` | MB |

Returns: `{ t: ISO string, username: string, comm: string, value: number }[]`

---

### etcd — Compute Node Config

#### `GET /api/etcd/nodes`

1. `etcd.getAll().prefix("/config/compute_node/").strings()` → flat `{ key: value }` map
2. Parse: split each key on `/`, group by `keyParts[3]` (nodeId), collect `keyParts[4]` as field name
3. Return `EtcdNodeConfig[]`:
   ```
   { nodeId, target_collect_agent, window, heartbeat_interval, status }
   ```

---

#### `POST /api/etcd/nodes`

**Body:** `{ nodeId, target_collect_agent, window?, heartbeat_interval? }`

Writes 4 keys:
```
/config/compute_node/{nodeId}/target_collect_agent  = body.target_collect_agent
/config/compute_node/{nodeId}/window                = body.window ?? "60"
/config/compute_node/{nodeId}/heartbeat_interval    = body.heartbeat_interval ?? "10"
/config/compute_node/{nodeId}/status                = "stopped"
```

Returns: `{ success: true, nodeId }`

---

#### `GET /api/etcd/nodes/[nodeId]`

Prefix-scan `/config/compute_node/{nodeId}/`. Returns parsed `EtcdNodeConfig` — 404 if empty.

---

#### `PUT /api/etcd/nodes/[nodeId]`

**Body:** `{ target_collect_agent?, window?, heartbeat_interval? }` (partial)

Only writes keys present in the request body. Returns: `{ success: true, updated: string[] }` — 400 if no fields.

---

#### `DELETE /api/etcd/nodes/[nodeId]`

```typescript
await etcd.delete().prefix(`/config/compute_node/${nodeId}/`).exec();
```

Returns: `{ success: true }`

---

#### `GET /api/etcd/nodes/[nodeId]/status`

Returns: `{ nodeId, status: "running" | "stopped" | null }`

---

#### `PUT /api/etcd/nodes/[nodeId]/status`

**Body:** `{ status: "running" | "stopped" }`

Returns: `{ success: true, nodeId, status }`

---

### etcd — Collect Agent Config

#### `GET /api/etcd/agents`

Prefix-scan `/config/collect_agent/`. Groups by agentId. JSON-parses `kafka_brokers` and `threshold_rules`. Returns `EtcdAgentConfig[]`.

---

#### `POST /api/etcd/agents`

**Body:** `{ agentId, kafka_brokers: string[], kafka_topic, grpc_port, threshold_rules? }`

Writes 4 keys with defaults for `threshold_rules`.

Returns: `{ success: true, agentId }`

---

#### `GET /api/etcd/agents/[agentId]`

Prefix-scan `/config/collect_agent/{agentId}/`. Returns parsed `EtcdAgentConfig` — 404 if empty.

---

#### `PUT /api/etcd/agents/[agentId]`

**Body:** `{ kafka_brokers?, kafka_topic?, grpc_port? }` — conditional write for present fields only.

---

#### `DELETE /api/etcd/agents/[agentId]`

```typescript
await etcd.delete().prefix(`/config/collect_agent/${agentId}/`).exec();
```

---

#### `GET /api/etcd/agents/[agentId]/threshold-rules`

Returns parsed `ThresholdRules` object — 404 if key absent.

---

#### `PUT /api/etcd/agents/[agentId]/threshold-rules`

**Body:** `ThresholdRules` object. Replaces atomically.

Returns: `{ success: true, agentId }`

---

### Collection Settings

#### `GET /api/config/collection`

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

---

#### `PUT /api/config/collection/[nodeId]`

**Body:** `{ interval_seconds, window_seconds, collect_agent? }`

**Step 1 — DB upsert:**
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

---

### Pipeline Rules

#### `GET /api/config/pipeline`

```sql
SELECT * FROM pipeline_rules ORDER BY created_at
```

---

#### `POST /api/config/pipeline`

**Body:** `{ name, type, resource, condition, enabled? }`

```sql
INSERT INTO pipeline_rules (name, type, resource, condition, enabled)
VALUES ($1, $2, $3, $4, COALESCE($5, TRUE))
RETURNING *
```

---

#### `PUT /api/config/pipeline/[id]`

**Body:** `{ name, type, resource, condition, enabled }`

```sql
UPDATE pipeline_rules
SET name=$2, type=$3, resource=$4, condition=$5, enabled=$6, updated_at=NOW()
WHERE id = $1
RETURNING *
```

---

#### `DELETE /api/config/pipeline/[id]`

```sql
DELETE FROM pipeline_rules WHERE id = $1
```

---

#### `POST /api/config/pipeline/push-to-etcd`

1. Load enabled rules from DB
2. Discover all agents from etcd prefix scan
3. Push JSON array to each agent's `pipeline_rules` key

Returns: `{ success: true, pushed_to_agents: string[], rule_count: number }`

---

### Alert Rules

#### `GET /api/config/alerts` / `POST` / `PUT /[id]` / `DELETE /[id]`

Standard CRUD on `alert_rules`. See api_spec.md §3c for field list.

---

#### `POST /api/config/alerts/push-to-etcd`

Loads enabled upper-bound rules (`operator IN ('>', '>=')`). Maps resource → etcd key. Most restrictive threshold wins. Pushes to all agents.

Returns: `{ success: true, threshold_rules, pushed_to_agents, skipped_rules }`

---

### Governance

#### `GET /api/config/governance/versions`

```sql
SELECT * FROM config_versions ORDER BY created_at DESC
```

---

#### `POST /api/config/governance/rollout`

**Body:** `{ id: string }` — UUID of the version to activate.

DB transaction: deactivate all → activate target → insert audit log.
etcd replay (non-fatal): push collection_settings, pipeline_rules, threshold_rules from snapshot.

Returns: `{ success: true, version, etcd_errors[] }`

---

#### `POST /api/config/governance/snapshot-and-push`

Atomically snapshots current DB state, activates as new version, pushes to etcd.

Returns: `{ success, version, pushed_to_nodes, pushed_to_agents, node_count, agent_count, rule_count, etcd_errors }`

---

### Notifications

#### `GET /api/notifications`

```sql
SELECT n.*, nd.name AS node_name
FROM notifications n
LEFT JOIN nodes nd ON n.node_id = nd.id
ORDER BY n.created_at DESC
```

---

#### `POST /api/notifications`

**Body:** `{ severity, message, node_id?, rule_id? }`

---

#### `PUT /api/notifications/[id]`

**Body:** `{ acknowledged: boolean }`

```sql
UPDATE notifications SET acknowledged = $2 WHERE id = $1 RETURNING *
```

---

### Stubs

#### `POST /api/analytics/ai-chart`

Keyword-parsed random timeseries. Future: Claude API + real DB query.

#### `POST /api/chat`

Keyword-matched canned responses. Future: Anthropic SDK with metric tool-calls.

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

- Credentials form: email + password inputs
- Submit: `signIn("credentials", { email, password, redirectTo: "/dashboard" })`
- Error display: checks `?error=CredentialsSignin` in URL params

---

### `/dashboard` — Cluster Overview

**Data loading (parallel):**

```typescript
const [etcdRes, statsRes] = await Promise.all([
  fetch("/api/etcd/nodes"),
  fetch(`/api/analytics/cluster-stats?range=${timeRange}`),
])
```

> The dashboard does **not** call `GET /api/nodes`. Node counts are derived from etcd only.

**`buildSummary(etcdNodes)`:**
- `active` = nodes with `status === "running"`
- `down` = nodes with `status === "stopped"`
- `idle` = always 0 (etcd-only; idle detection requires a DB join, not done here)
- `total` = `etcdNodes.length`

**Auto-refresh:** `setInterval(load, 30_000)` — resets when `timeRange` changes.

**Time range selector:** `"1h" | "6h" | "24h"` — no "Live" option. Default: `"1h"`. Both the cluster stats fetch and the Grafana panel URL update when the selection changes.

**UI sections:**

1. **Status summary grid** — 4 counters: Active / Idle (0) / Down / Total
2. **Resource stat cards** (6 cards, sourced from `cluster-stats`):

| Card | Field | Unit |
|------|-------|------|
| Avg CPU | `avg_cpu_pct` | % |
| Avg GPU | `avg_gpu_pct` | % |
| Avg Memory | `avg_mem_pct` | % |
| Avg Disk | `total_disk_mb` | MB |
| Network In | `net_rx_mb` | MB |
| Network Out | `net_tx_mb` | MB |

3. **Grafana panel grid** — 6 panels. CPU Usage panel has a dynamic src:

```typescript
const GRAFANA_BASE = "http://10.1.8.155:3000/d-solo/adtfbh4/h6-monitoring?orgId=1&timezone=browser&__feature.dashboardSceneSolo=true"
const cpuPanelSrc = `${GRAFANA_BASE}&panelId=panel-6&from=now-${timeRange}&to=now`
```

Other panels (GPU, Memory, Disk, Network, Node Status) show placeholder until embed URLs are configured.

**Grafana embedding requirement:** Grafana must have `GF_AUTH_ANONYMOUS_ENABLED=true` and `GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer` set in its Docker Compose environment to allow unauthenticated iframe access. `GF_SECURITY_ALLOW_EMBEDDING=true` is also required to bypass `X-Frame-Options`.

---

### `/dashboard/nodes` — Node List

**Data loading:** Parallel fetch of `GET /api/nodes` (DB) + `GET /api/etcd/nodes` (etcd). Both are needed here for full idle detection.

**Node row fields:** name, IP, group, collect_agent, derived status badge, Start/Stop button, "View →" link.

**Filtering:**
- Search bar: substring match on `name` or `ip`
- Status toggle buttons: All | Active | Idle | Down

**Start/Stop button:**
```typescript
await fetch(`/api/etcd/nodes/${node.id}/status`, {
  method: "PUT",
  body: JSON.stringify({ status: node.status === "active" ? "stopped" : "running" })
});
// Optimistic update — mutate local state, no re-fetch
```

---

### `/dashboard/nodes/[nodeId]` — Node Detail

**Data loading:**
```typescript
const [nodeRes, etcdRes] = await Promise.all([
  fetch(`/api/nodes/${nodeId}`),
  fetch(`/api/etcd/nodes/${nodeId}`),
])
```

**UI sections:**
1. Node metadata (name, IP, group, agent)
2. etcd config strip — window / heartbeat / targetAgent — shown only if etcd entry exists
3. Warning banner if no etcd entry
4. "Start Collection" / "Stop Collection" → `PUT /api/etcd/nodes/[nodeId]/status`
5. Hourly metric charts from `node_status_hourly` via `/api/nodes/[nodeId]/hourly`
6. Grafana panel placeholders

---

### `/analytics` — User & Application Usage Analytics

Tracks per-user and per-application resource consumption from `user_app_hourly` (TimescaleDB). All chart data is derived client-side from two API responses: `mode=summary` (user list) and `mode=apps` / `mode=timeseries` / `mode=app-timeseries` (chart data).

#### Filter Controls

| Control | State | Behaviour |
|---|---|---|
| Time Range | `timeRange` (`1h` / `6h` / `24h` / `7d` / `custom`) | Presets compute `from`/`to` via `getTimeRange()`. "Custom" reveals `DateRangePicker`. |
| Chart Type | `chartType` (`line` / `bar` / `pie`) | Switches rendering component. Pie skips timeseries fetch entirely. |
| View Mode | `viewMode` (`by-app` / `by-user`) | Controls how series are grouped and which API mode is called. |
| Resources | `resources` (`ResourceType[]`) | Multi-select pills; at least one must remain selected. One chart card rendered per selected resource. |
| Users | `selectedUids` (`number[]`) | Pill buttons populated from `mode=summary`. Changing selection resets app selection and re-fetches `mode=apps`. |
| Applications | `selectedApps` (`string[]`) | Managed by `AppSelector`. Shown only in `by-app` mode. Empty means "show nothing" in charts. |

#### Data Fetches & Triggers

| Fetch | Trigger | API call |
|---|---|---|
| User list | Mount (once) | `mode=summary&from=7d ago&to=now` |
| App breakdown | `selectedUids`, `timeRange`, `customFrom/To` | `mode=apps&uid=A,B&from=&to=` — resets `selectedApps` on complete |
| Timeseries | `selectedUids`, `resources`, `timeRange`, `viewMode`, `selectedApps`, `chartType` | Skipped when `chartType=pie`. `by-app` → `mode=app-timeseries` (one call per resource); `by-user` → `mode=timeseries` (one call per user per resource, parallel) |

#### `AppSelector` Component

Populated from `appData` (the `mode=apps` response). No extra API call.

**Intersection rule:** when N ≥ 2 users are selected, only `comm` values that appear for **every** selected username are shown. When N = 1, all apps are shown.

**Controls:** text search (client-side filter), "Top 5" / "Top 10" / "All" quick-pick buttons (sorted by `cpu_seconds DESC`), "Clear" button, count indicator (`N of M selected`).

**CPU bar:** each app row shows a relative bar proportional to its `cpu_seconds` vs the maximum in the list.

#### `AppUsageTable` Component

Collapsible sortable table below the filters. Columns: Application, User, CPU (s), Peak Mem (MB), Peak GPU (MiB), Disk I/O (MB), Net I/O (MB), Processes. Clicking a row toggles it in/out of `selectedApps` (same state as `AppSelector`). Selected rows are highlighted with a checkbox.

When `selectedApps` is empty, the table shows a prompt ("Select applications above to view breakdown") instead of all rows.

#### Chart Rendering

**Line / Bar mode** — one `UsageChart` card per selected resource.
- `by-app`: series keyed as `"username - comm"`, filtered to `selectedApps`.
- `by-user`: series keyed as `username`, aggregated across all comms.
- Legend items are clickable to hide/show individual series.

**Pie mode** — reads `appData` directly (no timeseries fetch).
- `by-app`: one donut chart per selected user. Slices = selected applications, values = total resource usage for that user over the time range. Grid layout: 1 column for 1 user, 2 columns for 2+ users.
- `by-user`: one donut chart per selected resource. Slices = selected users, values = summed resource usage across all their apps.
- Clicking a legend item hides/shows the corresponding pie slice. Tooltip shows absolute value + percentage.

---

### `/analytics/custom` — Custom Dashboard Builder

**State:** `ChartPanel[]` — each panel: `{ id, title, userIds, resource, chartType, pinned }`

**Add Panel modal:** title, resource, chart type, user multi-select.

**Panel actions:** Pin/Unpin (sorted to top), Remove.

---

### `/analytics/ai-chart` — AI Chart Generator

POST `{ prompt }` → `GET /api/analytics/ai-chart` → render chart. Currently stub data.

---

### `/chat` — Chatbot Assistant

POST `{ messages }` → `GET /api/chat` → append assistant reply. Keyword-matched stub. Future: Anthropic SDK.

---

### `/config/collection` — Collection Settings

**3 parallel fetches:** `GET /api/config/collection` + `GET /api/etcd/nodes` + `GET /api/etcd/agents`

**Merge logic:** etcd sync state = `etcdEntry?.window == node.window_seconds && etcdEntry?.heartbeat_interval == node.interval_seconds`

**"Push All"** → `POST /api/etcd/nodes` for each node missing from etcd.

**Edit modal** → `PUT /api/config/collection/[nodeId]` (dual-write to DB + etcd).

---

### `/config/pipeline` — Pipeline Rules

CRUD via `GET` / `POST` / `PUT` / `DELETE /api/config/pipeline`. Toggle `enabled` via `PUT`.

**"Push to Agents"** → `POST /api/config/pipeline/push-to-etcd`

---

### `/config/alerts` — Alert Rules

CRUD via `/api/config/alerts`. etcd sync badge on upper-bound rules.

**"Sync to etcd"** → `POST /api/config/alerts/push-to-etcd`

---

### `/config/governance` — Version History & Audit Log

**Two tabs:** Version History | Audit Log

**"Activate"** → `POST /api/config/governance/rollout`

**"Push to Nodes"** → `POST /api/config/governance/snapshot-and-push` (modal with description input).

---

## 11. Environment Variables

All variables are set in `.env.local` at `Application/hpc-admin/.env.local`.

| Variable | Required | Description |
|----------|----------|-------------|
| `NEXTAUTH_SECRET` | Yes | Auth.js JWT signing secret — any random string ≥32 chars |
| `ADMIN_EMAIL` | Yes | Single administrator login email |
| `ADMIN_PASSWORD` | Yes | Single administrator login password |
| `TIMESCALE_URL` | Yes | PostgreSQL connection string |
| `GRAFANA_BASE_URL` | No | Base URL for Grafana iframe embeds |
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

### Grafana Docker Compose (required env vars)

```yaml
environment:
  - GF_SECURITY_ADMIN_USER=admin
  - GF_SECURITY_ADMIN_PASSWORD=admin123
  - GF_SECURITY_ALLOW_EMBEDDING=true
  - GF_AUTH_ANONYMOUS_ENABLED=true
  - GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer
```
