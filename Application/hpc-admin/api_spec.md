# HPC Admin — API Specification

## Overview

The API serves one purpose: **give the Next.js web app a clean, typed interface to the data tier** so that every page can drop its mock data and talk to real infrastructure.

The API talks to three data stores:
- **TimescaleDB** — stores admin-managed config tables (nodes, users, rules, audit logs) and pre-aggregated historical metrics written by the pipeline.
- **InfluxDB** (read-only, not directly queried here) — real-time measurements. Node status (active/idle/down) is derived from whether a node appeared there recently.
- **etcd** — live config store. Compute node agents and collect agents watch etcd keys and reload their config without restarting. The admin web app writes to etcd so changes take effect immediately.

Routes under `src/app/api/` (TimescaleDB) follow:
```
acquire pg client → parameterized query → release → return JSON
```

Routes under `src/app/api/etcd/` follow:
```
etcd.get / etcd.put / etcd.delete → return JSON   (503 if etcd is unreachable)
```

Authentication is handled upstream by `src/proxy.ts` (Auth.js v5), so every API route can assume the caller is authenticated.

---

## Route Groups

### 1. Nodes (`/api/nodes`)

**Purpose:** Manage the compute node registry — the source of truth for which nodes exist, their IPs, groups, and collect agents.

| Endpoint | Method | What it does |
|---|---|---|
| `/api/nodes` | GET | List all nodes ordered by name |
| `/api/nodes` | POST | Register a new node |
| `/api/nodes/[nodeId]` | GET | Get a single node's metadata |
| `/api/nodes/[nodeId]` | PUT | Edit node metadata (name, IP, group) |
| `/api/nodes/[nodeId]` | DELETE | Remove node from registry |

**Key design notes:**
- `id` is the same string as `nodeId` in all InfluxDB measurements — it is the join key across every part of the system.
- Real-time status (`active` / `idle` / `down`) is NOT stored here. It is derived at query time: active = seen in InfluxDB in the last 10 s, idle = last 5 min, down = older than 5 min. This mirrors Grafana's logic.
- The dashboard page calls `GET /api/nodes` to populate the node list and status grid.

---

### 2. Analytics (`/api/analytics`)

**Purpose:** Answer two questions — "how much resource did each user consume?" and "what does usage look like over time?"

#### 2a. User Usage (`/api/analytics/user-usage`)

| Endpoint | Method | What it does |
|---|---|---|
| `/api/analytics/user-usage?mode=summary&from=&to=` | GET | Per-user totals (CPU hours, peak memory, peak GPU, total disk I/O) |
| `/api/analytics/user-usage?mode=timeseries&uid=&from=&to=` | GET | Hourly CPU-hours for one user (feed into Recharts line chart) |
| `/api/analytics/user-usage?mode=apps&uid=&from=&to=` | GET | Per-app breakdown for one user (comm field from process table) |

**Key design notes:**
- Queries run against `user_app_hourly` (a TimescaleDB continuous aggregate written by the pipeline), joined with `hpc_users` for human-readable names.
- `uid` is a Linux UID integer — it is the join key between `hpc_users` and `user_app_hourly`. It is NOT a UUID.
- `mode=summary` drives the user selector on `/analytics`. `mode=timeseries` drives the Recharts chart. `mode=apps` drives the per-user app breakdown toggle.
- Time range defaults: `from` = 7 days ago, `to` = now.

#### 2b. AI Chart (`/api/analytics/ai-chart`)

| Endpoint | Method | What it does |
|---|---|---|
| `/api/analytics/ai-chart` | POST | Accept a natural-language prompt, return a chart config |

**Key design notes:**
- Currently a stub: parses keywords (`gpu`, `bar`, `stacked`, etc.) and returns synthetic data shaped like `{ title, resource, chartType, data: [{t, value}] }`.
- In a future phase this can be wired to an LLM (Claude API) to generate real queries from the prompt.
- The `/analytics/ai-chart` page POSTs the user's prompt here and renders whatever chart config is returned.

---

### 3. Configuration (`/api/config`)

Three sub-groups manage the three editable config domains.

#### 3a. Collection Settings (`/api/config/collection`)

**Purpose:** Control how often each compute node's collect agent samples metrics and its aggregation window.

| Endpoint | Method | What it does |
|---|---|---|
| `/api/config/collection` | GET | All nodes with their current settings (LEFT JOIN) |
| `/api/config/collection/[nodeId]` | PUT | Save/update settings for one node (upsert) |

**Key design notes:**
- Uses `INSERT ... ON CONFLICT DO UPDATE` so a node with no settings row yet gets one automatically.
- The `/config/collection` page shows a table of nodes and opens an edit modal → PUT.
- In Phase 3 these settings should also be pushed to etcd so the collect agent picks them up live.

#### 3b. Pipeline Rules (`/api/config/pipeline`)

**Purpose:** CRUD for preprocessing rules (filter / aggregate / derive) that are sent to collect agents.

| Endpoint | Method | What it does |
|---|---|---|
| `/api/config/pipeline` | GET | All rules |
| `/api/config/pipeline` | POST | Create new rule |
| `/api/config/pipeline/[id]` | PUT | Edit rule (also used to toggle `enabled`) |
| `/api/config/pipeline/[id]` | DELETE | Remove rule |

**Key design notes:**
- `type` is constrained to `filter | aggregate | derive`. `resource` to `cpu | gpu | mem | disk | net`.
- The `enabled` field is toggled by a switch on the `/config/pipeline` page without opening the full edit modal — the PUT endpoint handles partial updates too.

#### 3c. Alert Rules (`/api/config/alerts`)

**Purpose:** CRUD for threshold-based alert rules. Each rule watches one resource on a node group and fires a notification when the threshold is crossed.

| Endpoint | Method | What it does |
|---|---|---|
| `/api/config/alerts` | GET | All alert rules |
| `/api/config/alerts` | POST | Create new rule |
| `/api/config/alerts/[id]` | PUT | Edit rule |
| `/api/config/alerts/[id]` | DELETE | Remove rule |

**Key design notes:**
- `operator` values: `> < >= <=`. `severity` values: `info | warning | critical`.
- `node_group` is a free string (e.g. `"gpu-cluster"`, `"all"`) — matches `group_name` on nodes.
- When a triggered alert fires in a future phase, it writes a row to `notifications` with the matching `rule_id`.

---

### 4. Governance (`/api/config/governance`)

**Purpose:** Maintain a history of configuration snapshots and a tamper-evident audit trail of every admin action.

| Endpoint | Method | What it does |
|---|---|---|
| `/api/config/governance/versions` | GET | All config versions, newest first |
| `/api/config/governance/versions` | POST | Save a new version snapshot |
| `/api/config/governance/audit` | GET | Last 100 audit log entries, newest first |
| `/api/config/governance/rollout` | POST | Activate a version (transactional) |

**Rollout transaction (critical path):**
```
BEGIN
  UPDATE config_versions SET active=FALSE        -- deactivate all
  UPDATE config_versions SET active=TRUE WHERE id=$1  -- activate target
  INSERT INTO audit_logs (action='ROLLOUT', ...)  -- record who did it
COMMIT
```

**Key design notes:**
- `config_snapshot` is a JSONB column — the POST endpoint snapshots the current state of all settings at save time.
- Every destructive or state-changing action in the app should append to `audit_logs` (CREATE / UPDATE / DELETE / ROLLOUT / LOGIN). The audit GET is read-only from the UI.

---

### 5. Notifications (`/api/notifications`)

**Purpose:** Surface in-app alerts that were fired when a metric crossed an alert rule threshold.

| Endpoint | Method | What it does |
|---|---|---|
| `/api/notifications` | GET | All notifications with node name (JOIN), newest first |
| `/api/notifications` | POST | Create a notification (called by alert engine) |
| `/api/notifications/[id]` | PUT | Acknowledge a notification (`acknowledged=true`) |

**Key design notes:**
- The GET response joins with `nodes` to include `node_name` for display.
- The acknowledge PUT is called when the admin clicks "dismiss" in the notification panel.
- In Phase 3, a background job or Grafana webhook would POST to this endpoint when a threshold fires.

---

### 6. Chat (`/api/chat`)

**Purpose:** Power the `/chat` assistant page.

| Endpoint | Method | What it does |
|---|---|---|
| `/api/chat` | POST | Accept a message, return an assistant reply |

**Key design notes:**
- Currently a keyword-matching stub (cpu → utilization summary, alert → active alerts count, etc.).
- Response shape matches `ChatMessage`: `{ id, role: "assistant", content, timestamp }`.
- Future: replace keyword matching with a Claude API call that has access to live cluster metrics as tool-call context.

---

## Implementation Plan

### Prerequisites (do once)
1. Run the schema: `psql $TIMESCALE_URL -f db/schema.sql`
2. Verify all 9 tables exist: `\dt` in psql
3. Add `ETCD_URL=http://localhost:2379` to `.env.local`
4. Check etcd key structure: `etcdctl get / --prefix --keys-only` then adjust prefix in `src/lib/etcd.ts`

### Phase 2 — API Routes (DONE)
All 16 route files created under `src/app/api/`. Build passes with zero errors.

```
✅ src/app/api/nodes/route.ts
✅ src/app/api/nodes/[nodeId]/route.ts
✅ src/app/api/analytics/user-usage/route.ts
✅ src/app/api/analytics/ai-chart/route.ts
✅ src/app/api/config/collection/route.ts
✅ src/app/api/config/collection/[nodeId]/route.ts
✅ src/app/api/config/pipeline/route.ts
✅ src/app/api/config/pipeline/[id]/route.ts
✅ src/app/api/config/alerts/route.ts
✅ src/app/api/config/alerts/[id]/route.ts
✅ src/app/api/config/governance/versions/route.ts
✅ src/app/api/config/governance/audit/route.ts
✅ src/app/api/config/governance/rollout/route.ts
✅ src/app/api/notifications/route.ts
✅ src/app/api/notifications/[id]/route.ts
✅ src/app/api/chat/route.ts
```

### Phase 3 — Integration (NEXT)

For each page, replace the mock data import with a real `fetch` call.

**Step-by-step per page:**

| Page | Remove | Replace with |
|---|---|---|
| `/dashboard` | `mockNodes` | `GET /api/nodes` |
| `/dashboard/nodes` | `mockNodes` | `GET /api/nodes` |
| `/dashboard/nodes/[nodeId]` | `mockNodes.find(...)` | `GET /api/nodes/[nodeId]` |
| `/analytics` | `mockUserUsage` | `GET /api/analytics/user-usage?mode=summary` |
| `/analytics` (chart) | hardcoded series | `GET /api/analytics/user-usage?mode=timeseries&uid=...` |
| `/analytics/ai-chart` | mock chart | `POST /api/analytics/ai-chart` |
| `/config/collection` | `mockCollectionSettings` | `GET /api/config/collection` |
| `/config/collection` (save) | no-op | `PUT /api/config/collection/[nodeId]` |
| `/config/pipeline` | `mockRules` | `GET /api/config/pipeline` |
| `/config/pipeline` (CRUD) | local state only | `POST / PUT / DELETE /api/config/pipeline` |
| `/config/alerts` | `mockAlertRules` | `GET /api/config/alerts` |
| `/config/alerts` (CRUD) | local state only | `POST / PUT / DELETE /api/config/alerts` |
| `/config/governance` | `mockVersions` | `GET /api/config/governance/versions` |
| `/config/governance` (audit) | `mockAuditLogs` | `GET /api/config/governance/audit` |
| `/config/governance` (rollout) | mock handler | `POST /api/config/governance/rollout` |
| `/chat` | canned replies | `POST /api/chat` |

**Pattern for server components (preferred):**
```ts
// In a server component (no "use client")
const res = await fetch(`${process.env.NEXT_PUBLIC_BASE_URL}/api/nodes`, { cache: "no-store" })
const nodes = await res.json()
```

**Pattern for interactive client components:**
```ts
// In a "use client" component that needs user interaction
const [data, setData] = useState([])
useEffect(() => {
  fetch("/api/config/pipeline").then(r => r.json()).then(setData)
}, [])
```

**Add loading states:**
```tsx
<Suspense fallback={<div className="animate-pulse h-40 bg-[#1c2128] rounded" />}>
  <NodeList />
</Suspense>
```

**Wire Grafana iframes:**
```ts
const grafanaUrl = (dashId: string, panelId: number, range = "1h") =>
  `${process.env.GRAFANA_BASE_URL}/d/${dashId}?panelId=${panelId}&kiosk&from=now-${range}&to=now`
```

### Phase 4 — Future Enhancements (optional)

| Feature | What to build |
|---|---|
| Real-time node status | Poll `GET /api/nodes` every 10 s on dashboard (or use SSE) |
| Alert engine | Cron job or Grafana webhook → `POST /api/notifications` |
| Claude-powered chat | Replace chat stub with Anthropic SDK call + metric tool-calls |
| AI chart (real) | Replace keyword stub with Claude API generating a TimescaleDB query |
| HPC user sync | Import from LDAP/SLURM into `hpc_users` table automatically |

---

## etcd API — Live Config Management

### Why etcd?

TimescaleDB is the **source of truth for the UI** (persists settings across restarts, drives the config pages).
etcd is the **live config bus** — compute node agents and collect agents watch their key prefixes and reload config immediately when a key changes, without any restart.

The two stores are kept in sync: whenever the admin saves a change in the UI, the backend writes to TimescaleDB **and** pushes the same value to etcd in one request.

### etcd Key Structure

From the setup script, two key namespaces are used:

```
/config/compute_node/{nodeId}/target_collect_agent   → gRPC address (e.g. "localhost:50051")
/config/compute_node/{nodeId}/window                 → collection window in seconds (e.g. "5.0")
/config/compute_node/{nodeId}/heartbeat_interval     → heartbeat in seconds (e.g. "10.0")
/config/compute_node/{nodeId}/status                 → "running" | "stopped"

/config/collect_agent/{agentId}/kafka_brokers        → JSON array string (e.g. '["localhost:9092"]')
/config/collect_agent/{agentId}/kafka_topic          → topic name (e.g. "monitoring_metrics")
/config/collect_agent/{agentId}/grpc_port            → port string (e.g. "50051")
/config/collect_agent/{agentId}/threshold_rules      → JSON object (see below)
```

**Default threshold_rules shape:**
```json
{
  "cpu_usage_percent":           { "max": 90 },
  "memory_usage_percent":        { "max": 85 },
  "gpu_max_temperature_celsius": { "max": 85 },
  "gpu_max_power_watts":         { "max": 300 },
  "gpu_max_utilization_percent": { "max": 95 }
}
```

### etcd Route Group — Compute Nodes (`/api/etcd/nodes`)

| Endpoint | Method | What it does |
|---|---|---|
| `/api/etcd/nodes` | GET | Scan `/config/compute_node/` prefix → return all nodes with their config fields |
| `/api/etcd/nodes` | POST | Create all 4 keys for a new node; status defaults to `"stopped"` |
| `/api/etcd/nodes/[nodeId]` | GET | Read all keys under `/config/compute_node/{nodeId}/` |
| `/api/etcd/nodes/[nodeId]` | PUT | Partial update: only writes keys whose fields are present in the body |
| `/api/etcd/nodes/[nodeId]` | DELETE | Delete all keys under `/config/compute_node/{nodeId}/` |
| `/api/etcd/nodes/[nodeId]/status` | GET | Return just `{ nodeId, status }` |
| `/api/etcd/nodes/[nodeId]/status` | PUT | Set status to `"running"` or `"stopped"` (validated) |

**Key design notes:**
- `GET /api/etcd/nodes` parses the flat KV map (all keys matching the prefix) into structured objects grouped by `nodeId`. Each object has: `nodeId`, `target_collect_agent`, `window`, `heartbeat_interval`, `status`.
- `PUT /api/etcd/nodes/[nodeId]` only writes keys that are present in the request body — fields omitted are left unchanged in etcd. This is a safe partial update.
- The `/status` sub-route is kept separate because toggling a node on/off (`running`/`stopped`) is a frequent action (Start/Stop buttons on the dashboard) and should not accidentally overwrite other config fields.
- All routes return `503` if etcd is unreachable, so the UI can degrade gracefully.

### etcd Route Group — Collect Agents (`/api/etcd/agents`)

| Endpoint | Method | What it does |
|---|---|---|
| `/api/etcd/agents` | GET | Scan `/config/collect_agent/` prefix → return all agents with their config fields |
| `/api/etcd/agents` | POST | Create all 4 keys for a new agent with defaults |
| `/api/etcd/agents/[agentId]` | GET | Read all keys; `threshold_rules` and `kafka_brokers` are JSON-parsed |
| `/api/etcd/agents/[agentId]` | PUT | Partial update: `kafka_brokers`, `kafka_topic`, `grpc_port` |
| `/api/etcd/agents/[agentId]` | DELETE | Delete all keys under `/config/collect_agent/{agentId}/` |
| `/api/etcd/agents/[agentId]/threshold-rules` | GET | Return parsed `threshold_rules` object |
| `/api/etcd/agents/[agentId]/threshold-rules` | PUT | Replace the full `threshold_rules` JSON in etcd |

**Key design notes:**
- `kafka_brokers` is stored as a JSON array string in etcd (matching the setup script: `'["localhost:9092"]'`). The GET route parses it back to an array. The PUT route accepts either an array or a raw string.
- `threshold_rules` is a separate sub-route because it has its own schema, is edited in a dedicated UI section, and is replaced atomically as a whole object.
- `GET /api/etcd/agents/[agentId]` JSON-parses both `kafka_brokers` and `threshold_rules` before returning, so the client always gets native types.

### Dual-Write on Collection Settings Save

`PUT /api/config/collection/[nodeId]` (the UI config save endpoint) now writes to **both** stores in one request:

```
1. INSERT/UPDATE collection_settings in TimescaleDB  (authoritative for UI)
2. etcd.put window, heartbeat_interval, target_collect_agent  (live push to agent)
```

The etcd push is non-fatal — if etcd is down, the DB write succeeds and a warning is logged. The agent will pick up the new config on next startup from etcd, or you can trigger a manual push via the `/api/etcd/nodes/[nodeId]` PUT endpoint.

### Infrastructure Setup

**`next.config.ts`** — etcd3 loads `.proto` files at runtime using `__dirname`; it must not be bundled by Turbopack:
```ts
serverExternalPackages: ["etcd3", "@grpc/grpc-js", "@grpc/proto-loader"]
```

**`.env.local`** — add:
```
ETCD_URL=http://localhost:2379
```

**Docker Compose** — the etcd server exposes port `2379` with no authentication (`ALLOW_NONE_AUTHENTICATION=yes`). The `etcd3` client in `src/lib/etcd.ts` connects to `ETCD_URL` at module load time.

### Quick Reference — All etcd Routes

```
GET  POST  /api/etcd/nodes
GET  PUT   DELETE  /api/etcd/nodes/[nodeId]
GET  PUT          /api/etcd/nodes/[nodeId]/status

GET  POST  /api/etcd/agents
GET  PUT   DELETE  /api/etcd/agents/[agentId]
GET  PUT          /api/etcd/agents/[agentId]/threshold-rules
```
