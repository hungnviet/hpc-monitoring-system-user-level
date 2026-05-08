# Chapter 2 — System Analysis

> **Estimated length:** 8–12 pages.
> **Purpose:** define the environment, the actors, the functional and non-functional requirements, and the use cases. No implementation details yet.

## 2.1 Environment and related components

The admin web application is one node in a larger monitoring system that the author also built as part of the thesis (separate subsystem `monitor-data-pipeline`). The rest of the system is treated as **environment** in this report: its behaviour is assumed, not documented.

The pipeline runs on every compute node and produces time-series metrics at two levels of aggregation:

- A **compute-node agent** (Python + eBPF, requires root) samples CPU, memory, GPU, disk, and network activity per process and sends gRPC messages to its configured collect agent. It reads its own configuration (collection window, heartbeat interval, target collect agent, running/stopped status) from **etcd** under `/config/compute_node/{nodeId}/...` and publishes its own heartbeat at `/nodes/{nodeId}/heartbeat`.
- A **collect agent** (Python, asyncio) receives gRPC messages from multiple compute nodes, runs a small processing pipeline (schema validation → filtering → enrichment → threshold checks → configurable aggregation), then publishes records to **Kafka**. Its configuration (Kafka brokers, topic, gRPC port, threshold rules, pipeline rules) also lives in etcd under `/config/collect_agent/{agentId}/...`.
- Kafka consumers (outside the scope of this thesis) persist the aggregated records into two TimescaleDB hypertables, `node_status_hourly` and `user_app_hourly`.
- **Grafana** reads from the same TimescaleDB and exposes dashboards that the admin application embeds through solo-panel iframes.

The admin application therefore never talks to the agents directly. It communicates through three stable boundaries:

| Boundary | Direction | Purpose |
|---|---|---|
| TimescaleDB | read only | historical analytics, latest metrics per node |
| etcd | read + write | live pipeline configuration and node status |
| Grafana | embedded iframe | real-time panels |

A system-context diagram is shown in [diagrams.md §System context](diagrams.md#system-context).

## 2.2 Stakeholders and actors

### Primary actor

**HPC administrator.** A single human role in the current version. The credentials provider in [src/auth.ts](../src/auth.ts) compares the submitted email/password against the environment variables `ADMIN_EMAIL` and `ADMIN_PASSWORD` — there is exactly one account. The architecture does not preclude multiple accounts or role-based access control; that is tracked as future work in Chapter 6.

### Secondary actors (systems)

| Actor | Role for this application |
|---|---|
| TimescaleDB | source of historical metrics (`node_status_hourly`, `user_app_hourly`) and home of the admin-owned tables (`nodes`, `hpc_users`, `collection_settings`, `pipeline_rules`, `alert_rules`, `notifications`, `config_versions`, `audit_logs`, `custom_dashboards`). |
| etcd | source of live pipeline configuration and heartbeats; also the destination of configuration writes made through the admin UI. |
| Grafana | visualizer of real-time metrics. The admin app embeds solo panels with a URL template documented in Chapter 3. |
| AI microservice | external HTTP service reachable at `http://localhost:5000/visualize`, responsible for turning natural-language questions into either an SVG chart or a Grafana embed URL. Built by the author but out of scope for this report. |

## 2.3 Functional requirements

The functional requirements are grouped by the four product goals from §1.3.

### FR-1. Real-time monitoring (Grafana embedding)

- **FR-1.1** The cluster dashboard shall embed a configurable set of cluster-level Grafana solo panels (CPU, memory, GPU, disk, network) with a user-selectable time range (1h / 6h / 24h).
- **FR-1.2** The node detail page shall embed per-node Grafana solo panels for the same set of resources, scoped via `var-node={nodeId}`.
- **FR-1.3** The cluster dashboard shall also show derived counters: total nodes, running nodes, stopped nodes, active alerts count.

### FR-2. Historical analytics

- **FR-2.1** The node list shall show, for each node, the last hourly bucket of CPU %, memory %, and GPU utilisation from `node_status_hourly`.
- **FR-2.2** The node detail page shall plot a chosen metric over a chosen range (24h / 48h / 7d / 30d) using Recharts over `node_status_hourly`.
- **FR-2.3** The user analytics page shall show, for a given date range, a summary of CPU seconds, peak memory, peak GPU memory, disk I/O, and network I/O per user from `user_app_hourly`.
- **FR-2.4** The user analytics page shall support drilling down to an individual user's time-series for a single resource.
- **FR-2.5** The user analytics page shall support a per-application breakdown (grouped by `comm`) across multiple selected users.
- **FR-2.6** All analytics queries shall use bind parameters only; resource names that feed aggregation expressions must come from an allow-list, never from interpolated user input.

### FR-3. AI-assisted charting

- **FR-3.1** The administrator shall be able to type a natural-language question and receive, in the same page, either a rendered SVG chart or an embedded Grafana panel that answers it.
- **FR-3.2** The admin application shall delegate question understanding and chart selection to the external AI microservice at `http://localhost:5000/visualize` and must tolerate network failure of that service (clear error message, no crash).
- **FR-3.3** When the AI microservice returns a remote Grafana URL, the admin application shall rewrite the host to `localhost` so that the iframe works inside the browser environment the administrator uses.

### FR-4. Dynamic configuration

Node registry:

- **FR-4.1** CRUD on the `nodes` table (id, name, ip, group, default collect agent).
- **FR-4.2** For each registered node, the administrator can create or update its live configuration in etcd (`target_collect_agent`, `window`, `heartbeat_interval`).
- **FR-4.3** The administrator can start or stop data collection on a node by toggling `/config/compute_node/{nodeId}/status` between `running` and `stopped`.

Collection settings:

- **FR-4.4** A screen lists every node with its current collection settings merged from `nodes` and `collection_settings`; editing a node's settings writes to both the DB and the corresponding etcd keys.

Pipeline rules and alerts:

- **FR-4.5** CRUD on `pipeline_rules` (filter / aggregate / derive on a resource) and on `alert_rules` (per-group threshold with severity).
- **FR-4.6** A "push to etcd" action writes all enabled pipeline rules as a JSON array under `/config/collect_agent/{agentId}/pipeline_rules` for every discovered agent.
- **FR-4.7** A similar action writes alert thresholds as a JSON object under `/config/collect_agent/{agentId}/threshold_rules`, with operator `>` / `>=` rules aggregated into per-resource minimums.

Governance:

- **FR-4.8** A *snapshot-and-push* action gathers the current DB state (collection settings + pipeline rules + threshold rules), auto-increments a semantic version, stores the JSON snapshot in `config_versions` (marked active), deactivates other versions, writes an `audit_logs` entry, and pushes the derived configuration to every discovered node and agent in etcd in a single transaction.
- **FR-4.9** A *rollout* action replays a saved snapshot back into etcd.
- **FR-4.10** Every administrator action affecting configuration shall be recorded in `audit_logs`.

Notifications:

- **FR-4.11** The notifications panel lists alert instances (`notifications` table, joined with `nodes` for readability) and allows acknowledging each one.

## 2.4 Non-functional requirements

| Category | Requirement |
|---|---|
| Usability | Dark-themed UI consistent with modern admin dashboards; all destructive actions confirmed; loading and empty states present on every page. |
| Performance | API p95 under 500 ms for analytics endpoints on a dataset of up to one year of hourly buckets. Grafana iframes load asynchronously and do not block the rest of the UI. |
| Availability | Single-instance deployment acceptable for the thesis; if etcd or the AI microservice is unreachable, the affected page shall degrade gracefully (show an error banner, keep other features usable). |
| Security | Every page except `/login` requires an authenticated session. Every SQL query uses bind parameters. No secret is shipped to the client. |
| Maintainability | TypeScript end-to-end; shared types in `src/types/index.ts`; single database pool (`src/lib/db.ts`) and etcd client (`src/lib/etcd.ts`); no `tailwind.config.ts` — theme tokens in `globals.css`. |
| Observability | Server-side console logs on every API error; future work to add structured logs and OpenTelemetry (see Chapter 6). |
| Extensibility | Route-group strategy and co-located API handlers make it straightforward to add new modules without touching existing ones. |

## 2.5 Use case catalogue

A use-case diagram is shown in [diagrams.md §Use cases](diagrams.md#use-case-diagram). The textual use cases follow the template *ID / actor / trigger / preconditions / main flow / alternative flows / postconditions*.

| ID | Title | Actor |
|---|---|---|
| UC-01 | Log in | Administrator |
| UC-02 | View cluster dashboard | Administrator |
| UC-03 | View node detail | Administrator |
| UC-04 | Start / stop data collection on a node | Administrator |
| UC-05 | View user usage analytics | Administrator |
| UC-06 | Generate a chart from a natural-language question | Administrator |
| UC-07 | Manage nodes (CRUD) | Administrator |
| UC-08 | Edit pipeline rules and push to etcd | Administrator |
| UC-09 | Edit alert rules and push thresholds to etcd | Administrator |
| UC-10 | Snapshot current configuration and push as a new version | Administrator |
| UC-11 | Roll back to a previous configuration version | Administrator |
| UC-12 | Review the audit log | Administrator |
| UC-13 | Acknowledge a notification | Administrator |

### UC-01 Log in (fully written example)

- **Trigger:** the administrator opens any URL of the application.
- **Preconditions:** the `ADMIN_EMAIL` and `ADMIN_PASSWORD` environment variables are set on the server.
- **Main flow:**
  1. The `src/proxy.ts` matcher intercepts the request because the path is neither `/login` nor `/api/auth/*`.
  2. The protected layout at [src/app/(protected)/layout.tsx](../src/app/(protected)/layout.tsx) calls `auth()`; if there is no session the user is redirected to `/login`.
  3. The administrator enters email and password; the client calls `signIn("credentials", { email, password, redirect: false })`.
  4. If the credentials match, `authorize` in [src/auth.ts](../src/auth.ts) returns a user object; NextAuth creates a JWT session.
  5. The browser is redirected to `/dashboard`.
- **Alternative flow:** if the credentials do not match, an in-page error is shown and no session is created.
- **Postconditions:** the administrator has a JWT session cookie and can reach any `(protected)` page.

The remaining use cases (UC-02 … UC-13) shall follow the same template and sit alongside this one in the final thesis; stubs are provided as bullet points above.

## 2.6 Requirements traceability

The table below maps every functional requirement to the module in Chapter 4 that realises it. It is also used as the basis for the test plan in Chapter 5 (every FR must have at least one positive and one negative test case).

| FR | Module (Chapter 4 §) | API routes | Page(s) |
|---|---|---|---|
| FR-1.1 | §4.7 Grafana embedding | — | `/dashboard` |
| FR-1.2 | §4.7 | — | `/dashboard/nodes/[nodeId]` |
| FR-1.3 | §4.6 Analytics | `/api/analytics/cluster-stats`, `/api/etcd/nodes` | `/dashboard` |
| FR-2.1 | §4.4 Node registry | `/api/nodes/metrics/latest` | `/dashboard/nodes` |
| FR-2.2 | §4.4 | `/api/nodes/[nodeId]/hourly` | `/dashboard/nodes/[nodeId]` |
| FR-2.3 to 2.5 | §4.6 | `/api/analytics/user-usage` | `/analytics` |
| FR-2.6 | §4.6 (SQL allow-list) | same | same |
| FR-3.1 to 3.3 | §4.10 AI chart | external `:5000/visualize` | `/analytics/ai-chart` |
| FR-4.1 | §4.4 | `/api/nodes`, `/api/nodes/[nodeId]` | `/dashboard/nodes` |
| FR-4.2 | §4.5 etcd module | `/api/etcd/nodes`, `/api/etcd/nodes/[nodeId]` | `/config/collection` |
| FR-4.3 | §4.5 | `/api/etcd/nodes/[nodeId]/status` | `/dashboard/nodes/[nodeId]`, `/config/collection` |
| FR-4.4 | §4.8 Config | `/api/config/collection`, `/api/config/collection/[nodeId]` | `/config/collection` |
| FR-4.5 | §4.8 | `/api/config/pipeline`, `/api/config/alerts` (+ `[id]`) | `/config/pipeline`, `/config/alerts` |
| FR-4.6 | §4.8 | `/api/config/pipeline/push-to-etcd` | `/config/pipeline` |
| FR-4.7 | §4.8 | `/api/config/alerts/push-to-etcd` | `/config/alerts` |
| FR-4.8 | §4.8 Governance | `/api/config/governance/snapshot-and-push` | `/config/governance` |
| FR-4.9 | §4.8 | `/api/config/governance/rollout` | `/config/governance` |
| FR-4.10 | §4.8 | `/api/config/governance/audit` | `/config/governance` |
| FR-4.11 | §4.9 Notifications | `/api/notifications`, `/api/notifications/[id]` | sidebar panel + dashboard |
