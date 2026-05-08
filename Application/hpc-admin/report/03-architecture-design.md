# Chapter 3 — Architecture and Design

> **Estimated length:** 15–20 pages.
> **Purpose:** show the solution at design level. Technology choices, high-level architecture, layered decomposition, data model, etcd key schema, API design, security, external integrations, configuration governance.

## 3.1 Technology stack decisions

The stack was chosen for four reasons that run through every decision: (a) a single language (TypeScript) end-to-end to reduce integration friction; (b) server and client under the same framework so route protection, data fetching, and UI are coherent; (c) minimal indirection over the database and etcd because both schemas are already well-defined by the pipeline; (d) reliance on the existing Grafana deployment rather than reimplementing charts for real-time data.

### 3.1.1 Next.js 16 (App Router) + TypeScript

Next.js 16 is used for both the UI and the API. The App Router gives three features that match the requirements directly:

- **File-based routing**, so every URL corresponds to a folder in `src/app`.
- **Route groups** such as `(auth)` and `(protected)`, which are used in §3.4 to model authentication boundaries without changing URL paths.
- **Server components in layouts**, which let the protected layout check the session on the server before rendering any child page.

Two Next.js 16 specificities are important to document:

- Middleware was renamed to **proxy**. The file [src/proxy.ts](../src/proxy.ts) exports `{ auth as proxy }` and a `matcher`. A pre-16 tutorial would call this file `middleware.ts`.
- Dynamic route params are **Promises**: `const { id } = await params`. Every API route that uses `[param]` awaits it, e.g. [src/app/api/nodes/[nodeId]/route.ts](../src/app/api/nodes/[nodeId]/route.ts).

### 3.1.2 Auth.js v5 (next-auth@beta) with credentials + JWT

Auth.js v5 is used because (a) it is the official authentication library recommended by the Next.js team for App Router; (b) it exposes a simple `auth()` function that returns the current session in server components; (c) a JWT-session strategy means no server-side session store is needed. A credentials provider is sufficient for the single-admin scenario specified in Chapter 2; SSO / OIDC is listed in future work.

### 3.1.3 Tailwind CSS v4 with theme-in-CSS

Tailwind v4 is used without a `tailwind.config.ts`. The theme tokens (colour palette `#0d1117`, `#161b22`, `#1c2128`, `#30363d`, `#58a6ff`, etc.) are declared inside the `@theme` block of [src/app/globals.css](../src/app/globals.css). This keeps the visual identity in one place and removes the need for a compile-time JS config.

### 3.1.4 PostgreSQL / TimescaleDB via `pg` pool

The application talks to TimescaleDB directly through `pg` (`node-postgres`), without an ORM. The rationale is:

- The analytics queries lean heavily on TimescaleDB-specific SQL (`time_bucket`, `DISTINCT ON`, hypertables), which ORMs abstract away awkwardly.
- The admin tables are few and simple (nine tables) and CRUD can be expressed in one-screen SQL.
- A single shared `Pool` at [src/lib/db.ts](../src/lib/db.ts) avoids connection exhaustion: every API route does `pool.connect()` and releases in a `finally` block.

### 3.1.5 etcd3 client

Live pipeline configuration uses etcd because the compute-node and collect agents already watch their own keys there; writing through a separate indirection would only add latency. [src/lib/etcd.ts](../src/lib/etcd.ts) creates one shared `Etcd3` client (v3 gRPC protocol) and every API route imports it.

### 3.1.6 Recharts for analytics, Grafana iframe for real-time

Recharts is used on pages where the application owns the data (`/analytics`, `/dashboard/nodes/[nodeId]`). Real-time cluster and per-node panels are owned by Grafana and embedded via `iframe` using the solo-dashboard URL pattern documented in §3.9.1. Not duplicating Grafana's chart work is a deliberate scope decision.

### 3.1.7 Summary of dependencies

From [package.json](../package.json), the runtime dependencies are limited and intentional:

| Package | Version | Purpose |
|---|---|---|
| `next` | 16.1.6 | framework |
| `react`, `react-dom` | 19.2.3 | UI |
| `next-auth` | 5.0.0-beta.x | authentication |
| `pg` | ^8.18.0 | PostgreSQL / TimescaleDB driver |
| `etcd3` | ^1.1.2 | etcd v3 client |
| `recharts` | ^3.7.0 | analytics charts |
| `tailwindcss` | v4 | styling |

No AI SDK is imported at runtime because the AI microservice is a separate process reached over HTTP (see §3.9.2).

## 3.2 High-level architecture

A high-level component diagram of the runtime system is provided in [diagrams.md §High-level architecture](diagrams.md#high-level-architecture). Four facts are worth emphasising here:

1. The browser is the only **active** client; all fetches originate from the admin's browser.
2. The Next.js server is a **single process** that serves both the HTML pages (App Router) and the JSON API (`/api/...`). There is no separate backend.
3. **Reads** flow from the Next.js server to TimescaleDB (SQL) or etcd (gRPC). **Writes** that affect the pipeline fan out to *both* TimescaleDB (for durable record and audit) and etcd (for live configuration).
4. The browser talks directly to **Grafana** via `iframe` because solo-dashboard URLs are public to anyone who can reach the Grafana server; and to the **AI microservice** via `fetch` to `http://localhost:5000/visualize` because both run on the admin's workstation in the current deployment.

## 3.3 Layered decomposition

The application is organised into four layers, each with one directory in the repository.

| Layer | Directory | Responsibility |
|---|---|---|
| Presentation | [src/app/(auth)](../src/app/(auth)), [src/app/(protected)](../src/app/(protected)), [src/components](../src/components) | UI pages and reusable components. |
| API | [src/app/api](../src/app/api) | HTTP JSON handlers (Next.js route handlers). |
| Integration | [src/lib](../src/lib) | Singletons and helpers that talk to TimescaleDB, etcd, Grafana. |
| Data | [db/schema.sql](../db/schema.sql) + TimescaleDB hypertables | Relational schema owned by the application + pipeline-owned hypertables read only. |

Cross-cutting: [src/auth.ts](../src/auth.ts), [src/proxy.ts](../src/proxy.ts), [src/types/index.ts](../src/types/index.ts).

A component-level diagram showing the imports between these layers is provided in [diagrams.md §Layered decomposition](diagrams.md#layered-decomposition).

## 3.4 Route and navigation design

### Route groups

Next.js route groups `(auth)` and `(protected)` carry no URL segment; they exist only to attach different layouts.

- `(auth)/login/page.tsx` is the only unauthenticated route.
- `(protected)/layout.tsx` wraps every admin page, calls `await auth()` and redirects to `/login` on null session, then renders the `Sidebar` and `Header` around `{children}`.

Code reference (unchanged, 19 lines):

```1:19:Application/hpc-admin/src/app/(protected)/layout.tsx
import { auth } from "@/auth"
import { redirect } from "next/navigation"
import { Sidebar } from "@/components/layout/Sidebar"
import { Header } from "@/components/layout/Header"

export default async function ProtectedLayout({ children }: { children: React.ReactNode }) {
  const session = await auth()
  if (!session) redirect("/login")

  return (
    <div className="min-h-screen bg-[#0d1117]">
      <Sidebar />
      <Header />
      <main className="ml-60 pt-14 min-h-screen">
        {children}
      </main>
    </div>
  )
}
```

### Sidebar grouping

The sidebar groups routes into three sections that mirror the product goals from Chapter 2:

- **Monitoring** — Dashboard (`/dashboard`), Nodes (`/dashboard/nodes`), Analytics (`/analytics`).
- **Configuration** — Collection (`/config/collection`), Pipeline (`/config/pipeline`), Alerts (`/config/alerts`), Governance (`/config/governance`).
- **Assistance** — Chat (`/chat`), AI Chart (`/analytics/ai-chart`).

A route tree is shown in [diagrams.md §Route tree](diagrams.md#route-tree).

## 3.5 Data model

### Admin-owned tables (managed by the web app)

Defined in [db/schema.sql](../db/schema.sql):

| Table | Purpose |
|---|---|
| `nodes` | Compute-node registry (id, name, ip, group, default collect agent). |
| `hpc_users` | Cluster users for joining against `user_app_hourly.uid`. |
| `collection_settings` | Per-node override of interval/window/collect_agent (1:1 to `nodes`). |
| `pipeline_rules` | Named rules of type `filter` / `aggregate` / `derive` on a resource. |
| `alert_rules` | Threshold rules per node group, with operator and severity. |
| `notifications` | Alert instances (joined with `nodes` for display). |
| `config_versions` | Immutable JSON snapshots of configuration, at most one marked `active`. |
| `audit_logs` | Administrator actions of type `CREATE` / `UPDATE` / `DELETE` / `ROLLOUT` / `LOGIN`. |
| `custom_dashboards` | Saved chart definitions for the analytics custom-dashboard page. |

### Pipeline-owned hypertables (read-only for the web app)

| Hypertable | Primary key | Use |
|---|---|---|
| `node_status_hourly` | (`bucket_time`, `node_id`) | per-node hourly metrics. |
| `user_app_hourly` | (`bucket_time`, `node_id`, `uid`, `comm`) | per-user-per-application hourly metrics. |

Both are TimescaleDB hypertables with `bucket_time` as the time dimension. The admin application never writes to them.

An entity-relationship diagram is in [diagrams.md §Entity-relationship diagram](diagrams.md#entity-relationship-diagram).

## 3.6 etcd key schema

The admin application adopts the schema that the pipeline already defines. The table below lists every key *that the application reads or writes*.

### Compute-node scope

| Key | Direction | Purpose |
|---|---|---|
| `/config/compute_node/{nodeId}/target_collect_agent` | read/write | IP:port of the collect agent the node must send gRPC to. |
| `/config/compute_node/{nodeId}/window` | read/write | sampling window in seconds. |
| `/config/compute_node/{nodeId}/heartbeat_interval` | read/write | heartbeat cadence in seconds. |
| `/config/compute_node/{nodeId}/status` | read/write | `running` or `stopped`. |
| `/nodes/{nodeId}/heartbeat` | read only | JSON `{ timestamp, status, collection_active }` written by the agent. |

### Collect-agent scope

| Key | Direction | Purpose |
|---|---|---|
| `/config/collect_agent/{agentId}/kafka_brokers` | read/write | JSON array of brokers. |
| `/config/collect_agent/{agentId}/kafka_topic` | read/write | Kafka topic name. |
| `/config/collect_agent/{agentId}/pipeline_stages` | read/write | JSON array of processing-stage names the agent instantiates on startup. |
| `/config/collect_agent/{agentId}/process_fields` | read/write | JSON array — allow-list of per-process fields retained after `field_projection`. |
| `/config/collect_agent/{agentId}/comm_prefixes` | read/write | JSON array — process-name prefixes folded by `prefix_aggregation`. |
| `/config/collect_agent/{agentId}/threshold_rules` | read/write | JSON object derived from `alert_rules`, consumed by the `threshold_checker` stage. |

The admin application currently writes only a subset of these keys (`kafka_brokers`, `kafka_topic`, `threshold_rules`) plus a legacy `pipeline_rules` array that the agent does not read. Appendix B documents every key the agent reads, and [Chapter 6 §6.3](06-conclusion.md#63-future-work) tracks the work to bring the push handler in line with this schema.

### Node status derivation

Node status is **not** stored as a simple boolean. It is derived at read time from the heartbeat:

```
threshold = heartbeat_interval * 3      // default 20s × 3 = 60s
isAlive = heartbeat.status == "alive"
         && now - heartbeat.timestamp <= threshold
node.status = isAlive ? "running" : "stopped"
```

This derivation lives in [src/app/api/etcd/nodes/route.ts](../src/app/api/etcd/nodes/route.ts). The rationale is that the administrator cares about *observed liveness*, not *configured intent*, and heartbeats are the authoritative signal.

## 3.7 API design principles

Five conventions are applied uniformly across the 30 API routes.

1. **REST over JSON** with file-based routing. Each folder under `src/app/api` maps to a URL, and each `route.ts` exports named `GET`, `POST`, `PUT`, `DELETE` functions.
2. **Reads go to TimescaleDB** (registry + analytics), **writes that affect the pipeline go to both the DB and etcd**. The DB is the source of truth for versioning and audit; etcd receives a *projection* of the active configuration.
3. **Bind parameters always**, allow-lists never interpolated. For analytics, resource names (`cpu`, `mem`, `gpu`, `disk`, `net`) are mapped to hard-coded SQL expressions:

   ```5:11:Application/hpc-admin/src/app/api/analytics/user-usage/route.ts
   // Hardcoded SQL expressions per resource — no user input in SQL
   const RESOURCE_SQL: Record<string, string> = {
     cpu:  "SUM(h.total_cpu_time_seconds)",
     mem:  "MAX(h.max_rss_memory_bytes) / 1048576.0",
     gpu:  "MAX(h.max_gpu_memory_mib)",
     disk: "SUM(h.total_read_bytes + h.total_write_bytes) / 1048576.0",
     net:  "SUM(h.total_net_rx_bytes + h.total_net_tx_bytes) / 1048576.0",
   }
   ```

4. **Graceful degradation** on external failures. The etcd route returns `503` when etcd is unreachable rather than `500`; the *snapshot-and-push* flow commits the DB transaction *before* pushing to etcd and reports etcd errors separately so the admin knows what landed.
5. **Status codes.** `200` for read, `201` for create, `400` for validation error, `404` for unknown id, `500` for unexpected failures, `503` for dependency unavailable.

## 3.8 Security design

### Authentication

- Credentials provider against env vars; JWT session strategy. See [src/auth.ts](../src/auth.ts).
- Single handler route at [src/app/api/auth/[...nextauth]/route.ts](../src/app/api/auth/[...nextauth]/route.ts) exports `GET` and `POST` from `handlers`.
- The protected layout is a server component that calls `auth()` and redirects on null session.

### Route protection

- `src/proxy.ts` exports `{ auth as proxy }`. Its `matcher` excludes `_next/static`, `_next/image`, `favicon.ico`, `login`, and `api/auth`.

  ```1:5:Application/hpc-admin/src/proxy.ts
  export { auth as proxy } from "@/auth"

  export const config = {
    matcher: ["/((?!api/auth|_next/static|_next/image|favicon.ico|login).*)"],
  }
  ```

### Known gap (to be addressed; see Chapter 6)

The matcher above protects **HTML routes** and redirects unauthenticated users to `/login`. However, the other `/api/*` routes are not currently wrapped in an explicit session check inside each handler. On a shared network this would allow an unauthenticated client to call, for example, `/api/config/pipeline`. The mitigation is to call `await auth()` at the top of each API handler and return `401` when no session exists; this is planned work tracked in Chapter 6.

### SQL safety

Every SQL statement uses `$1`, `$2`, … placeholders. User-provided strings that feed aggregation expressions (e.g. `resource` in analytics) are mapped through hard-coded allow-lists before SQL is built.

### Client secrets

No secret is exposed to the browser. TimescaleDB and etcd credentials live in `.env.local` only; NextAuth's `NEXTAUTH_SECRET` is server-side. The Grafana host is server-rendered into the iframe `src` value.

## 3.9 External integrations design

### 3.9.1 Grafana (real-time panels)

The admin app embeds **solo-panel** URLs from an existing Grafana instance. Pattern:

```
http://{GRAFANA_HOST}/d-solo/{dashUid}/{dashSlug}?orgId=1
    &timezone=browser
    &__feature.dashboardSceneSolo=true
    &var-node={nodeId}         ← only on node-detail panels
    &from=now-{range}&to=now
    &panelId={panelId}
    &refresh=10s               ← only on live panels
```

Only the parameters in the table below are varied by the application:

| Parameter | Set by |
|---|---|
| `var-node` | node-detail page, URL-encoded `{nodeId}` |
| `from` / `to` | time-range selector in the UI (`1h` / `6h` / `24h` / `7d` / `30d`) |
| `panelId` | hard-coded per metric (CPU, memory, GPU, disk, network) |

The component that actually renders the iframe is [src/components/dashboard/GrafanaPanel.tsx](../src/components/dashboard/GrafanaPanel.tsx); it shows a loading placeholder until `onLoad` fires and a different placeholder when `src` is empty (so pages can render a stub when `GRAFANA_BASE_URL` is not configured).

### 3.9.2 AI microservice

The admin application calls a separate HTTP microservice to turn natural language into a chart. The contract is intentionally tiny:

**Request**

```
POST http://localhost:5000/visualize
Content-Type: application/json

{ "question": "Show GPU memory usage" }
```

**Response**

```json
{
  "reasoning": "string",
  "pipeline": "static_chart | grafana_embed",
  "code_render_svg": "<svg>…</svg> | null",
  "panel_embed_url": "http://{host}/d-solo/…?… | null"
}
```

If `panel_embed_url` is present, the admin page rewrites the host to `localhost` so the iframe renders inside the browser environment (the microservice may return an internal host unreachable from the admin's machine). The interaction is sequenced in [diagrams.md §AI chart generation sequence](diagrams.md#ai-chart-generation-sequence).

There is also a stub route at `/api/analytics/ai-chart` that predates the microservice integration and returns mocked data based on keyword parsing. The `/analytics/ai-chart` page does **not** call it; it is kept because other code paths may still reference it, and removing it is scheduled as a housekeeping task in Chapter 6.

## 3.10 Configuration governance design

The most complex flow is *snapshot-and-push*, implemented in [src/app/api/config/governance/snapshot-and-push/route.ts](../src/app/api/config/governance/snapshot-and-push/route.ts). Its design follows three principles:

1. **Durable first, live second.** The database transaction (save a new `config_versions` row, deactivate all others, write an `audit_logs` entry) commits before any etcd write begins. If etcd is unavailable, the administrator has a persisted, audited snapshot she can retry against etcd later.
2. **Versioning is derived.** The new version is `{major}.{minor}.{patch+1}` of the latest row; `1.0.0` is used when there is no history. This keeps the domain simple and avoids an explicit version input.
3. **Fan-out to discovered agents.** Rather than maintaining a separate registry of collect agents, the flow *discovers* them from etcd (`/config/collect_agent/` prefix) at the moment of the push. This matches the operational reality that agents can be added and removed at any time.

A sequence diagram is in [diagrams.md §Snapshot-and-push sequence](diagrams.md#snapshot-and-push-sequence).

The sibling *rollout* flow (`/api/config/governance/rollout`) is a degenerate case of *snapshot-and-push*: instead of reading current state from the DB it reads a previously saved `config_snapshot`, replays the fan-out to etcd, marks that version active, and writes the audit entry. The symmetric design makes it straightforward to add "preview" and "diff" features later.

## 3.11 Summary

The architecture of the admin application is intentionally thin:

- one Next.js process that serves both HTML and JSON;
- two singletons (`pg.Pool`, `Etcd3`) for every external write;
- two data stores (TimescaleDB, etcd) with well-defined responsibilities;
- two external systems (Grafana, AI microservice) that the browser speaks to directly.

Chapter 4 walks through how each module realises this design in code.
