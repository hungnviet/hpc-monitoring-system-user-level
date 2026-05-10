# hpc-admin

Next.js 16 admin web application for managing and monitoring an HPC cluster.

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Next.js 16 (App Router) + TypeScript |
| Styling | Tailwind CSS v4 (`@import "tailwindcss"` + `@theme` in `globals.css`) |
| Auth | Auth.js v5 / `next-auth@beta` — credentials provider |
| Database | `pg` (node-postgres) → TimescaleDB |
| Config store | `etcd3` client → etcd |
| Charts | Recharts |

## Pages

| Route | Description |
|---|---|
| `/login` | Admin login (credentials from `.env.local`) |
| `/dashboard` | Cluster overview — active nodes, resource summaries, Grafana panel embeds |
| `/dashboard/nodes` | Full node list with search and status filter |
| `/dashboard/nodes/[nodeId]` | Per-node detail: metrics timeline + Grafana panels |
| `/analytics` | Per-user / per-application usage charts and tables |
| `/analytics/custom` | Custom dashboard builder (saved to TimescaleDB) |
| `/analytics/ai-chart` | AI-assisted chart generator |
| `/config/collection` | Collection settings per node (interval, window) — writes to etcd |
| `/config/pipeline` | Pipeline preprocessing rule editor |
| `/config/alerts` | Alert threshold rule editor — writes rules to etcd via push-to-etcd endpoint |
| `/config/governance` | Configuration versions, audit logs, and rollout controls |
| `/chat` | AI admin chatbot |

## API Routes

| Method | Route | Description |
|---|---|---|
| GET, POST | `/api/nodes` | List and register compute nodes |
| GET, PUT, DELETE | `/api/nodes/[nodeId]` | Single node CRUD |
| GET | `/api/nodes/[nodeId]/hourly` | Hourly metric time series from `node_status_hourly` |
| GET | `/api/nodes/metrics/latest` | Latest metric snapshot for all nodes |
| GET | `/api/etcd/nodes` | List all nodes from etcd with live status |
| GET, PUT | `/api/etcd/nodes/[nodeId]` | Per-node etcd config read/write |
| PUT | `/api/etcd/nodes/[nodeId]/status` | Start/stop collection (`running`/`stopped`) |
| GET | `/api/etcd/agents` | List collect agents from etcd |
| GET, PUT | `/api/etcd/agents/[agentId]` | Per-agent etcd config read/write |
| PUT | `/api/etcd/agents/[agentId]/threshold-rules` | Write threshold rules to etcd |
| GET | `/api/analytics/user-usage` | User and app usage from `user_app_hourly` |
| GET | `/api/analytics/cluster-stats` | Cluster-level aggregate stats |
| POST | `/api/analytics/ai-chart` | AI chart generation |
| GET, PUT | `/api/config/collection`, `/api/config/collection/[nodeId]` | Collection settings (DB) |
| GET, POST | `/api/config/pipeline` | Pipeline rules |
| PUT, DELETE | `/api/config/pipeline/[id]` | Single pipeline rule |
| POST | `/api/config/pipeline/push-to-etcd` | Sync pipeline rules to etcd |
| GET, POST | `/api/config/alerts` | Alert rules |
| PUT, DELETE | `/api/config/alerts/[id]` | Single alert rule |
| POST | `/api/config/alerts/push-to-etcd` | Sync alert rules to etcd |
| GET, POST | `/api/config/governance/versions` | Config version history |
| GET | `/api/config/governance/audit` | Audit log |
| POST | `/api/config/governance/rollout` | Roll out a saved config version |
| POST | `/api/config/governance/snapshot-and-push` | Snapshot current config and push to etcd |
| GET, POST | `/api/notifications` | Alert notifications |
| PUT | `/api/notifications/[id]` | Acknowledge a notification |
| POST | `/api/chat` | Admin chatbot |
| POST | `/api/auth/[...nextauth]` | Auth.js handler |

## Project Structure

```
src/
├── app/
│   ├── (auth)/login/               # Public login page
│   ├── (protected)/                # All admin pages (auth-gated layout)
│   │   ├── layout.tsx              # Calls auth(), redirects to /login if no session
│   │   ├── dashboard/
│   │   ├── analytics/
│   │   ├── config/
│   │   └── chat/
│   ├── api/                        # API route handlers
│   └── layout.tsx                  # Root HTML shell (no auth)
├── components/
│   ├── layout/                     # Sidebar, Header, NotificationsPanel
│   ├── dashboard/                  # GrafanaPanel, NodeStatusBadge, HealthIndicator
│   ├── analytics/                  # UsageChart, UsagePieChart, AppUsageTable, ...
│   └── ui/                         # Button, Badge, Input, Modal, Table, Select, ...
├── lib/
│   ├── db.ts                       # pg pool singleton → TimescaleDB
│   ├── etcd.ts                     # etcd3 client singleton
│   └── mockData/                   # Fallback mock data (alerts, analytics, chat, governance, nodes)
├── types/index.ts                  # Shared TypeScript types
├── auth.ts                         # Auth.js v5 config (credentials provider)
└── proxy.ts                        # Route guard — exports { auth as proxy }
db/
└── schema.sql                      # Full DDL: hypertables + 9 admin tables
```

## Database Schema

Two hypertables written by the pipeline (read-only in hpc-admin):

| Table | Description |
|---|---|
| `node_status_hourly` | Hourly node-level aggregates: CPU, memory, GPU, disk, network |
| `user_app_hourly` | Hourly per-user, per-process aggregates |

Nine admin tables managed by hpc-admin (`db/schema.sql`):

| Table | Description |
|---|---|
| `nodes` | Compute node registry |
| `hpc_users` | HPC user accounts |
| `collection_settings` | Per-node collection config |
| `pipeline_rules` | Preprocessing rule definitions |
| `alert_rules` | Threshold alert rules |
| `notifications` | In-app alert instances |
| `config_versions` | Versioned config snapshots |
| `audit_logs` | Admin action trail |
| `custom_dashboards` | Saved chart panel configurations |

## Environment Variables

Configure `src/.env.local` (file already exists, update the values):

| Variable | Description |
|---|---|
| `NEXTAUTH_SECRET` | Random secret for session signing — generate with `openssl rand -base64 32` |
| `ADMIN_EMAIL` | Login email for the admin UI |
| `ADMIN_PASSWORD` | Login password for the admin UI |
| `TIMESCALE_URL` | Full PostgreSQL connection string, e.g. `postgresql://admin:pass@host:5432/hpc_monitoring` |
| `GRAFANA_BASE_URL` | Grafana base URL for iframe embeds, e.g. `http://grafana-host:3000/d/adtfbh4/h6-monitoring` |
| `ETCD_URL` | etcd HTTP client URL, e.g. `http://etcd-host:2379` |

## Setup & Run

### 1. Install dependencies

```bash
cd Application/hpc-admin
npm install
```

### 2. Apply the database schema (once)

```bash
# From the repo root — replace credentials as needed
docker exec -i hpc_timescaledb psql -U admin -d hpc_monitoring < Application/hpc-admin/db/schema.sql
```

### 3. Configure `.env.local`

Edit `Application/hpc-admin/.env.local` to point to your running services (see [Environment Variables](#environment-variables) above).

### 4. Start the development server

```bash
npm run dev
# → http://localhost:3000
```

### 5. Production build

```bash
npm run build
npm run start
```

## Notes

- **All page components are `"use client"`** — server components are only used in the protected layout for the auth check.
- **Route protection** is handled by `src/proxy.ts` (Next.js 16 renamed `middleware` → `proxy`). All routes except `/login` and `/api/auth/*` redirect unauthenticated users to `/login`.
- **Route params** in Next.js 16 are Promises: always `const { id } = await params`.
- **Tailwind v4** — there is no `tailwind.config.ts`. Extend the theme only via the `@theme {}` block in `src/app/globals.css`.
- If Grafana runs on the same host as hpc-admin, run hpc-admin on a different port: `PORT=3001 npm run dev`.
