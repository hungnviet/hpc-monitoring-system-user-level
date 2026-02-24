# HPC Monitor Admin — Project Context for Claude

## Project Overview
Web application for HPC cluster administrators built with Next.js 16 (App Router) + Tailwind CSS v4.
The HPC pipeline (Compute Node Agents → Collect Agents → Kafka → InfluxDB/TimescaleDB) is already running.
Grafana panels are already deployed. This web app manages configuration and provides analytics.

## Architecture
```
Pipeline: Compute Nodes → Collect Agents → Kafka → InfluxDB (real-time) / TimescaleDB (historical)
Web App:  Next.js (App Router) → TimescaleDB (pg) + Grafana (iframe embed)
```

## Tech Stack
- **Framework:** Next.js 16, App Router, TypeScript
- **Styling:** Tailwind CSS v4 (`@import "tailwindcss"` + `@theme` in globals.css — NO tailwind.config.ts)
- **Auth:** Auth.js v5 / next-auth@beta (use `auth()` not `getServerSession()`)
- **DB:** `pg` (node-postgres) → TimescaleDB. Pool singleton at `src/lib/db.ts`
- **Charts:** Recharts
- **Route protection:** `src/proxy.ts` exports `{ auth as proxy }` (Next.js 16 renamed middleware→proxy)

## Important Conventions
- Route groups: `(auth)` for login, `(protected)` for all admin pages
- Protected layout at `src/app/(protected)/layout.tsx` calls `auth()` and redirects to `/login`
- All pages are `"use client"` — server components only used for the protected layout auth check
- DB queries use parameterized `pool.connect()` / `client.release()` pattern (see Phase 2 plan)
- Colors: `#0d1117` bg, `#161b22` surface, `#1c2128` card, `#30363d` border, `#58a6ff` primary
- No tailwind.config.ts — extend theme via CSS `@theme { --color-xxx: ... }` in globals.css

## Current Implementation Status

### ✅ Phase 0 — Project Setup (COMPLETE)
- `npx create-next-app` scaffolded + deps installed
- `.env.local` has: `NEXTAUTH_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `TIMESCALE_URL`, `GRAFANA_BASE_URL`

### ✅ Phase 1 — Frontend with Mock Data (COMPLETE)
All 15 routes built, `npm run build` passes zero errors.

**All mock data lives in `src/lib/mockData/`** — will be replaced in Phase 3.

| Route | Page |
|---|---|
| `/login` | Admin login |
| `/dashboard` | Cluster overview + Grafana panel placeholders |
| `/dashboard/nodes` | Node list with filter/search |
| `/dashboard/nodes/[nodeId]` | Node detail |
| `/analytics` | User usage history charts (Recharts) |
| `/analytics/custom` | Custom dashboard builder |
| `/analytics/ai-chart` | AI chart generator (mock) |
| `/chat` | Chatbot (mock) |
| `/config/collection` | Collection settings per node |
| `/config/pipeline` | Pipeline preprocessing rules |
| `/config/alerts` | Alert threshold rules |
| `/config/governance` | Version history + audit log |

### 🔲 Phase 2 — Backend API Routes (NEXT)
**Prerequisite:** Run `db/schema.sql` against TimescaleDB first.

API routes to create in `src/app/api/`:
```
nodes/route.ts                       GET  → SELECT * FROM nodes
nodes/[nodeId]/route.ts              GET  → SELECT * FROM nodes WHERE id=$1
analytics/user-usage/route.ts        GET  → query user_usage hypertable
config/collection/route.ts           GET  → JOIN nodes + collection_settings
config/collection/[nodeId]/route.ts  PUT  → UPSERT collection_settings
config/pipeline/route.ts             GET/POST
config/pipeline/[id]/route.ts        PUT/DELETE
config/alerts/route.ts               GET/POST
config/alerts/[id]/route.ts          PUT/DELETE
config/governance/versions/route.ts  GET
config/governance/audit/route.ts     GET
config/governance/rollout/route.ts   POST
notifications/route.ts               GET
notifications/[id]/route.ts          PUT (acknowledge)
analytics/ai-chart/route.ts          POST (stub)
chat/route.ts                        POST (stub)
```

### 🔲 Phase 3 — Integration (after Phase 2)
- Replace `src/lib/mockData/*` imports with `fetch('/api/...')` calls
- Wire Grafana iframe URLs: `${GRAFANA_BASE_URL}/d/{dashId}?panelId={id}&kiosk&from=now-{range}&to=now`
- Add loading skeletons (Suspense) and error states

## Database Schema

### Tables from existing pipeline (READ from these, do NOT write)
> Verify exact column names with `\d tablename` in psql before writing queries

- `metrics` — time-series node metrics (columns: likely `time`, `node_id`, `resource`, `value`)
- `user_usage` — user-attributed usage (confirm if exists: `\dt user_usage`)

### New tables for admin app (in `db/schema.sql`)
- `nodes` — compute node registry
- `hpc_users` — HPC users for analytics
- `collection_settings` — per-node collection config
- `pipeline_rules` — preprocessing rule definitions
- `alert_rules` — threshold alert rules
- `notifications` — in-app alert instances
- `config_versions` — configuration version history
- `audit_logs` — admin action audit trail
- `custom_dashboards` — saved chart panel configs

Full DDL in `db/schema.sql` (to be created before Phase 2).

## Key File Paths
| Purpose | Path |
|---|---|
| Types | `src/types/index.ts` |
| DB pool | `src/lib/db.ts` |
| Auth | `src/auth.ts` |
| Route guard | `src/proxy.ts` |
| Mock data | `src/lib/mockData/` |
| Env vars | `.env.local` |
| Schema SQL | `db/schema.sql` |

## Run Commands
```bash
cd Application/hpc-admin
npm run dev      # start dev server → http://localhost:3000
npm run build    # production build check
```
Login: use values from `.env.local` (`ADMIN_EMAIL` / `ADMIN_PASSWORD`)

## What NOT to change
- `src/app/globals.css` — Tailwind v4 theme is here, not in tailwind.config.ts
- `src/proxy.ts` — exports `{ auth as proxy }` (not middleware) for Next.js 16
- `src/auth.ts` — uses Auth.js v5 API (`handlers`, `signIn`, `signOut`, `auth`)
- UI color palette — defined in globals.css `@theme` block
