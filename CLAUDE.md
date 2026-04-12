# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is an HPC cluster monitoring system consisting of two major subsystems:

```
monitor-data-pipeline/    ← Python data pipeline (agents, Kafka, etcd)
Application/hpc-admin/    ← Next.js admin web app
```

**Data flow:**
```
Compute Node Agent  →(gRPC)→  Collect Agent  →(Kafka)→  TimescaleDB / InfluxDB
                                                                   ↓
                                              etcd ←────  hpc-admin (Next.js)
```

---

## monitor-data-pipeline

### Architecture

| Component | Location | Language | Role |
|---|---|---|---|
| Coordinator | `coordinator/` | Docker (etcd) | Central config & service discovery |
| Compute Node Agent | `compute-node-agent/` | Python | Collects per-process + system metrics via eBPF |
| Collect Agent | `collect-agent/` | Python (asyncio) | gRPC server, processing pipeline, Kafka publisher |
| Kafka | `kafka/` | Docker | Message broker |

### Key conventions

- Both agents read from **etcd** at startup and watch for config changes live — no restart needed to change collection parameters
- Compute node agent requires **root** to run (eBPF): `sudo venv/bin/python main.py`
- Each agent's local identity is in `infra.json` (`node_id` for compute node, `collect_agent_id` for collect agent)
- Protobuf files must be generated before running: `python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/metrics.proto`

### Collect agent pipeline stages (in order)

1. `SchemaValidator` — field validation and range checks
2. `MetricsFilter` — removes system/bootstrap processes
3. `MetricsEnricher` — adds timestamps and agent metadata
4. `ThresholdChecker` — CPU/GPU/memory threshold alerts
5. `UserProcessor` — configurable aggregation/sampling via etcd

### etcd key schema

```
/config/compute_node/{node_id}/target_collect_agent  → "ip:50051"
/config/compute_node/{node_id}/window                → "5.0"
/config/compute_node/{node_id}/heartbeat_interval    → "10.0"
/config/compute_node/{node_id}/status                → "running"|"stopped"

/nodes/{node_id}/heartbeat   → JSON: { timestamp, status, collection_active }

/config/collect_agent/{agent_id}/kafka_brokers       → JSON array
/config/collect_agent/{agent_id}/kafka_topic         → "metrics"
/config/collect_agent/{agent_id}/grpc_port           → "50051"
/config/collect_agent/{agent_id}/threshold_rules     → JSON object
/config/collect_agent/{agent_id}/user_processors     → JSON array
```

### Run commands

```bash
# Coordinator
cd monitor-data-pipeline/coordinator && docker-compose up -d

# Collect agent
cd monitor-data-pipeline/collect-agent
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/metrics.proto
python main.py

# Compute node agent (requires root for eBPF)
cd monitor-data-pipeline/compute-node-agent
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/metrics.proto
sudo venv/bin/python main.py

# Kafka
cd monitor-data-pipeline/kafka && docker-compose up -d

# Start/stop collection for a node (from coordinator)
docker exec etcd-server etcdctl put /config/compute_node/<node_id>/status running
docker exec etcd-server etcdctl put /config/compute_node/<node_id>/status stopped
```

---

## Application/hpc-admin

### Tech stack

- **Framework:** Next.js 16 App Router + TypeScript
- **Styling:** Tailwind CSS v4 — `@import "tailwindcss"` + `@theme` in `globals.css`. **No `tailwind.config.ts`** — extend theme only via CSS `@theme {}` block
- **Auth:** Auth.js v5 / `next-auth@beta` — use `auth()`, not `getServerSession()`
- **DB:** `pg` pool singleton (`src/lib/db.ts`) → TimescaleDB. Pattern: `pool.connect()` → query → `client.release()`
- **etcd:** `etcd3` client singleton (`src/lib/etcd.ts`)
- **Charts:** Recharts

### Run commands

```bash
cd Application/hpc-admin
npm run dev      # dev server → http://localhost:3000
npm run build    # production build (type-check + route compilation)
npm run lint     # ESLint
```

### Architecture

**Route protection:** `src/proxy.ts` (Next.js 16 renamed middleware → proxy) exports `{ auth as proxy }`. All routes except `/login`, `/api/auth/*`, and static assets are protected.

**Layout hierarchy:**
```
src/app/layout.tsx                    ← root HTML shell (no auth)
src/app/(auth)/login/page.tsx         ← public login
src/app/(protected)/layout.tsx        ← calls auth(), redirects if no session; renders Sidebar + Header
src/app/(protected)/dashboard/        ← cluster overview + node detail
src/app/(protected)/analytics/        ← user usage charts, custom dashboards, AI chart
src/app/(protected)/config/           ← collection, pipeline, alerts, governance
src/app/(protected)/chat/             ← admin chatbot
```

**All pages are `"use client"`** — server components are only used for the protected layout's auth check.

**API routes** live under `src/app/api/`:
- `nodes/` + `nodes/[nodeId]/` — CRUD against `nodes` table
- `etcd/nodes/` + `etcd/nodes/[nodeId]/` — etcd config read/write; node status derived from heartbeat staleness (threshold = `heartbeat_interval × 3`)
- `analytics/` — queries `node_status_hourly` and `user_app_hourly` hypertables
- `config/` — collection_settings, pipeline_rules, alert_rules, config_versions, audit_logs
- `notifications/` — alert instances

**Route params** in Next.js 16 are Promises: `const { id } = await params`

### Database

Two TimescaleDB hypertables (written by the pipeline, read-only from the web app):
- `node_status_hourly` — bucketed node-level metrics (CPU, GPU, memory, disk, network)
- `user_app_hourly` — per-user, per-process metrics

Admin tables (managed by the web app via `db/schema.sql`):
- `nodes`, `hpc_users`, `collection_settings`, `pipeline_rules`, `alert_rules`, `notifications`, `config_versions`, `audit_logs`, `custom_dashboards`

### Infrastructure (live credentials in `.env.local`)

| Service | Address |
|---|---|
| TimescaleDB | `postgresql://admin:admin123@10.1.8.154:5432/hpc_monitoring` |
| etcd | `http://10.1.8.153:2379` |
| Grafana | `http://10.1.8.155:3000` |

Grafana panel embed URL pattern:
```
http://10.1.8.155:3000/d-solo/adtfbh4/h6-monitoring?orgId=1&timezone=browser&var-node={nodeId}&from=now-{range}&to=now&panelId={panelId}&__feature.dashboardSceneSolo=true
```

### Color palette

```
#0d1117  background
#161b22  surface
#1c2128  card
#30363d  border
#58a6ff  primary blue
```
