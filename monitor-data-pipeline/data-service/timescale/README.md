# TimescaleDB

TimescaleDB stores **hourly-aggregated** metrics produced by the `hourly_aggregator` worker, and all **admin tables** managed by the hpc-admin web application.

## Contents

```
timescale/
├── docker-compose.yml   # Service definition
├── .env.example         # Template for required credentials
├── .env                 # Actual credentials (git-ignored, you must create this)
├── initdb.sql           # Schema applied automatically on first start
└── data/                # Persistent volume (git-ignored)
```

## Schema

`initdb.sql` is mounted into `/docker-entrypoint-initdb.d/` and runs once when the container starts for the first time with an empty data directory.

### Hypertables (written by the `hourly_aggregator` worker)

#### `node_status_hourly`

One row per `(bucket_time, node_id)` — hourly node-level resource summary.

| Column | Type | Description |
|---|---|---|
| `bucket_time` | TIMESTAMPTZ | Start of the 1-hour bucket |
| `node_id` | TEXT | Compute node identifier |
| `avg_cpu_usage_percent` | DOUBLE PRECISION | Average CPU usage % |
| `max_cpu_usage_percent` | DOUBLE PRECISION | Peak CPU usage % |
| `avg_mem_usage_percent` | DOUBLE PRECISION | Average memory usage % |
| `max_mem_used_bytes` | BIGINT | Peak memory bytes used |
| `avg_gpu_utilization` | DOUBLE PRECISION | Average GPU utilisation % |
| `max_gpu_temperature` | INT | Peak GPU temperature °C |
| `total_gpu_power_watts` | DOUBLE PRECISION | Total GPU power draw (W) |
| `total_disk_read_bytes` | BIGINT | Total disk read bytes |
| `total_disk_write_bytes` | BIGINT | Total disk write bytes |
| `total_net_rx_bytes` | BIGINT | Total network receive bytes |
| `total_net_tx_bytes` | BIGINT | Total network transmit bytes |
| `is_active` | BOOLEAN | Whether the node was active in the bucket |

#### `user_app_hourly`

One row per `(bucket_time, node_id, uid, comm)` — hourly per-user, per-process summary.

| Column | Type | Description |
|---|---|---|
| `bucket_time` | TIMESTAMPTZ | Start of the 1-hour bucket |
| `node_id` | TEXT | Compute node identifier |
| `uid` | INT | Linux user ID |
| `comm` | TEXT | Process command name |
| `total_cpu_time_seconds` | DOUBLE PRECISION | Total CPU time (s) |
| `avg_rss_memory_bytes` | BIGINT | Average RSS memory (bytes) |
| `max_rss_memory_bytes` | BIGINT | Peak RSS memory (bytes) |
| `max_gpu_memory_mib` | INT | Peak GPU memory (MiB) |
| `total_read_bytes` | BIGINT | Total disk read bytes |
| `total_write_bytes` | BIGINT | Total disk write bytes |
| `total_net_rx_bytes` | BIGINT | Total network receive bytes |
| `total_net_tx_bytes` | BIGINT | Total network transmit bytes |
| `process_count` | INT | Number of distinct processes aggregated |

### Admin tables (written by hpc-admin)

These tables are created by `Application/hpc-admin/db/schema.sql` and must be applied separately after the container starts:

`nodes`, `hpc_users`, `collection_settings`, `pipeline_rules`, `alert_rules`, `notifications`, `config_versions`, `audit_logs`, `custom_dashboards`

## Configuration

Copy the example file and fill in your values before starting:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_DB` | `hpc_monitoring` | Database name — must match `PG_DB` in the worker `.env` and `TIMESCALE_URL` in hpc-admin |
| `POSTGRES_USER` | `admin` | PostgreSQL superuser name |
| `POSTGRES_PASSWORD` | *(must set)* | PostgreSQL password |

## Start

```bash
docker compose up -d
```

The schema in `initdb.sql` is applied automatically the first time the container starts with an empty `data/` directory.

## Apply hpc-admin schema

Run this once after the container is up:

```bash
# From the repo root
docker exec -i hpc_timescaledb psql -U admin -d hpc_monitoring \
  < Application/hpc-admin/db/schema.sql
```

## Verify

```bash
# All tables should be listed
docker exec -it hpc_timescaledb psql -U admin -d hpc_monitoring -c "\dt"

# Confirm hypertables
docker exec -it hpc_timescaledb psql -U admin -d hpc_monitoring \
  -c "SELECT hypertable_name FROM timescaledb_information.hypertables;"
```

## Useful commands

```bash
# Connect interactively
docker exec -it hpc_timescaledb psql -U admin -d hpc_monitoring

# Check row counts
docker exec -it hpc_timescaledb psql -U admin -d hpc_monitoring \
  -c "SELECT COUNT(*) FROM node_status_hourly;"
```

## Shutdown

```bash
# Stop only (data preserved)
docker compose down

# Stop and delete all data (destructive — schema will be re-applied on next start)
docker compose down -v
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `initdb.sql` not applied | Volume already existed from a previous run | `docker compose down -v` then `docker compose up -d` |
| Port 5432 already in use | Another PostgreSQL running on the host | Change the host port in `docker-compose.yml`, e.g. `"15432:5432"`, and update all connection strings |
| `password authentication failed` | `.env` password doesn't match what was used when the volume was created | `docker compose down -v` and recreate with the correct password |
