# InfluxDB

InfluxDB stores **raw real-time metrics** as they arrive from the Kafka consumer. It acts as the high-resolution time-series store from which the `hourly_aggregator` queries and summarises data into TimescaleDB.

## Contents

```
influx/
├── docker-compose.yml   # Service definition
├── .env.example         # Template for required credentials and init config
├── .env                 # Actual credentials (git-ignored, you must create this)
├── config/              # InfluxDB runtime config (auto-generated on first start)
└── data/                # Persistent volume (git-ignored)
```

## Measurements

Data is written by the `monitor_consumer.py` worker. Two measurements are used inside the configured bucket:

| Measurement | Written by | Description |
|---|---|---|
| `node_status` | `monitor_consumer.py` | System-level metrics per node: CPU %, memory %, GPU utilisation %, GPU temperature, GPU power, disk I/O, network I/O |
| `process_metrics` | `monitor_consumer.py` | Per-process metrics: CPU time, memory (RSS), disk I/O, network I/O, GPU memory |

Tags on `node_status`: `node_id`  
Tags on `process_metrics`: `node_id`, `uid`, `comm`, `pid`

## Configuration

Copy the example file and fill in all values before starting:

```bash
cp .env.example .env
```

| Variable | Description |
|---|---|
| `INFLUXDB_USERNAME` | Admin username (e.g. `admin`) |
| `INFLUXDB_PASSWORD` | Admin password — use a strong password |
| `INFLUXDB_ORG` | Organisation name (e.g. `hpcc-org`) — must match `INFLUX_ORG` in the worker `.env` |
| `INFLUXDB_BUCKET` | Bucket name (e.g. `metrics`) — must match `INFLUX_BUCKET` in the worker `.env` |
| `INFLUXDB_ADMIN_TOKEN` | Long random token used by all clients — generate with `openssl rand -hex 32` |

> The `INFLUXDB_ADMIN_TOKEN` value must be copied into the worker `.env` as `INFLUX_TOKEN`, and into the Grafana InfluxDB data source configuration.

## Start

```bash
docker compose up -d
```

On the first start, InfluxDB reads the `INFLUXDB_*` environment variables to create the organisation, bucket, and admin token. Subsequent starts ignore these init variables (the data directory already exists).

## Verify

```bash
# HTTP health check
curl -s http://localhost:8086/health

# Expected response:
# {"name":"influxdb","message":"ready for queries and writes","status":"pass",...}
```

You can also open the InfluxDB UI at `http://<host>:8086` and log in with `INFLUXDB_USERNAME` / `INFLUXDB_PASSWORD`.

## Connect Grafana

1. In Grafana → **Configuration → Data Sources → Add data source → InfluxDB**
2. Set **Query Language** to `Flux`
3. Set **URL** to `http://<DB_HOST_IP>:8086`
4. Under **InfluxDB Details**, set:
   - `Organization` — value of `INFLUXDB_ORG`
   - `Token` — value of `INFLUXDB_ADMIN_TOKEN`
   - `Default Bucket` — value of `INFLUXDB_BUCKET`
5. Click **Save & Test**

## Useful commands

```bash
# List all buckets via CLI inside the container
docker exec hpc_influxdb influx bucket list \
  --token <INFLUXDB_ADMIN_TOKEN> \
  --org <INFLUXDB_ORG>

# Run a quick Flux query to check data is arriving
docker exec hpc_influxdb influx query \
  --token <INFLUXDB_ADMIN_TOKEN> \
  --org <INFLUXDB_ORG> \
  'from(bucket: "metrics") |> range(start: -5m) |> limit(n: 5)'
```

## Shutdown

```bash
# Stop only (data preserved)
docker compose down

# Stop and delete all data (destructive — init env vars will re-run on next start)
docker compose down -v
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Container exits immediately | `.env` not created or variables missing | Ensure `.env` has all 5 variables set |
| Worker writes fail with 401 | Wrong token in worker `.env` | Copy the exact value of `INFLUXDB_ADMIN_TOKEN` into the worker's `INFLUX_TOKEN` |
| Worker writes fail with "bucket not found" | `INFLUX_BUCKET` in worker doesn't match `INFLUXDB_BUCKET` | Make both values identical |
| Grafana shows no data | Data source misconfigured | Re-check org, token, and bucket in Grafana; run the Flux query above to confirm data is present |
| Init variables ignored on restart | Data directory already exists | Expected behaviour — InfluxDB only reads init vars once. To re-init: `docker compose down -v` |
