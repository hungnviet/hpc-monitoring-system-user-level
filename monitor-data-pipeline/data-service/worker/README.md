# Worker Services

Python worker services that bridge Kafka to the storage layer. Three containers are defined in `docker-compose.yml`, all built from the same `Dockerfile`.

## Contents

```
worker/
├── docker-compose.yml        # Three service definitions
├── Dockerfile                # python:3.9-slim + libpq-dev
├── .env.example              # Template — copy to .env and fill in values
├── .env                      # Actual credentials (git-ignored, you must create this)
├── monitor_consumer.py       # Service 1: Kafka → InfluxDB
├── hourly_aggregator.py      # Service 3: InfluxDB → TimescaleDB (hourly ETL)
└── requirements.txt          # Python dependencies (must be created — see below)
```

> **Note:** `requirements.txt` is not committed to the repository but is required by the Dockerfile. Create it before running `docker compose up --build` (see [Setup](#setup)).

## Services

### `hpc_metrics_consumer` — `monitor_consumer.py`

Consumes JSON messages from the Kafka topic `monitoring_metrics` and writes them to InfluxDB as two measurements:

- **`node_status`** — system-level metrics (CPU %, memory %, GPU utilisation, GPU temperature, GPU power, disk I/O, network I/O) tagged by `node_id`
- **`process_metrics`** — per-process metrics (CPU time, RSS memory, disk I/O, network I/O, GPU memory) tagged by `node_id`, `uid`, `comm`, `pid`

Runs continuously. Restarts automatically on failure (`restart: always`).

### `hpc_hourly_aggregator` — `hourly_aggregator.py`

Scheduled ETL job that runs **once per hour**. It queries InfluxDB for the previous hour's data using Flux and upserts summarised rows into two TimescaleDB hypertables:

- `node_status_hourly` — node-level averages, maxima, and totals
- `user_app_hourly` — per-user, per-process aggregates

Uses `schedule` to trigger at the top of each hour. Runs continuously. Restarts automatically on failure (`restart: always`).

### `hpc_metadata_sync` — `sync_metadata.py`

One-shot synchronisation of metadata. Runs once at startup and exits (`restart: "no"`).

> **Note:** `sync_metadata.py` is not present in the repository. This container will fail to start. It does not affect `hpc_metrics_consumer` or `hpc_hourly_aggregator`.

## Setup

### 1. Create `requirements.txt`

```bash
cd monitor-data-pipeline/data-service/worker
cat > requirements.txt << 'EOF'
kafka-python>=2.0.2
influxdb-client>=1.36.0
psycopg2-binary>=2.9.6
schedule>=1.2.0
EOF
```

### 2. Configure `.env`

```bash
cp .env.example .env
# Edit .env and fill in all values
```

| Variable | Description | Example |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | Kafka broker address(es), comma-separated | `192.168.1.100:9092` |
| `KAFKA_TOPIC` | Kafka topic to consume | `monitoring_metrics` |
| `KAFKA_CONSUMER_GROUP` | Consumer group ID | `hpc_worker_group` |
| `INFLUX_URL` | InfluxDB HTTP URL | `http://192.168.1.101:8086` |
| `INFLUX_TOKEN` | InfluxDB admin token (from `influx/.env` `INFLUXDB_ADMIN_TOKEN`) | — |
| `INFLUX_ORG` | InfluxDB organisation (must match `influx/.env` `INFLUXDB_ORG`) | `hpcc-org` |
| `INFLUX_BUCKET` | InfluxDB bucket (must match `influx/.env` `INFLUXDB_BUCKET`) | `metrics` |
| `PG_HOST` | TimescaleDB host IP | `192.168.1.101` |
| `PG_PORT` | TimescaleDB port | `5432` |
| `PG_DB` | Database name | `hpc_monitoring` |
| `PG_USER` | Database user | `admin` |
| `PG_PASS` | Database password (from `timescale/.env` `POSTGRES_PASSWORD`) | — |

> Both `INFLUX_TOKEN` and `PG_PASS` are required. The containers will exit immediately at startup if either is missing.

### 3. Build and start

```bash
docker compose up -d --build
```

## Verify

```bash
# Check all containers are running
docker ps --filter name=hpc_metrics_consumer
docker ps --filter name=hpc_hourly_aggregator

# Tail consumer logs — should show "Listening from Kafka and writing to InfluxDB..."
docker logs -f hpc_metrics_consumer

# Tail aggregator logs — should show hourly ETL runs
docker logs -f hpc_hourly_aggregator
```

## Network

All three services use `network_mode: "host"`, so they connect to all other services using their actual host IP addresses (as configured in `.env`). There is no inter-container DNS.

## Shutdown

```bash
docker compose down
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Build fails: `COPY requirements.txt` | File not created | Create `requirements.txt` as shown in [Setup](#setup) |
| Consumer exits: `INFLUX_TOKEN environment variable is required` | `INFLUX_TOKEN` not set in `.env` | Copy `INFLUXDB_ADMIN_TOKEN` from `influx/.env` |
| Aggregator exits: `Missing required environment variables: PG_PASS` | `PG_PASS` not set in `.env` | Set `PG_PASS` in `.env` |
| Consumer connects but writes nothing | Wrong `INFLUX_ORG` or `INFLUX_BUCKET` | Values must match exactly what was used during InfluxDB initialisation |
| Aggregator query returns no data | No data in InfluxDB yet | Start the consumer first and wait for the pipeline to produce messages; check with `docker logs hpc_metrics_consumer` |
| `hpc_metadata_sync` exits with error | `sync_metadata.py` not in repo | Expected — ignore this container until the file is added |
