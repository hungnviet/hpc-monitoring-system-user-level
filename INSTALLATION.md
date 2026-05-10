# HPC Cluster Monitoring System — Installation & Deployment Guide

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Prerequisites](#2-prerequisites)
3. [Network & Port Requirements](#3-network--port-requirements)
4. [Deployment Order](#4-deployment-order)
5. [Step-by-Step Deployment](#5-step-by-step-deployment)
   - [5.1 Coordinator (etcd)](#51-coordinator-etcd)
   - [5.2 Kafka](#52-kafka)
   - [5.3 Databases (TimescaleDB + InfluxDB)](#53-databases-timescaledb--influxdb)
   - [5.4 Python Worker Services](#54-python-worker-services)
   - [5.5 Grafana](#55-grafana)
   - [5.6 Collect Agent](#56-collect-agent)
   - [5.7 Compute Node Agent](#57-compute-node-agent)
   - [5.8 hpc-admin Web Application](#58-hpc-admin-web-application)
6. [etcd Configuration Reference](#6-etcd-configuration-reference)
7. [System Validation](#7-system-validation)
8. [Starting and Stopping Data Collection](#8-starting-and-stopping-data-collection)
9. [Troubleshooting](#9-troubleshooting)
10. [Quick Start (Single-Machine Local Deployment)](#10-quick-start-single-machine-local-deployment)

---

## 1. System Architecture

This system collects, processes, stores, and visualises real-time metrics (CPU, memory, disk, network, GPU) from HPC compute nodes.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  COORDINATOR HOST                                                             │
│  etcd (:2379) — central config, service discovery, heartbeat store           │
└───────────────────────────────────────┬──────────────────────────────────────┘
                                        │  config / heartbeat
              ┌─────────────────────────┼────────────────────────┐
              ▼                         │                         ▼
┌─────────────────────────┐            │         ┌─────────────────────────┐
│  COMPUTE NODE (×N)      │            │         │  COMPUTE NODE (×N)      │
│  compute-node-agent     │            │         │  compute-node-agent     │
│  (eBPF + nvidia-smi)    │            │         │  (eBPF + nvidia-smi)    │
└──────────┬──────────────┘            │         └──────────┬──────────────┘
           │ gRPC stream               │                    │ gRPC stream
           └──────────────────┐        │         ┌──────────┘
                              ▼        │         ▼
                   ┌──────────────────────────────────┐
                   │  COLLECT AGENT HOST              │
                   │  collect-agent (:50051)          │
                   │  → SchemaValidator               │
                   │  → MetricsFilter                 │
                   │  → MetricsEnricher               │
                   │  → ThresholdChecker              │
                   │  → UserProcessor                 │
                   │  → KafkaPublisher                │
                   │                                  │
                   │  Kafka broker (:9092)             │
                   │  Topic: monitoring_metrics        │
                   └────────────────┬─────────────────┘
                                    │ consume
                   ┌────────────────▼─────────────────┐
                   │  DATABASE / WORKER HOST           │
                   │  InfluxDB (:8086)  ← raw metrics  │
                   │  TimescaleDB (:5432) ← aggregated │
                   │  Worker containers:               │
                   │    metrics-consumer               │
                   │    hourly-aggregator              │
                   └────────────────┬─────────────────┘
                                    │
              ┌─────────────────────┼────────────────────┐
              ▼                                           ▼
┌─────────────────────────┐              ┌─────────────────────────────────┐
│  GRAFANA HOST (:3000)   │              │  hpc-admin (Next.js) (:3000)    │
│  Dashboards + panels    │              │  Admin web UI                   │
└─────────────────────────┘              └─────────────────────────────────┘
```

### Component Summary

| Component | Folder | Host Role | Tech |
|---|---|---|---|
| Coordinator | `monitor-data-pipeline/coordinator/` | etcd host | Docker (etcd v3.5) |
| Kafka | `monitor-data-pipeline/kafka/` | Kafka host | Docker (Confluent Kafka 7.6, KRaft) |
| TimescaleDB | `monitor-data-pipeline/data-service/timescale/` | DB host | Docker (TimescaleDB PG14) |
| InfluxDB | `monitor-data-pipeline/data-service/influx/` | DB host | Docker (InfluxDB 2.7) |
| Worker services | `monitor-data-pipeline/data-service/worker/` | DB/worker host | Docker (Python 3.9) |
| Grafana | `monitor-data-pipeline/grafana/` | Grafana host | Docker (Grafana latest) |
| Collect Agent | `monitor-data-pipeline/collect-agent/` | Collect host | Python 3.8+ (bare metal) |
| Compute Node Agent | `monitor-data-pipeline/compute-node-agent/` | Each compute node | Python 3.8+ (bare metal, root) |
| hpc-admin | `Application/hpc-admin/` | Admin host | Node.js 18+ / Next.js 16 |

---

## 2. Prerequisites

### All machines

| Requirement | Version | Notes |
|---|---|---|
| OS | Linux (Ubuntu 22.04+ recommended) | macOS for hpc-admin dev only |
| Docker | 24.x+ | [Install Docker](https://docs.docker.com/engine/install/) |
| Docker Compose | v2.x+ (`docker compose` plugin) | Bundled with Docker Desktop |
| `git` | Any recent | For cloning the repo |

### Compute Node Agent machines (additional)

| Requirement | Notes |
|---|---|
| Linux kernel 4.4+ with eBPF support | Required for eBPF collectors |
| BCC (BPF Compiler Collection) | Must be installed as a **system package** (not via pip) |
| Kernel headers matching running kernel | `linux-headers-$(uname -r)` |
| Python 3.8+ | For running the agent |
| Root / sudo access | eBPF requires root |
| NVIDIA drivers + `nvidia-smi` | Only needed if nodes have NVIDIA GPUs; GPU metrics are skipped if absent |

Install BCC on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
```

Install BCC on CentOS/RHEL:

```bash
sudo yum install -y python3-bcc bcc-tools kernel-devel
```

### Collect Agent machine (additional)

| Requirement | Notes |
|---|---|
| Python 3.8+ | — |
| Network access to etcd (:2379) and Kafka (:9092) | — |

### hpc-admin machine (additional)

| Requirement | Version |
|---|---|
| Node.js | 18.x or 20.x LTS |
| npm | 9.x+ (bundled with Node.js) |

---

## 3. Network & Port Requirements

All hosts must be able to reach each other on the following ports. Configure firewalls and security groups accordingly.

| Service | Default Port | Direction | Description |
|---|---|---|---|
| etcd client API | `2379` | All agents → etcd host | Config reads/writes, heartbeat |
| etcd peer | `2380` | etcd internal | Only needed for etcd clustering |
| Kafka broker | `9092` | Collect Agent → Kafka host, Worker → Kafka host | Publish and consume metrics |
| TimescaleDB (PostgreSQL) | `5432` | Worker, hpc-admin → DB host | Database access |
| InfluxDB | `8086` | Worker → DB host | Raw metric writes and reads |
| Collect Agent gRPC | `50051` | Compute nodes → Collect Agent host | Streaming metrics |
| Grafana | `3000` | Browser → Grafana host | Dashboard UI and iframe embeds |
| hpc-admin | `3000` | Browser → Admin host | Admin web UI (use a different port if Grafana is on the same host) |

---

## 4. Deployment Order

Services must be started in this order because each layer depends on the previous one:

```
1. Coordinator (etcd)
      ↓
2. Kafka
      ↓
3. TimescaleDB  ←┐
4. InfluxDB     ←┘  (can start in parallel)
      ↓
5. Worker services (needs Kafka + both DBs)
      ↓
6. Grafana  (can start any time after InfluxDB is ready)
      ↓
7. Collect Agent (needs etcd + Kafka)
      ↓
8. Compute Node Agent (needs etcd + Collect Agent)
      ↓
9. hpc-admin (needs etcd + TimescaleDB)
```

---

## 5. Step-by-Step Deployment

### 5.1 Coordinator (etcd)

**Folder:** `monitor-data-pipeline/coordinator/`

etcd stores all runtime configuration for agents and receives heartbeats from compute nodes. It must be running before any agent starts.

#### 5.1.1 Start etcd

```bash
cd monitor-data-pipeline/coordinator
docker compose up -d
```

#### 5.1.2 Verify etcd is healthy

```bash
docker exec etcd-server etcdctl endpoint health
# Expected output:
# 127.0.0.1:2379 is healthy: successfully committed proposal: took = ...
```

#### 5.1.3 Seed initial configuration with setup-etcd.sh

The `setup-etcd.sh` script writes all required etcd keys for one or more nodes and the collect agent. Run it **from the coordinator machine** after etcd is up.

```bash
cd monitor-data-pipeline/coordinator

# Seed config for one node and the collect agent in one call:
./setup-etcd.sh \
  --node      node_id_1 \
  --grpc      <COLLECT_AGENT_HOST_IP>:50051 \
  --collect-agent collect_agent_1 \
  --kafka     <KAFKA_HOST_IP>:9092 \
  --topic     monitoring_metrics
```

Replace `<COLLECT_AGENT_HOST_IP>` and `<KAFKA_HOST_IP>` with the actual IP addresses.

To add more compute nodes, run the script again for each node ID:

```bash
./setup-etcd.sh --node node_id_2 --grpc <COLLECT_AGENT_HOST_IP>:50051
```

#### 5.1.4 Verify etcd keys were written

```bash
docker exec etcd-server etcdctl get --prefix /config
```

#### Troubleshooting — etcd

| Symptom | Cause | Fix |
|---|---|---|
| `docker exec etcd-server etcdctl endpoint health` fails | Container not started | `docker compose logs etcd` to see errors |
| Agents report "Cannot connect to etcd" | Wrong IP in `infra.json` or firewall | Confirm port 2379 is reachable: `curl http://<ETCD_IP>:2379/health` |

---

### 5.2 Kafka

**Folder:** `monitor-data-pipeline/kafka/`

Kafka is the message bus between the Collect Agent (producer) and the Worker services (consumer). It runs in KRaft mode (no Zookeeper).

#### 5.2.1 Update advertised listener IP

Open `kafka/docker-compose.yaml` and replace the IP in `KAFKA_ADVERTISED_LISTENERS` with the actual IP of the Kafka host:

```yaml
KAFKA_ADVERTISED_LISTENERS: 'PLAINTEXT://hpc_kafka:29092,EXTERNAL://<KAFKA_HOST_IP>:9092'
```

This is the address that producers and consumers outside Docker will use to connect.

#### 5.2.2 Start Kafka

```bash
cd monitor-data-pipeline/kafka
docker compose up -d
```

#### 5.2.3 Wait for Kafka to be ready (~15–30 seconds), then create the topic

```bash
docker exec hpc_kafka /opt/kafka/bin/kafka-topics.sh \
  --create \
  --topic monitoring_metrics \
  --bootstrap-server localhost:9092 \
  --partitions 3 \
  --replication-factor 1
```

#### 5.2.4 Verify the topic exists

```bash
docker exec hpc_kafka /opt/kafka/bin/kafka-topics.sh \
  --list \
  --bootstrap-server localhost:9092
# Should print: monitoring_metrics
```

#### 5.2.5 Kafka UI (optional)

The Kafka UI is not included in the current `docker-compose.yaml`. If you need a web UI, you can add it or manage topics via the CLI commands above.

#### Troubleshooting — Kafka

| Symptom | Cause | Fix |
|---|---|---|
| Collect Agent or Worker shows "Connection refused" to Kafka | `KAFKA_ADVERTISED_LISTENERS` uses wrong IP | Update `docker-compose.yaml`, recreate the container: `docker compose down && docker compose up -d` |
| Topic creation fails with "broker not available" | Kafka not fully initialised | Wait 20–30 s and retry |
| Collect Agent connects but messages don't reach Worker | Topic name mismatch | Both sides must use `monitoring_metrics`; verify with `docker exec hpc_kafka /opt/kafka/bin/kafka-topics.sh --list --bootstrap-server localhost:9092` |

---

### 5.3 Databases (TimescaleDB + InfluxDB)

Both database services live under `monitor-data-pipeline/data-service/`. They can be started on the same host.

#### 5.3.1 TimescaleDB

**Folder:** `monitor-data-pipeline/data-service/timescale/`

**Configure credentials:**

```bash
cd monitor-data-pipeline/data-service/timescale
cp .env.example .env
# Edit .env — set a real password for POSTGRES_PASSWORD
```

`.env` fields:

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_DB` | `hpc_monitoring` | Database name |
| `POSTGRES_USER` | `admin` | PostgreSQL superuser name |
| `POSTGRES_PASSWORD` | *(must set)* | PostgreSQL password |

**Start TimescaleDB:**

```bash
docker compose up -d
```

The `initdb.sql` file is mounted into the container's init directory and is executed automatically on the **first** start. It creates the `node_status_hourly` and `user_app_hourly` hypertables.

**Verify TimescaleDB and schema:**

```bash
docker exec -it hpc_timescaledb psql -U admin -d hpc_monitoring -c "\dt"
# Should list: node_status_hourly, user_app_hourly
```

**Apply the hpc-admin schema** (run once to create admin tables used by the web app):

```bash
docker exec -i hpc_timescaledb psql -U admin -d hpc_monitoring \
  < ../../Application/hpc-admin/db/schema.sql
```

Or, if running from the repo root:

```bash
docker exec -i hpc_timescaledb psql -U admin -d hpc_monitoring \
  < Application/hpc-admin/db/schema.sql
```

**Verify admin tables:**

```bash
docker exec -it hpc_timescaledb psql -U admin -d hpc_monitoring -c "\dt"
# Should now include: nodes, hpc_users, collection_settings, pipeline_rules,
#   alert_rules, notifications, config_versions, audit_logs, custom_dashboards
```

#### 5.3.2 InfluxDB

**Folder:** `monitor-data-pipeline/data-service/influx/`

**Configure credentials:**

```bash
cd monitor-data-pipeline/data-service/influx
cp .env.example .env
# Edit .env — fill in all values
```

`.env` fields:

| Variable | Description |
|---|---|
| `INFLUXDB_USERNAME` | Admin username (e.g. `admin`) |
| `INFLUXDB_PASSWORD` | Admin password |
| `INFLUXDB_ORG` | Organisation name (e.g. `hpcc-org`) — must match Worker `.env` |
| `INFLUXDB_BUCKET` | Bucket name (e.g. `metrics`) — must match Worker `.env` |
| `INFLUXDB_ADMIN_TOKEN` | Long random string; generate with `openssl rand -hex 32` |

**Start InfluxDB:**

```bash
docker compose up -d
```

**Verify InfluxDB:**

```bash
curl -s http://localhost:8086/health
# Expected: {"name":"influxdb","message":"ready for queries and writes","status":"pass",...}
```

#### Troubleshooting — Databases

| Symptom | Cause | Fix |
|---|---|---|
| `initdb.sql` not applied | TimescaleDB was started before (data volume exists) | `docker compose down -v` to wipe the volume, then `docker compose up -d` |
| TimescaleDB port conflict | Port 5432 already in use on the host | Change host port in `docker-compose.yml` (e.g. `"15432:5432"`) and update connection strings |
| InfluxDB init fails | `.env` not created | Ensure `.env` exists and all 5 variables are set |

---

### 5.4 Python Worker Services

**Folder:** `monitor-data-pipeline/data-service/worker/`

Three services run as Docker containers. They consume Kafka messages, write raw metrics to InfluxDB, and run hourly ETL aggregations into TimescaleDB.

> **Note:** `requirements.txt` is currently missing from this folder. Create it before building the images.

**Create `requirements.txt`:**

```bash
cd monitor-data-pipeline/data-service/worker
cat > requirements.txt << 'EOF'
kafka-python>=2.0.2
influxdb-client>=1.36.0
psycopg2-binary>=2.9.6
schedule>=1.2.0
EOF
```

**Configure environment:**

```bash
cp .env.example .env
# Edit .env — fill in all addresses and credentials
```

`.env` fields:

| Variable | Description | Example |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | Kafka broker address | `192.168.1.100:9092` |
| `KAFKA_TOPIC` | Topic to consume from | `monitoring_metrics` |
| `KAFKA_CONSUMER_GROUP` | Consumer group name | `hpc_worker_group` |
| `INFLUX_URL` | InfluxDB HTTP URL | `http://192.168.1.101:8086` |
| `INFLUX_TOKEN` | InfluxDB admin token (from `influx/.env`) | — |
| `INFLUX_ORG` | Organisation name (must match `influx/.env`) | `hpcc-org` |
| `INFLUX_BUCKET` | Bucket name (must match `influx/.env`) | `metrics` |
| `PG_HOST` | TimescaleDB host IP | `192.168.1.101` |
| `PG_PORT` | TimescaleDB port | `5432` |
| `PG_DB` | Database name | `hpc_monitoring` |
| `PG_USER` | Database user | `admin` |
| `PG_PASS` | Database password (from `timescale/.env`) | — |

**Build and start:**

```bash
cd monitor-data-pipeline/data-service/worker
docker compose up -d --build
```

This starts three containers:

| Container | Script | Description |
|---|---|---|
| `hpc_metrics_consumer` | `monitor_consumer.py` | Consumes Kafka messages, writes to InfluxDB |
| `hpc_hourly_aggregator` | `hourly_aggregator.py` | Runs every hour: aggregates InfluxDB → TimescaleDB |
| `hpc_metadata_sync` | `sync_metadata.py` | One-shot metadata sync (`restart: "no"`) |

> **Note:** `sync_metadata.py` is referenced in `docker-compose.yml` but is not present in the repository. The `hpc_metadata_sync` container will fail. This does not affect `hpc_metrics_consumer` or `hpc_hourly_aggregator`. TODO: confirm whether `sync_metadata.py` should be added to the repository.

**Verify worker containers are running:**

```bash
docker ps --filter name=hpc_metrics_consumer
docker ps --filter name=hpc_hourly_aggregator

docker logs hpc_metrics_consumer
docker logs hpc_hourly_aggregator
```

#### Troubleshooting — Worker Services

| Symptom | Cause | Fix |
|---|---|---|
| Build fails: `COPY requirements.txt` not found | `requirements.txt` missing | Create it as shown above |
| `INFLUX_TOKEN` missing error at startup | `.env` not created or token is empty | Ensure `.env` exists with a valid `INFLUX_TOKEN` |
| `PG_PASS` missing error at startup | Password not set in `.env` | Set `PG_PASS` in `.env` |
| Consumer connects but writes nothing to InfluxDB | Wrong `INFLUX_ORG` / `INFLUX_BUCKET` | Values must match exactly what was used during InfluxDB init |

---

### 5.5 Grafana

**Folder:** `monitor-data-pipeline/grafana/`

Grafana visualises the metrics stored in InfluxDB. Its panels are embedded as iframes in the hpc-admin web application.

**Configure admin credentials:**

```bash
cd monitor-data-pipeline/grafana
cp .env.example .env
# Edit .env — set a real GF_SECURITY_ADMIN_PASSWORD
```

`.env` fields:

| Variable | Default | Description |
|---|---|---|
| `GF_SECURITY_ADMIN_USER` | `admin` | Grafana admin username |
| `GF_SECURITY_ADMIN_PASSWORD` | *(must set)* | Grafana admin password |

**Start Grafana:**

```bash
docker compose up -d
```

**Verify Grafana:**

```bash
curl -s http://localhost:3000/api/health | python3 -m json.tool
# "database": "ok"
```

Open `http://<GRAFANA_HOST_IP>:3000` in a browser and log in with the credentials from `.env`.

**Connect InfluxDB as a data source:**

1. Go to **Configuration → Data Sources → Add data source → InfluxDB**
2. Set **Query Language** to `Flux`
3. Set **URL** to `http://<DB_HOST_IP>:8086`
4. Under **InfluxDB Details**, enter `Organisation`, `Token`, and `Default Bucket` (from `influx/.env`)
5. Click **Save & Test**

**Import the sample dashboard** (optional):

```bash
# The sample dashboard JSON is at:
# monitor-data-pipeline/grafana/Sample Dashboard.json
# Import via Grafana UI: Dashboards → Import → Upload JSON file
```

#### Troubleshooting — Grafana

| Symptom | Cause | Fix |
|---|---|---|
| Dashboard shows "No data" | Data source not configured, or wrong bucket/org | Re-check InfluxDB data source settings; verify data is actually arriving via `docker logs hpc_metrics_consumer` |
| Panels not loading in hpc-admin iframes | Grafana anonymous auth disabled | Ensure `GF_AUTH_ANONYMOUS_ENABLED=true` and `GF_SECURITY_ALLOW_EMBEDDING=true` in `docker-compose.yaml` (already set by default) |
| Login fails | Wrong password | Check `GF_SECURITY_ADMIN_PASSWORD` in `.env`; restart container after editing |

---

### 5.6 Collect Agent

**Folder:** `monitor-data-pipeline/collect-agent/`

The Collect Agent runs as a bare-metal Python service. It accepts gRPC metric streams from Compute Node Agents, processes them through a pipeline, and publishes results to Kafka.

#### 5.6.1 Clone the repository on the Collect Agent host

```bash
git clone <REPO_URL>
cd monitor-data-pipeline/collect-agent
```

#### 5.6.2 Configure `infra.json`

Open `infra.json` and set the correct values:

```json
{
    "collect_agent_id": "collect_agent_1",
    "etcd_endpoint": "http://<ETCD_HOST_IP>:2379"
}
```

| Field | Description |
|---|---|
| `collect_agent_id` | Must match the ID used in `setup-etcd.sh` (e.g. `collect_agent_1`) |
| `etcd_endpoint` | Full URL to etcd, including scheme and port |

#### 5.6.3 Create virtual environment and install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 5.6.4 Generate protobuf files

```bash
python -m grpc_tools.protoc \
  -I. \
  --python_out=. \
  --grpc_python_out=. \
  proto/metrics.proto
```

#### 5.6.5 Start the Collect Agent

```bash
python main.py
```

**Expected startup output:**

```
INFO:config:Loading configuration from infra.json
INFO:config:Connecting to etcd at <ETCD_IP>:2379
INFO:config:Connected to etcd successfully
INFO:server:gRPC server listening on port 50051
```

To run as a background process:

```bash
nohup python main.py > collect-agent.log 2>&1 &
```

#### 5.6.6 Verify the Collect Agent

```bash
# Check the gRPC port is listening
ss -tlnp | grep 50051

# Tail the log
tail -f collect-agent.log
```

#### Troubleshooting — Collect Agent

| Symptom | Cause | Fix |
|---|---|---|
| `ConnectionError: Max retries reached` at startup | etcd unreachable | Check `etcd_endpoint` in `infra.json`; verify with `curl http://<ETCD_IP>:2379/health` |
| Proto import errors | Protobuf files not generated | Re-run the `grpc_tools.protoc` command |
| Kafka publish failures | Wrong broker address or topic in etcd | Run `docker exec etcd-server etcdctl get --prefix /config/collect_agent/collect_agent_1` to verify values |
| `ModuleNotFoundError` | venv not activated or requirements not installed | `source venv/bin/activate && pip install -r requirements.txt` |

---

### 5.7 Compute Node Agent

**Folder:** `monitor-data-pipeline/compute-node-agent/`

Deploy on **each** compute node you want to monitor. Each instance must have a unique `node_id`.

#### 5.7.1 Clone the repository on the compute node

```bash
git clone <REPO_URL>
cd monitor-data-pipeline/compute-node-agent
```

#### 5.7.2 Configure `infra.json`

Open `infra.json` and set the node identity and etcd address:

```json
{
    "node_id": "node_id_1",
    "etcd_endpoint": "http://<ETCD_HOST_IP>:2379"
}
```

| Field | Description |
|---|---|
| `node_id` | Unique identifier for this node (e.g. `node_id_1`, `node_id_2`). Must match the ID registered in etcd via `setup-etcd.sh`. |
| `etcd_endpoint` | Full URL to etcd, including scheme and port |

> **Important:** Every compute node must have a **different** `node_id`. If two agents share the same ID, their heartbeats and configuration will collide.

#### 5.7.3 Run the setup script

`setup.sh` checks for BCC, creates a virtual environment with system site-packages (so BCC is accessible), installs Python dependencies, and generates protobuf files.

```bash
chmod +x setup.sh
./setup.sh
```

If BCC is not installed, `setup.sh` will print installation instructions and exit. Install BCC first (see [Prerequisites](#2-prerequisites)), then re-run `setup.sh`.

#### 5.7.4 Register this node in etcd

This step must be run **from the Coordinator machine** (where Docker and `etcd-server` are running):

```bash
cd monitor-data-pipeline/coordinator
./setup-etcd.sh \
  --node      node_id_1 \
  --grpc      <COLLECT_AGENT_HOST_IP>:50051 \
  --window    5.0 \
  --heartbeat 10.0
```

#### 5.7.5 Start the Compute Node Agent

Use the provided `run.sh` script, which automatically elevates to root for eBPF:

```bash
./run.sh
```

Or run manually with sudo:

```bash
sudo .venv/bin/python main.py
```

**Expected startup output:**

```
INFO:config:Loading configuration from infra.json
INFO:config:Connected to etcd successfully
INFO:config:Configuration loaded for node: node_id_1
INFO:config:Initial status: collection DISABLED
INFO:main:Compute node agent started
```

Collection begins only after you send `running` status via etcd (see [Section 8](#8-starting-and-stopping-data-collection)).

#### 5.7.6 Verify the agent is sending heartbeats

From the Coordinator machine:

```bash
docker exec etcd-server etcdctl get /nodes/node_id_1/heartbeat
# Expected output (JSON):
# {"timestamp": 1746000000, "status": "alive", "collection_active": false}
```

#### Troubleshooting — Compute Node Agent

| Symptom | Cause | Fix |
|---|---|---|
| `setup.sh` exits: "BCC is not installed" | BCC not available as a system package | Install `python3-bpfcc bpfcc-tools linux-headers-$(uname -r)` then rerun `setup.sh` |
| `Permission denied` on `run.sh` | Script not executable | `chmod +x run.sh setup.sh` |
| `Permission denied: cannot attach BPF` | Not running as root | Run `sudo ./run.sh` |
| `ConnectionError` connecting to etcd | Wrong IP or firewall | Verify `etcd_endpoint` in `infra.json`; test with `curl http://<ETCD_IP>:2379/health` |
| GPU metrics are all zero / missing | No NVIDIA GPU or drivers not installed | Install NVIDIA drivers and confirm `nvidia-smi` works. CPU/memory metrics still work without GPU. |
| No heartbeat in etcd after startup | Wrong `node_id` or etcd keys not seeded | Make sure `setup-etcd.sh` was run with the same `node_id` that is in `infra.json` |

---

### 5.8 hpc-admin Web Application

**Folder:** `Application/hpc-admin/`

A Next.js 16 admin dashboard that reads from TimescaleDB and etcd, and embeds Grafana panels.

#### 5.8.1 Install Node.js dependencies

```bash
cd Application/hpc-admin
npm install
```

#### 5.8.2 Configure `.env.local`

The file already exists. Edit it to point to your actual service addresses:

```bash
# Application/hpc-admin/.env.local
NEXTAUTH_SECRET=<random-string-at-least-32-chars>

ADMIN_EMAIL=admin@hpc.local
ADMIN_PASSWORD=<your-admin-password>

TIMESCALE_URL=postgresql://admin:<PG_PASS>@<DB_HOST_IP>:5432/hpc_monitoring

GRAFANA_BASE_URL=http://<GRAFANA_HOST_IP>:3000/d/adtfbh4/h6-monitoring

ETCD_URL=http://<ETCD_HOST_IP>:2379
```

| Variable | Description |
|---|---|
| `NEXTAUTH_SECRET` | Random secret for session signing; generate with `openssl rand -base64 32` |
| `ADMIN_EMAIL` | Login email for the web UI |
| `ADMIN_PASSWORD` | Login password for the web UI |
| `TIMESCALE_URL` | Full PostgreSQL connection string |
| `GRAFANA_BASE_URL` | Base URL for Grafana panel embeds (no trailing slash) |
| `ETCD_URL` | etcd HTTP client URL |

#### 5.8.3 Run in development mode

```bash
npm run dev
# Server starts at http://localhost:3000
```

#### 5.8.4 Run in production mode

```bash
npm run build
npm run start
```

#### 5.8.5 Verify the web app

Open `http://localhost:3000` and log in with `ADMIN_EMAIL` / `ADMIN_PASSWORD` from `.env.local`.

#### Troubleshooting — hpc-admin

| Symptom | Cause | Fix |
|---|---|---|
| Build fails with TypeScript errors | Type mismatch in code | Run `npm run lint` to identify issues |
| Login page redirects back to itself | `NEXTAUTH_SECRET` missing or empty | Set a non-empty `NEXTAUTH_SECRET` in `.env.local` |
| API routes return 500 (DB errors) | Wrong `TIMESCALE_URL` or DB not running | Check connection string; test with `psql "$TIMESCALE_URL" -c "\l"` |
| Grafana iframes show blank | Grafana anonymous auth off or wrong URL | Confirm `GF_AUTH_ANONYMOUS_ENABLED=true` in Grafana's `docker-compose.yaml`; verify `GRAFANA_BASE_URL` |

---

## 6. etcd Configuration Reference

All runtime configuration is stored in etcd and read by agents at startup. Changes take effect **without restarting** the agents (they watch for changes via etcd watch).

### Compute Node keys

```
/config/compute_node/{node_id}/target_collect_agent   → "192.168.1.x:50051"
/config/compute_node/{node_id}/window                 → "5.0"        (seconds)
/config/compute_node/{node_id}/heartbeat_interval     → "10.0"       (seconds)
/config/compute_node/{node_id}/status                 → "running" | "stopped"

/nodes/{node_id}/heartbeat   → JSON written by agent: {"timestamp":…,"status":"alive","collection_active":…}
```

### Collect Agent keys

```
/config/collect_agent/{agent_id}/kafka_brokers        → JSON array: ["192.168.1.x:9092"]
/config/collect_agent/{agent_id}/kafka_topic          → "monitoring_metrics"
/config/collect_agent/{agent_id}/grpc_port            → "50051"
/config/collect_agent/{agent_id}/threshold_rules      → JSON object (see below)
/config/collect_agent/{agent_id}/user_processors      → JSON array
```

### Threshold rules format

```json
{
  "cpu_usage_percent":           { "max": 90 },
  "memory_usage_percent":        { "max": 85 },
  "gpu_max_temperature_celsius": { "max": 85 },
  "gpu_max_power_watts":         { "max": 300 },
  "gpu_max_utilization_percent": { "max": 95 }
}
```

Update threshold rules at runtime (no restart needed):

```bash
docker exec etcd-server etcdctl put /config/collect_agent/collect_agent_1/threshold_rules \
  '{"cpu_usage_percent":{"max":90},"memory_usage_percent":{"max":85}}'
```

---

## 7. System Validation

Run these checks in order after completing all deployment steps.

### 7.1 Docker containers are running

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
# Expected containers:
# etcd-server        Up ...
# hpc_kafka          Up ...
# hpc_timescaledb    Up ...
# hpc_influxdb       Up ...
# hpc_metrics_consumer   Up ...
# hpc_hourly_aggregator  Up ...
# hpc_grafana        Up ...
```

### 7.2 etcd is healthy and keys are present

```bash
docker exec etcd-server etcdctl endpoint health
docker exec etcd-server etcdctl get --prefix /config
```

### 7.3 Kafka topic exists

```bash
docker exec hpc_kafka /opt/kafka/bin/kafka-topics.sh \
  --list \
  --bootstrap-server localhost:9092
# Should include: monitoring_metrics
```

### 7.4 TimescaleDB is initialised

```bash
docker exec hpc_timescaledb psql -U admin -d hpc_monitoring -c "\dt"
# Should list all tables including node_status_hourly, user_app_hourly, nodes, etc.
```

### 7.5 InfluxDB is healthy

```bash
curl -s http://<DB_HOST_IP>:8086/health
```

### 7.6 Compute Node heartbeats are arriving

```bash
docker exec etcd-server etcdctl get /nodes/node_id_1/heartbeat
# Should show a JSON blob with a recent timestamp
```

### 7.7 Metrics are flowing through Kafka

```bash
# Watch messages on the topic for a few seconds:
docker exec hpc_kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic monitoring_metrics \
  --max-messages 5
# Should print JSON metric payloads once collection is started
```

### 7.8 Data is visible in Grafana

Open `http://<GRAFANA_HOST_IP>:3000`, navigate to the imported dashboard, and confirm metrics panels are populated.

---

## 8. Starting and Stopping Data Collection

Collection is gated by an etcd status key. The Compute Node Agent checks this key at startup and watches for changes in real time.

**Start collection for a node:**

```bash
docker exec etcd-server etcdctl put /config/compute_node/node_id_1/status running
```

**Stop collection for a node:**

```bash
docker exec etcd-server etcdctl put /config/compute_node/node_id_1/status stopped
```

**Confirm the agent reacted:**

```bash
docker exec etcd-server etcdctl get /nodes/node_id_1/heartbeat
# "collection_active" should flip to true / false
```

---

## 9. Troubleshooting

### Kafka: Connection refused / no route to host

```bash
# 1. Confirm the container is running
docker ps --filter name=hpc_kafka

# 2. Check Kafka logs
docker logs hpc_kafka | tail -30

# 3. Verify the advertised IP in docker-compose.yaml matches the host
grep KAFKA_ADVERTISED_LISTENERS monitor-data-pipeline/kafka/docker-compose.yaml

# 4. Test reachability from another machine
nc -zv <KAFKA_HOST_IP> 9092
```

### etcd: endpoint cannot be reached

```bash
# 1. Health check via HTTP (no etcdctl needed)
curl http://<ETCD_HOST_IP>:2379/health

# 2. Confirm the container is up
docker ps --filter name=etcd-server

# 3. Check the infra.json on the agent machine
cat monitor-data-pipeline/collect-agent/infra.json
cat monitor-data-pipeline/compute-node-agent/infra.json
```

### TimescaleDB: initialisation error

```bash
# View init logs
docker logs hpc_timescaledb 2>&1 | head -50

# If the schema was not applied (e.g. volume pre-existed):
docker compose down -v           # removes data volume — DESTRUCTIVE
docker compose up -d

# Or apply the schema manually
docker exec -i hpc_timescaledb psql -U admin -d hpc_monitoring \
  < monitor-data-pipeline/data-service/timescale/initdb.sql
```

### Python: dependency installation error

```bash
# Ensure you are in the correct virtual environment
which python  # should point inside venv/ or .venv/

# Collect Agent
cd monitor-data-pipeline/collect-agent
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Compute Node Agent — BCC must come from system packages, not pip
python3 -c "from bcc import BPF" 2>&1   # test BCC availability
source .venv/bin/activate
pip install --upgrade pip
pip install --ignore-installed grpcio grpcio-tools protobuf etcd3-py pynvml typing-extensions
```

### Permission denied running setup.sh or run.sh

```bash
chmod +x monitor-data-pipeline/compute-node-agent/setup.sh
chmod +x monitor-data-pipeline/compute-node-agent/run.sh
# eBPF requires root; run.sh will sudo automatically if needed
./run.sh
```

### Grafana dashboard does not show data

1. Open Grafana → **Configuration → Data Sources** and click **Save & Test** on the InfluxDB source.
2. Confirm `hpc_metrics_consumer` is running and consuming: `docker logs hpc_metrics_consumer | tail -20`.
3. Check that the Flux queries reference the correct `bucket` and `org` values.
4. Confirm collection is active: `docker exec etcd-server etcdctl get /nodes/node_id_1/heartbeat`.
5. Wait at least 60 seconds after starting collection — InfluxDB needs a few write cycles before data appears.

### hpc-admin: etcd API routes return errors

```bash
# Test etcd reachability from the admin host
curl http://<ETCD_HOST_IP>:2379/health

# Verify ETCD_URL in .env.local
grep ETCD_URL Application/hpc-admin/.env.local
```

---

## 10. Quick Start (Single-Machine Local Deployment)

All components can run on one machine for development or testing. The key constraint is that Grafana and hpc-admin both default to port 3000 — run hpc-admin on port 3001 to avoid the conflict.

```bash
# 1. Clone
git clone <REPO_URL>
cd <REPO_DIR>

# 2. Start infrastructure services
cd monitor-data-pipeline/coordinator && docker compose up -d && cd ../..
cd monitor-data-pipeline/kafka && docker compose up -d && cd ../..

# 3. Databases
cd monitor-data-pipeline/data-service/timescale
cp .env.example .env && docker compose up -d && cd ../../..

cd monitor-data-pipeline/data-service/influx
cp .env.example .env
# Edit .env to set INFLUXDB_ADMIN_TOKEN before starting
docker compose up -d && cd ../../..

# 4. Worker services
cd monitor-data-pipeline/data-service/worker
cp .env.example .env
# Edit .env: point KAFKA_BOOTSTRAP_SERVERS, INFLUX_URL, PG_HOST all to 127.0.0.1
# Create requirements.txt (see Section 5.4)
docker compose up -d --build && cd ../../..

# 5. Grafana
cd monitor-data-pipeline/grafana
cp .env.example .env && docker compose up -d && cd ../..

# 6. Seed etcd with local addresses
cd monitor-data-pipeline/coordinator
./setup-etcd.sh \
  --node node_id_1 --grpc 127.0.0.1:50051 \
  --collect-agent collect_agent_1 --kafka 127.0.0.1:9092 --topic monitoring_metrics
cd ../..

# 7. Create Kafka topic
docker exec hpc_kafka /opt/kafka/bin/kafka-topics.sh \
  --create --topic monitoring_metrics \
  --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1

# 8. Apply database schema
docker exec -i hpc_timescaledb psql -U admin -d hpc_monitoring \
  < Application/hpc-admin/db/schema.sql

# 9. Collect Agent
cd monitor-data-pipeline/collect-agent
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/metrics.proto
# Edit infra.json: set etcd_endpoint to http://127.0.0.1:2379
python main.py &
cd ../..

# 10. Compute Node Agent (requires BCC installed system-wide)
cd monitor-data-pipeline/compute-node-agent
# Edit infra.json: set etcd_endpoint to http://127.0.0.1:2379, node_id to node_id_1
./setup.sh
sudo ./run.sh &
cd ../..

# 11. Start collection
docker exec etcd-server etcdctl put /config/compute_node/node_id_1/status running

# 12. hpc-admin (on port 3001 to avoid conflict with Grafana)
cd Application/hpc-admin
# Edit .env.local: set all localhost addresses
npm install
PORT=3001 npm run dev
# Open http://localhost:3001
```

---

*Generated for the HPC Cluster Monitoring System. Keep this file updated when service ports, container names, or topology change.*
