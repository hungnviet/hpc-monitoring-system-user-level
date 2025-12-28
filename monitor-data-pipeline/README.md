# Monitor Data Pipeline

A distributed system for collecting, processing, and publishing real-time system metrics from compute nodes. The pipeline collects both per-process metrics (CPU, memory, disk, network, GPU) and node-level system metrics (overall CPU/memory usage, GPU temperature, power consumption).

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              COORDINATOR (Machine A)                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                         etcd Server (:2379)                              │   │
│  │  - Configuration storage for all agents                                 │   │
│  │  - Service discovery (gRPC endpoints)                                   │   │
│  │  - Node heartbeat monitoring                                            │   │
│  │  - Collection control (start/stop)                                      │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    │ Configuration & Heartbeat            │
                    ▼                                      ▼
┌─────────────────────────────────────┐  ┌─────────────────────────────────────┐
│     COMPUTE NODE (Machine B/C/D)    │  │     COMPUTE NODE (Machine E/F/G)    │
│  ┌───────────────────────────────┐  │  │  ┌───────────────────────────────┐  │
│  │      compute-node-agent       │  │  │  │      compute-node-agent       │  │
│  │                               │  │  │  │                               │  │
│  │  Collectors:                  │  │  │  │  Collectors:                  │  │
│  │  ├─ CPU (eBPF)               │  │  │  │  ├─ CPU (eBPF)               │  │
│  │  ├─ Memory (/proc)           │  │  │  │  ├─ Memory (/proc)           │  │
│  │  ├─ Disk (eBPF)              │  │  │  │  ├─ Disk (eBPF)              │  │
│  │  ├─ Network (eBPF)           │  │  │  │  ├─ Network (eBPF)           │  │
│  │  ├─ GPU Process (nvidia-smi) │  │  │  │  ├─ GPU Process (nvidia-smi) │  │
│  │  ├─ System CPU (/proc/stat)  │  │  │  │  ├─ System CPU (/proc/stat)  │  │
│  │  ├─ System Memory (/proc)    │  │  │  │  ├─ System Memory (/proc)    │  │
│  │  └─ GPU System (nvidia-smi)  │  │  │  │  └─ GPU System (nvidia-smi)  │  │
│  │                               │  │  │  │                               │  │
│  │  gRPC Client (streaming)     │  │  │  │  gRPC Client (streaming)     │  │
│  └───────────────────────────────┘  │  │  └───────────────────────────────┘  │
└─────────────────────────────────────┘  └─────────────────────────────────────┘
                    │                                      │
                    │        gRPC Stream (metrics)         │
                    └──────────────────┬───────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           COLLECT SERVER (Machine H)                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                         collect-agent (:50051)                          │   │
│  │                                                                          │   │
│  │  Ingestion:                                                             │   │
│  │  └─ gRPC Server (async, multi-client streaming)                        │   │
│  │                                                                          │   │
│  │  Processing Pipeline:                                                   │   │
│  │  ├─ Stage 1: SchemaValidator (validate fields, ranges)                 │   │
│  │  ├─ Stage 2: MetricsFilter (remove bootstrap processes)                │   │
│  │  ├─ Stage 3: MetricsEnricher (add timestamps, agent ID)               │   │
│  │  ├─ Stage 4: ThresholdChecker (CPU/GPU/Memory alerts)                 │   │
│  │  └─ Stage 5: UserProcessor (configurable via etcd)                    │   │
│  │                                                                          │   │
│  │  Publisher:                                                             │   │
│  │  └─ KafkaPublisher (async, gzip compression)                          │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                       │                                         │
│                                       ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                         Kafka Broker (:9092)                            │   │
│  │  Topic: metrics                                                         │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
                            [Downstream Consumers]
                            (Analytics, Dashboard, etc.)
```

## Components

### 1. Coordinator (etcd)

Central configuration and service discovery server.

**Location:** `coordinator/`

**Responsibilities:**

- Store configuration for all agents
- Provide gRPC endpoint addresses for compute nodes
- Store heartbeat data from compute nodes
- Control collection start/stop via status keys
- Store threshold rules and user processors config

### 2. Compute Node Agent

Lightweight agent deployed on each monitored compute node.

**Location:** `compute-node-agent/`

**Metrics Collected:**

| Category         | Metric                     | Source        | Description               |
| ---------------- | -------------------------- | ------------- | ------------------------- |
| **Per-Process**  | cpu_ontime_ns              | eBPF          | CPU time in nanoseconds   |
|                  | read_bytes, write_bytes    | eBPF          | Disk I/O bytes            |
|                  | net_rx_bytes, net_tx_bytes | eBPF          | Network I/O bytes         |
|                  | avg_rss_bytes              | /proc         | Average memory usage      |
|                  | gpu_used_memory_mib        | nvidia-smi    | GPU memory per process    |
| **System-Level** | cpu_usage_percent          | /proc/stat    | Overall CPU usage %       |
|                  | memory_usage_percent       | /proc/meminfo | Overall memory usage %    |
|                  | gpu_utilization_percent    | nvidia-smi    | Per-GPU utilization %     |
|                  | gpu_temperature_celsius    | nvidia-smi    | Per-GPU temperature       |
|                  | gpu_power_watts            | nvidia-smi    | Per-GPU power consumption |

### 3. Collect Agent

Central server that receives, processes, and publishes metrics.

**Location:** `collect-agent/`

**Pipeline Stages:**

1. **SchemaValidator** - Validates data format and ranges
2. **MetricsFilter** - Removes system/bootstrap processes
3. **MetricsEnricher** - Adds timestamps and agent metadata
4. **ThresholdChecker** - Checks CPU/GPU/memory thresholds, triggers alerts
5. **UserProcessor** - Custom processing (aggregation, sampling)

### 4. Kafka

Message broker for processed metrics.

**Location:** `kafka/`

---

## Deployment Guide

### Prerequisites

All machines need:

- Python 3.8+
- Docker & Docker Compose (for etcd and Kafka)
- Network connectivity between all components

Compute nodes additionally need:

- Linux kernel 4.4+ with eBPF support
- BCC (BPF Compiler Collection) installed
- Root/sudo access for eBPF collectors
- NVIDIA drivers + nvidia-smi (for GPU metrics)

### Machine Roles

| Role               | Components           | Typical Machine                  |
| ------------------ | -------------------- | -------------------------------- |
| **Coordinator**    | etcd                 | Central server or VM             |
| **Collect Server** | collect-agent, Kafka | Central server with good network |
| **Compute Node**   | compute-node-agent   | GPU nodes, worker nodes          |

---

## Step-by-Step Deployment

### Step 1: Deploy Coordinator (etcd)

**Machine: Coordinator Server**

```bash
# 1. Clone the repository
git clone <repo-url>
cd monitor-data-pipeline/coordinator

# 2. Start etcd
docker-compose up -d

# 3. Verify etcd is running
docker exec etcd-server etcdctl endpoint health

# 4. Access web UI (optional)
# Open http://<coordinator-ip>:8080 in browser
```

### Step 2: Deploy Kafka

**Machine: Collect Server (can be same as Coordinator)**

```bash
cd monitor-data-pipeline/kafka

# 1. Update docker-compose.yaml if needed
# Change KAFKA_CFG_ADVERTISED_LISTENERS to use actual IP:
#   PLAINTEXT://<collect-server-ip>:9092

# 2. Start Kafka
docker-compose up -d

# 3. Verify Kafka is running
docker logs kafka
```

### Step 3: Deploy Collect Agent

**Machine: Collect Server**

```bash
cd monitor-data-pipeline/collect-agent

# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate protobuf files
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/metrics.proto

# 4. Configure infra.json
cat > infra.json << EOF
{
    "collect_agent_id": "collect_agent_1",
    "etcd_endpoint": "http://<coordinator-ip>:2379"
}
EOF

# 5. Setup collect-agent configuration in etcd
# Run from coordinator machine or use etcdctl remotely:
docker exec etcd-server etcdctl put /config/collect_agent/collect_agent_1/kafka_brokers '["<collect-server-ip>:9092"]'
docker exec etcd-server etcdctl put /config/collect_agent/collect_agent_1/kafka_topic "metrics"
docker exec etcd-server etcdctl put /config/collect_agent/collect_agent_1/grpc_port "50051"

# 6. Setup threshold rules (optional)
docker exec etcd-server etcdctl put /config/collect_agent/collect_agent_1/threshold_rules '{
    "cpu_usage_percent": {"max": 90},
    "memory_usage_percent": {"max": 85},
    "gpu_max_temperature_celsius": {"max": 85},
    "gpu_max_power_watts": {"max": 300}
}'

# 7. Start collect-agent
python main.py
```

### Step 4: Deploy Compute Node Agent

**Machine: Each Compute Node**

```bash
cd monitor-data-pipeline/compute-node-agent

# 1. Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Generate protobuf files
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/metrics.proto

# 5. Configure infra.json (unique node_id per machine!)
cat > infra.json << EOF
{
    "node_id": "compute_node_1",
    "etcd_endpoint": "http://<coordinator-ip>:2379"
}
EOF

# 6. Setup node configuration in etcd (run from coordinator)
NODE_ID="compute_node_1"
COLLECT_AGENT="<collect-server-ip>:50051"

docker exec etcd-server etcdctl put "/config/compute_node/${NODE_ID}/target_collect_agent" "$COLLECT_AGENT"
docker exec etcd-server etcdctl put "/config/compute_node/${NODE_ID}/window" "5.0"
docker exec etcd-server etcdctl put "/config/compute_node/${NODE_ID}/heartbeat_interval" "10.0"
docker exec etcd-server etcdctl put "/config/compute_node/${NODE_ID}/status" "stopped"

# 7. Start compute-node-agent (requires root for eBPF)
sudo venv/bin/python main.py
```

### Step 5: Start Collection

**From Coordinator Machine:**

```bash
# Enable collection for a specific node
NODE_ID="compute_node_1"
docker exec etcd-server etcdctl put "/config/compute_node/${NODE_ID}/status" "running"

# Verify heartbeat
docker exec etcd-server etcdctl get "/nodes/${NODE_ID}/heartbeat"

# Watch metrics flow (check Kafka)
docker exec kafka kafka-console-consumer.sh \
    --bootstrap-server localhost:9092 \
    --topic metrics \
    --from-beginning
```

---

## Configuration Reference

### etcd Keys for Compute Node

| Key                                                   | Description                  | Example                |
| ----------------------------------------------------- | ---------------------------- | ---------------------- |
| `/config/compute_node/{node_id}/target_collect_agent` | gRPC server address          | `192.168.1.100:50051`  |
| `/config/compute_node/{node_id}/window`               | Collection window (seconds)  | `5.0`                  |
| `/config/compute_node/{node_id}/heartbeat_interval`   | Heartbeat interval (seconds) | `10.0`                 |
| `/config/compute_node/{node_id}/status`               | Collection status            | `running` or `stopped` |

### etcd Keys for Collect Agent

| Key                                                | Description              | Example                                          |
| -------------------------------------------------- | ------------------------ | ------------------------------------------------ |
| `/config/collect_agent/{agent_id}/kafka_brokers`   | Kafka broker list (JSON) | `["localhost:9092"]`                             |
| `/config/collect_agent/{agent_id}/kafka_topic`     | Kafka topic name         | `metrics`                                        |
| `/config/collect_agent/{agent_id}/grpc_port`       | gRPC server port         | `50051`                                          |
| `/config/collect_agent/{agent_id}/threshold_rules` | Threshold rules (JSON)   | See below                                        |
| `/config/collect_agent/{agent_id}/user_processors` | User processors (JSON)   | `[{"type": "sampler", "params": {"rate": 0.1}}]` |

### Threshold Rules Format

```json
{
  "cpu_usage_percent": { "max": 90, "min": 0 },
  "memory_usage_percent": { "max": 85 },
  "gpu_0_utilization_percent": { "max": 95 },
  "gpu_0_temperature_celsius": { "max": 85 },
  "gpu_0_power_watts": { "max": 300 },
  "gpu_max_temperature_celsius": { "max": 85 },
  "gpu_max_utilization_percent": { "max": 95 }
}
```

### Available Threshold Metrics

| Metric                        | Description                     |
| ----------------------------- | ------------------------------- |
| `cpu_usage_percent`           | Overall CPU usage (0-100%)      |
| `memory_usage_percent`        | Overall memory usage (0-100%)   |
| `cpu_total_ns`                | Sum of per-process CPU time     |
| `memory_total_bytes`          | Sum of per-process memory       |
| `gpu_{N}_utilization_percent` | GPU N utilization %             |
| `gpu_{N}_temperature_celsius` | GPU N temperature               |
| `gpu_{N}_power_watts`         | GPU N power consumption         |
| `gpu_max_utilization_percent` | Max utilization across all GPUs |
| `gpu_max_temperature_celsius` | Max temperature across all GPUs |
| `gpu_max_power_watts`         | Max power across all GPUs       |

---

## Operations

### Start/Stop Collection

```bash
# Start collection
docker exec etcd-server etcdctl put /config/compute_node/<node_id>/status running

# Stop collection
docker exec etcd-server etcdctl put /config/compute_node/<node_id>/status stopped
```

### Monitor Heartbeats

```bash
# Watch heartbeats for a specific node
docker exec etcd-server etcdctl watch /nodes/<node_id>/heartbeat

# Get current heartbeat
docker exec etcd-server etcdctl get /nodes/<node_id>/heartbeat
```

### View All Configuration

```bash
docker exec etcd-server etcdctl get --prefix /config
```

### Consume Kafka Messages

```bash
docker exec kafka kafka-console-consumer.sh \
    --bootstrap-server localhost:9092 \
    --topic metrics \
    --from-beginning
```

---

## Troubleshooting

### Compute Node Agent Issues

**eBPF permission denied:**

```bash
# Must run as root
sudo python main.py
```

**nvidia-smi not found:**

```bash
# GPU metrics will be empty if no NVIDIA GPU or drivers
# Install NVIDIA drivers if needed
nvidia-smi  # Test if available
```

**Cannot connect to etcd:**

```bash
# Check network connectivity
curl http://<coordinator-ip>:2379/health

# Check infra.json has correct etcd_endpoint
```

### Collect Agent Issues

**Cannot connect to Kafka:**

```bash
# Verify Kafka is running
docker logs kafka

# Test connectivity
nc -zv <kafka-ip> 9092
```

**Proto files not generated:**

```bash
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/metrics.proto
```

### General Issues

**Check etcd health:**

```bash
docker exec etcd-server etcdctl endpoint health
```

**View logs:**

```bash
# Compute node agent
sudo python main.py 2>&1 | tee agent.log

# Collect agent
python main.py 2>&1 | tee collect.log
```
