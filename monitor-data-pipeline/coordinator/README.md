# Coordinator - etcd Server

This folder contains the docker-compose setup for running etcd server, which acts as the central configuration and service discovery server for the monitor-data-pipeline.

## Quick Start

```bash
# Start etcd and etcdkeeper (web UI)
docker-compose up -d

# Verify etcd is running
docker exec etcd-server etcdctl endpoint health

# Access web UI (optional)
# Open http://localhost:8080 in browser
```

## Setup Script

The `setup-etcd.sh` script configures compute nodes and collect agents.

### Configure Compute Node

```bash
# Default configuration (node_id_1 -> localhost:50051)
./setup-etcd.sh

# Custom node with specific collect-agent address
./setup-etcd.sh --node gpu_node_1 --grpc 192.168.1.100:50051

# Full options
./setup-etcd.sh --node my_node \
    --grpc 192.168.1.100:50051 \
    --window 10.0 \
    --heartbeat 30.0
```

### Configure Collect Agent

```bash
# Configure collect agent with Kafka settings
./setup-etcd.sh --collect-agent collect_agent_1 --kafka 192.168.1.100:9092

# Full options
./setup-etcd.sh --collect-agent collect_agent_1 \
    --kafka 192.168.1.100:9092 \
    --topic metrics \
    --port 50051
```

### Configure Both

```bash
# Configure node and collect-agent together
./setup-etcd.sh --node node_1 --grpc 192.168.1.100:50051 \
    --collect-agent collect_agent_1 --kafka 192.168.1.100:9092
```

## Operations

### Start/Stop Collection

```bash
# Start collection for a node
docker exec etcd-server etcdctl put /config/compute_node/node_id_1/status running

# Stop collection
docker exec etcd-server etcdctl put /config/compute_node/node_id_1/status stopped
```

### Monitor Nodes

```bash
# Watch heartbeat
docker exec etcd-server etcdctl watch /nodes/node_id_1/heartbeat

# Get current heartbeat
docker exec etcd-server etcdctl get /nodes/node_id_1/heartbeat
```

### View Configuration

```bash
# View all configuration
docker exec etcd-server etcdctl get --prefix /config

# View specific node config
docker exec etcd-server etcdctl get --prefix /config/compute_node/node_id_1

# View collect agent config
docker exec etcd-server etcdctl get --prefix /config/collect_agent/collect_agent_1
```

### Update Threshold Rules

```bash
docker exec etcd-server etcdctl put /config/collect_agent/collect_agent_1/threshold_rules '{
    "cpu_usage_percent": {"max": 90},
    "memory_usage_percent": {"max": 85},
    "gpu_max_temperature_celsius": {"max": 85},
    "gpu_max_power_watts": {"max": 300}
}'
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| etcd | 2379 | Client communication |
| etcd | 2380 | Peer communication |
| etcdkeeper | 8080 | Web UI (http://localhost:8080) |

## etcd Key Structure

### Compute Node Keys

```
/config/compute_node/{node_id}/
├── target_collect_agent    # gRPC server address (e.g., "192.168.1.100:50051")
├── window                  # Collection window in seconds (e.g., "5.0")
├── heartbeat_interval      # Heartbeat interval in seconds (e.g., "10.0")
└── status                  # "running" or "stopped"

/nodes/{node_id}/
└── heartbeat               # JSON: {"timestamp": ..., "status": "alive", "collection_active": true}
```

### Collect Agent Keys

```
/config/collect_agent/{agent_id}/
├── kafka_brokers           # JSON array: ["localhost:9092"]
├── kafka_topic             # Topic name: "metrics"
├── grpc_port               # Port number: "50051"
├── threshold_rules         # JSON: {"cpu_usage_percent": {"max": 90}, ...}
└── user_processors         # JSON array: [{"type": "sampler", "params": {...}}]
```

## Shutdown

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (delete all data)
docker-compose down -v
```
