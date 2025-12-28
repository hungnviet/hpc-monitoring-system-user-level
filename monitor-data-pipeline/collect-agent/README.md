# Collect Agent

High-throughput middleware layer for ingesting, processing, and distributing metrics from distributed compute node agents.

## Architecture

```
Compute Nodes → [gRPC Stream] → Collect Agent → [Kafka] → Message Broker
                                       ↓
                                [Alert gRPC] → Main Server
```

## Components

### 1. gRPC Server (`server/`)

- Async streaming RPC for continuous metric ingestion
- One connection per compute node
- Concurrent stream handling
- Configurable worker pool

### 2. Processing Pipeline (`pipeline/`)

Fixed stages executed sequentially:

1. **SchemaValidator** - Validates incoming protobuf schema
2. **MetricsFilter** - Removes bootstrap/invalid/noisy records
3. **MetricsEnricher** - Adds collectAgentId and system metadata
4. **ThresholdChecker** - Checks resource thresholds, triggers alerts
5. **UserProcessor** - User-configurable plugins (optional)

### 3. Message Broker Publisher (`publisher/`)

- Async Kafka producer with batching
- gzip compression
- Keyed by node_id for partitioning

### 4. Alert Client (`alert/`)

- Direct gRPC to Main Server for critical alerts
- Async, non-blocking
- Automatic reconnection

### 5. Configuration Management (`config.py`)

- Loads from etcd
- Singleton pattern
- Hot-reload support

## Setup

### 0. Create Virtual Environment

```bash
python3 -m venv .venv
```

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate Protobuf Files

```bash
cd proto
bash generate.sh
```

### 3. Update infra.json

```json
{
  "collect_agent_id": "collect_agent_1",
  "etcd_endpoint": "http://localhost:2379"
}
```

## Usage

```bash
python3 main.py
```

## Pipeline Stages

### Stage 1: Schema Validation

- Validates required fields: node_id, timestamp, processes
- Checks process fields: pid > 0, cpu_ontime_ns >= 0, comm exists
- Invalid processes are dropped

### Stage 2: Filtering & Cleaning

- Filters bootstrap processes: systemd, init, kthreadd
- Removes metrics from startup period (< 300s)
- Drops processes with zero activity

### Stage 3: Enrichment

- Adds `collect_agent_id`
- Adds `received_timestamp`
- Attaches system metadata to each process

### Stage 4: Threshold Checking

- Calculates node-level aggregates
- Checks against configured thresholds
- Triggers alerts via gRPC to Main Server

### Stage 5: User Processors (Optional)

- **Aggregator**: Time-window aggregation
- **Sampler**: Statistical sampling
- Extensible plugin system

## Data Flow

```
1. Compute Node Agent → gRPC Stream → MetricsServicer
2. MetricsServicer → Proto to MetricBatch
3. MetricBatch → Pipeline (5 stages)
4. Valid batches → Kafka Publisher
5. Threshold violations → Alert Client → Main Server
```

## Configuration

All configuration except `collect_agent_id` and `etcd_endpoint` comes from etcd:

| etcd Key                                         | Description       | Example                           |
| ------------------------------------------------ | ----------------- | --------------------------------- |
| `/config/collect_agent/<id>/kafka_brokers`       | Kafka broker list | `["kafka1:9092"]`                 |
| `/config/collect_agent/<id>/kafka_topic`         | Kafka topic       | `"metrics"`                       |
| `/config/collect_agent/<id>/main_server_address` | Alert server      | `"mainserver:50052"`              |
| `/config/collect_agent/<id>/grpc_port`           | gRPC listen port  | `50051`                           |
| `/config/collect_agent/<id>/threshold_rules`     | Threshold config  | `{"cpu_total_ns": {"max": 9e11}}` |
| `/config/collect_agent/<id>/user_processors`     | User plugins      | `[{"type": "aggregator"}]`        |

## Monitoring

The servicer tracks:

- `total_reports_received`
- `total_processes_received`
- `active_connections`

Add metrics export for production monitoring.

## Network Requirements

- **Inbound**: Port 50051 (from compute nodes)
- **Outbound**: Kafka brokers, etcd, Main Server

## Error Handling

- Invalid batches → Logged, dropped
- Kafka publish errors → Logged, retried by aiokafka
- Alert send failures → Logged, connection auto-reconnect
- Pipeline stage errors → Logged, batch dropped

## Performance

- Async I/O for all operations
- Kafka batching with compression
- Configurable worker pool
- Non-blocking alert path

## Testing

See parent DEPLOYMENT.md for multi-machine testing setup.
