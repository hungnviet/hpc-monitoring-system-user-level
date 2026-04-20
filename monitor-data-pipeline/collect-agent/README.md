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

1. **SchemaValidator** - Validates incoming protobuf / `MetricBatch` shape
2. **FieldProjectionStage** - Keeps only etcd-configured process fields (others zeroed); Kafka emits only those keys when set
3. **PrefixAggregationStage** - Groups processes by longest matching `comm` prefix per `uid`, sums numeric fields (unmatched processes pass through)
4. **MetricsEnricher** - Adds `collect_agent_id` and `received_timestamp`
5. **ThresholdChecker** - Node/system thresholds and alerts
6. **UserProcessor** - User-configurable plugins (optional)

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
- `reload()` re-reads etcd (restart the process or call `reload()` if you extend the server to use it; pipeline stages read `CollectAgentConfig` on each batch)

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
- Invalid processes are dropped; invalid optional system metrics are cleared

### Stage 2: Field projection

- If `process_fields` is set in etcd, only those fields are retained (others zeroed on `ProcessMetric`)
- Kafka JSON for each process includes only those keys (plus `metadata` only when not projecting)

### Stage 3: Prefix aggregation

- If `comm_prefixes` is set, groups by `(uid, longest matching prefix)` and merges rows as described above
- If unset or empty, this stage is a no-op

### Stage 4: Enrichment

- Adds `collect_agent_id`
- Adds `received_timestamp`

### Stage 5: Threshold Checking

- Calculates node-level aggregates (including system and GPU metrics when present)
- Checks against configured thresholds
- Triggers alerts via gRPC to Main Server

### Stage 6: User Processors (Optional)

- **Aggregator** / **Sampler** plugins from etcd `user_processors`

## Data Flow

```
1. Compute Node Agent → gRPC Stream → MetricsServicer
2. MetricsServicer → Proto to MetricBatch
3. MetricBatch → Pipeline (core stages above)
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
| `/config/collect_agent/<id>/threshold_rules`     | Threshold config  | `{"cpu_usage_percent":{"max":80}}` |
| `/config/collect_agent/<id>/process_fields`       | Process fields to keep (JSON array); omit or empty = all fields | `["pid","uid","comm","read_bytes"]` |
| `/config/collect_agent/<id>/comm_prefixes`        | Prefixes for aggregation (JSON array); omit or empty = no aggregation | `["StreamT","kworker"]` |
| `/config/collect_agent/<id>/pipeline_stages`     | Ordered list of stage names (JSON array); omit or empty = default order | See below |
| `/config/collect_agent/<id>/user_processors`     | User plugins      | `[{"type": "aggregator"}]`        |

**`process_fields`:** Names must match `metrics.proto` `ProcessMetrics` fields (e.g. `pid`, `cpu_ontime_ns`, `read_bytes`). Unknown names are ignored.

**`comm_prefixes`:** For each process, the **longest** prefix in the list such that `comm.startswith(prefix)` wins. All processes with the same `(uid, matched_prefix)` are merged: numeric fields are summed; `comm` becomes the prefix; `pid` is set to `0`; `process_name` is cleared. Processes that match no prefix are left as single rows.

**Thresholds:** `gpu_utilization_percent` in etcd is accepted as an alias for the max GPU utilization across devices (`gpu_max_utilization_percent` internally).

**`pipeline_stages`:** JSON array of stage identifiers in execution order. Omitted or `[]` uses the default: `schema_validator` → `field_projection` → `prefix_aggregation` → `metrics_enricher` → `threshold_checker`. Each entry can be snake_case (`schema_validator`) or class-style (`SchemaValidator`); unknown names are skipped with a warning. Optional: `user_processor` (requires `user_processors` in etcd and the `user_processor` module). Restart the collect-agent after changing this key so the pipeline is rebuilt.

Example:

```bash
etcdctl put /config/collect_agent/collect_agent_1/pipeline_stages \
  '["SchemaValidator","field_projection","prefix_aggregation","metrics_enricher","threshold_checker"]'
```

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
