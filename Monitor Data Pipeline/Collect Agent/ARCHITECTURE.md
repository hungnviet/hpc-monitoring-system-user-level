# Collect Agent - Modular Architecture

This document describes the modular architecture of the Collect Agent, which implements a **Layered Architecture Pattern** with clear separation of concerns.

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────┐
│                    Collect Agent                                │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │          Input Layer (Server Adapters)                   │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │  │
│  │  │  gRPC    │  │  MQTT    │  │ Telegraf │  ...         │  │
│  │  │ Server   │  │ Server   │  │ Server   │              │  │
│  │  └─────┬────┘  └─────┬────┘  └─────┬────┘              │  │
│  │        │             │             │                     │  │
│  │        └─────────────┼─────────────┘                     │  │
│  │                      ↓                                    │  │
│  │         Convert to Common Schema                         │  │
│  │              (MonitoringSnapshot)                        │  │
│  └──────────────────────┬───────────────────────────────────┘  │
│                         ↓                                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │         Processing Layer (Business Logic)                │  │
│  │                                                           │  │
│  │                   DataProcessor                          │  │
│  │    ┌────────────────────────────────────────┐           │  │
│  │    │  1. Validate                           │           │  │
│  │    │  2. Filter processes                   │           │  │
│  │    │  3. Enrich data                        │           │  │
│  │    │  4. Aggregate metrics                  │           │  │
│  │    │  5. Add metadata                       │           │  │
│  │    └────────────────────────────────────────┘           │  │
│  └──────────────────────┬───────────────────────────────────┘  │
│                         ↓                                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │          Output Layer (Publisher)                        │  │
│  │                                                           │  │
│  │               KafkaPublisher                             │  │
│  │    ┌────────────────────────────────────────┐           │  │
│  │    │  - Serialize to JSON                   │           │  │
│  │    │  - Publish to Kafka topic              │           │  │
│  │    │  - Handle retries and errors           │           │  │
│  │    └────────────────────────────────────────┘           │  │
│  └──────────────────────┬───────────────────────────────────┘  │
│                         ↓                                       │
└─────────────────────────┼───────────────────────────────────────┘
                          ↓
                 Kafka Topic
           (monitoring-data)
```

## Layer Responsibilities

### 1. Input Layer (Server Adapters)

**Purpose:** Receive data from compute nodes via various protocols

**Components:**
- `gRPC/server.py` - GrpcServerAdapter
- `MQTT/server.py` - MqttServerAdapter
- `Telegraf/server.py` - TelegrafServerAdapter (future)

**Responsibilities:**
1. Listen for incoming data on specific protocols
2. Parse protocol-specific format (Protobuf, JSON, InfluxDB Line Protocol, etc.)
3. Convert to common schema (`MonitoringSnapshot`)
4. Pass to processing layer
5. Return acknowledgment to client

**Key Principle:** Each server adapter is independent and pluggable. Adding new protocols requires only:
- Creating a new adapter class
- Implementing conversion to `MonitoringSnapshot`
- No changes to processing or publishing layers

### 2. Common Schema

**Purpose:** Unified data model for internal processing

**Location:** `common/schema.py`

**Core Classes:**
- `MonitoringSnapshot` - Complete snapshot from compute node
- `ProcessMetrics` - Per-process resource usage
- `GpuState` - GPU global state

**Benefits:**
- Decouples input protocols from processing logic
- Single source of truth for data structure
- Easy serialization (JSON, dict, etc.)
- Type safety with Python dataclasses

### 3. Processing Layer (Business Logic)

**Purpose:** Central computing logic for data transformation

**Location:** `processing/processor.py`

**Component:** `DataProcessor`

**Pipeline Steps:**
1. **Validate** - Check data integrity, freshness, and required fields
2. **Filter** - Remove low-resource processes based on thresholds
3. **Enrich** - Add computed metrics, rankings, classifications
4. **Aggregate** - Calculate summary statistics and top processes
5. **Add Metadata** - Include processing timestamps and version info

**Configuration:** Controlled via `infra.json`:
```json
{
  "processing": {
    "min_cpu_threshold": 0.1,
    "min_memory_threshold": 10485760,
    "enable_aggregation": true,
    "enable_enrichment": true
  }
}
```

**Key Principle:** All business logic is centralized here. Servers don't implement any processing logic - they only adapt input/output.

### 4. Output Layer (Publisher)

**Purpose:** Publish processed data to downstream systems

**Location:** `publishing/kafka_publisher.py`

**Component:** `KafkaPublisher`

**Responsibilities:**
1. Maintain connection to Kafka broker
2. Serialize processed data to JSON
3. Publish to configured topic with message key
4. Handle errors and retries
5. Track publishing statistics

**Mock Mode:** `MockKafkaPublisher` for testing without real Kafka

**Configuration:** Controlled via `infra.json`:
```json
{
  "kafka": {
    "use_mock": true,
    "bootstrap_servers": ["localhost:9092"],
    "topic": "monitoring-data",
    "key_field": "node_id"
  }
}
```

## Data Flow Example

### Complete Flow (gRPC)

```
1. Compute Node sends Protobuf message via gRPC
   ↓
2. GrpcServerAdapter receives request
   └─ Calls _convert_from_protobuf()
   └─ Creates MonitoringSnapshot object
   ↓
3. DataProcessor.process(snapshot)
   ├─ Validates data
   ├─ Filters 100 processes → 25 relevant processes
   ├─ Enriches with resource scores
   ├─ Aggregates: total CPU, memory, top 5 by metric
   └─ Returns processed_data dict
   ↓
4. KafkaPublisher.publish(processed_data)
   ├─ Serializes to JSON
   ├─ Publishes to topic "monitoring-data"
   ├─ Key: "compute-node-01"
   └─ Returns success
   ↓
5. GrpcServerAdapter returns SnapshotResponse
   └─ Client receives acknowledgment
```

### Complete Flow (MQTT)

```
1. Compute Node publishes JSON message to MQTT topic
   ↓
2. MqttServerAdapter receives message via callback
   └─ Calls _convert_from_json()
   └─ Creates MonitoringSnapshot object
   ↓
3. [Same as gRPC: DataProcessor → KafkaPublisher]
   ↓
4. No explicit acknowledgment (pub/sub model)
```

## Design Patterns

### 1. Adapter Pattern
- Each server (gRPC, MQTT, Telegraf) is an **adapter** that converts protocol-specific input to common schema
- Allows adding new protocols without changing core logic

### 2. Pipeline Pattern
- DataProcessor implements a processing pipeline
- Each step is independent and can be enabled/disabled
- Easy to add new processing steps

### 3. Strategy Pattern
- MockKafkaPublisher vs KafkaPublisher
- Same interface, different implementation
- Allows testing without infrastructure dependencies

### 4. Dependency Injection
- Servers receive processor and publisher as constructor arguments
- Loose coupling, easy to test, configurable

## Adding New Input Servers

To add a new protocol (e.g., REST API, Telegraf):

### Step 1: Create Server Adapter

```python
# REST/server.py
from flask import Flask, request
from common.schema import MonitoringSnapshot
from processing.processor import DataProcessor
from publishing.kafka_publisher import KafkaPublisher

class RestServerAdapter:
    def __init__(self, processor: DataProcessor, publisher: KafkaPublisher):
        self.processor = processor
        self.publisher = publisher
        self.app = Flask(__name__)

        @self.app.route('/monitoring/snapshot', methods=['POST'])
        def receive_snapshot():
            data = request.json
            snapshot = self._convert_from_json(data)
            processed_data = self.processor.process(snapshot)
            self.publisher.publish(processed_data)
            return {'success': True}

    def _convert_from_json(self, data: dict) -> MonitoringSnapshot:
        # Convert REST JSON to MonitoringSnapshot
        pass

    def start(self):
        self.app.run(host='0.0.0.0', port=8000)
```

### Step 2: That's It!

No changes needed to:
- Common schema (already defined)
- DataProcessor (protocol-agnostic)
- KafkaPublisher (protocol-agnostic)

## Configuration

All components are configured via `infra.json`:

```json
{
  "grpc_server": {...},
  "mqtt_broker": {...},
  "kafka": {
    "use_mock": true,
    "bootstrap_servers": ["localhost:9092"],
    "topic": "monitoring-data"
  },
  "processing": {
    "min_cpu_threshold": 0.1,
    "enable_aggregation": true
  }
}
```

## Benefits of This Architecture

1. **Separation of Concerns**: Input, processing, and output are independent
2. **Maintainability**: Each component has a single, well-defined responsibility
3. **Testability**: Components can be tested in isolation with mocks
4. **Scalability**: Easy to add new protocols, processing steps, or output destinations
5. **Flexibility**: Components can be configured independently
6. **Reusability**: Processing and publishing logic is shared across all servers

## Testing Strategy

### Unit Testing
- Test each layer independently
- Mock dependencies

```python
def test_processor_filtering():
    processor = DataProcessor({'min_cpu_threshold': 5.0})
    snapshot = create_test_snapshot(cpu_values=[1.0, 6.0, 10.0])
    result = processor.process(snapshot)
    assert len(result['processes']) == 2  # Only > 5.0%
```

### Integration Testing
- Test with MockKafkaPublisher
- Verify end-to-end flow without infrastructure

### System Testing
- Deploy with real Kafka
- Send test data from compute nodes
- Verify in Kafka topic

## Future Enhancements

1. **Add more input protocols**: REST API, WebSocket, Telegraf
2. **Add more output destinations**: Database, file storage, metrics systems
3. **Advanced processing**: Anomaly detection, ML predictions, alerting
4. **Horizontal scaling**: Multiple server instances, load balancing
5. **Data persistence**: Cache snapshots for replay/recovery
