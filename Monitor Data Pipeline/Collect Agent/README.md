# Collect Agent - Monitoring Data Collection Service

The **Collect Agent** is a unified data collection service that receives monitoring data from compute nodes via multiple protocols (gRPC, MQTT), processes the data, and publishes it to Kafka for downstream analysis.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Collect Agent                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐          ┌──────────────┐                   │
│  │ gRPC Server  │          │ MQTT Server  │   Input Layer     │
│  │ (Protobuf)   │          │ (JSON)       │                   │
│  └──────┬───────┘          └──────┬───────┘                   │
│         │                          │                            │
│         └──────────┬───────────────┘                           │
│                    │                                            │
│         ┌──────────▼──────────┐                                │
│         │  Common Schema      │   Data Model                   │
│         │  (MonitoringSnapshot)│                               │
│         └──────────┬──────────┘                                │
│                    │                                            │
│         ┌──────────▼──────────┐                                │
│         │  Data Processor     │   Processing Layer             │
│         │  - Validation       │                                │
│         │  - Filtering        │                                │
│         │  - Enrichment       │                                │
│         │  - Aggregation      │                                │
│         └──────────┬──────────┘                                │
│                    │                                            │
│         ┌──────────▼──────────┐                                │
│         │  Kafka Publisher    │   Output Layer                 │
│         │  Topic: raw_data    │                                │
│         └─────────────────────┘                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

1. **Protocol Agnostic**: Both gRPC and MQTT servers convert their protocol-specific formats to a common schema
2. **Modular Architecture**: Separate input, processing, and output layers for maintainability
3. **Unified Configuration**: Single `infra.json` configuration file for all components
4. **Single Virtual Environment**: One `venv` for all servers and dependencies
5. **Flexible Deployment**: Run gRPC or MQTT server independently from the root directory

## Directory Structure

```
Collect Agent/
├── README.md                  # This file
├── requirements.txt           # Python dependencies
├── setup.sh                   # Virtual environment setup script
├── generate_proto.sh          # Protobuf code generation script
│
├── run_grpc_server.py         # gRPC server launcher (run from here!)
├── run_mqtt_server.py         # MQTT server launcher (run from here!)
│
├── common/                    # Shared data models
│   ├── __init__.py
│   └── schema.py              # MonitoringSnapshot, ProcessMetrics, GpuState
│
├── processing/                # Data processing logic
│   ├── __init__.py
│   └── processor.py           # DataProcessor class
│
├── publishing/                # Kafka publishing
│   ├── __init__.py
│   └── kafka_publisher.py     # KafkaPublisher, MockKafkaPublisher
│
├── gRPC/                      # gRPC server implementation
│   ├── server.py              # GrpcServerAdapter
│   └── generated/             # Generated protobuf code (created by generate_proto.sh)
│       ├── monitor_pb2.py
│       └── monitor_pb2_grpc.py
│
└── MQTT/                      # MQTT server implementation
    └── server.py              # MqttServerAdapter
```

## Quick Start

### 1. Setup Virtual Environment

Run the setup script to create a virtual environment and install dependencies:

```bash
cd "Monitor Data Pipeline/Collect Agent"

# Run setup script
./setup.sh

# Or manually:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Generate Protobuf Code (gRPC only)

If you want to use the gRPC server, generate the Python protobuf code:

```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Generate protobuf code
./generate_proto.sh

# Or manually:
python3 -m grpc_tools.protoc \
    -I ../Utils \
    --python_out=gRPC/generated \
    --grpc_python_out=gRPC/generated \
    ../Utils/monitor.proto
```

### 3. Start Kafka (Required)

The Collect Agent publishes to Kafka, so you need a running Kafka broker:

```bash
# Option A: Using Docker Compose
cd "../../Streaming Section"
docker-compose up -d

# Option B: Using local Kafka
# Start Zookeeper
zookeeper-server-start.sh config/zookeeper.properties

# Start Kafka
kafka-server-start.sh config/server.properties
```

### 4. Configure infra.json

Edit `../../infra.json` to configure Kafka connection:

```json
{
  "kafka": {
    "use_mock": false,
    "bootstrap_servers": ["localhost:9093"],
    "topic": "raw_data",
    "key_field": "node_id"
  }
}
```

**Note:** Set `"use_mock": true` to test without Kafka (messages will be logged only).

### 5. Start a Server

#### Option A: Run gRPC Server

```bash
# Activate virtual environment
source venv/bin/activate

# Start gRPC server (default: port 50051)
python3 run_grpc_server.py

# With custom port
python3 run_grpc_server.py --port 50052

# With mock Kafka (no real Kafka required)
python3 run_grpc_server.py --mock-kafka
```

#### Option B: Run MQTT Server

```bash
# Activate virtual environment
source venv/bin/activate

# Start MQTT server (default: localhost:1883)
python3 run_mqtt_server.py

# With custom broker
python3 run_mqtt_server.py --broker localhost --port 1883

# With custom topic
python3 run_mqtt_server.py --topic monitoring/my-nodes

# With mock Kafka
python3 run_mqtt_server.py --mock-kafka
```

## Common Data Schema

Both servers convert their input to this unified schema:

```python
@dataclass
class GpuState:
    power_watts: float
    temperature_celsius: int
    total_load_percent: int

@dataclass
class ProcessMetrics:
    pid: int
    uid: int
    command: str
    cpu_usage_percent: float
    memory_bytes: int
    gpu_sm_percent: float = -1.0  # -1 means not using GPU
    gpu_mem_percent: float = -1.0
    gpu_mem_mib: int = 0

@dataclass
class MonitoringSnapshot:
    timestamp: int                    # Unix timestamp
    node_id: str
    gpu_global_state: GpuState
    processes: List[ProcessMetrics]
    received_at: float                # Added by server
    source_protocol: str              # 'gRPC' or 'MQTT'
```

## Data Processing Pipeline

The `DataProcessor` class performs the following operations:

### 1. Validation
- Checks required fields (node_id, timestamp)
- Validates data freshness (warns if > 1 hour old)
- Detects suspicious values (e.g., CPU > 1000%)

### 2. Filtering
- Filters processes by CPU threshold
- Filters processes by memory threshold
- Always keeps GPU-using processes

### 3. Enrichment
- Ranks processes by resource usage score
- Computes weighted score: `0.4 * CPU + 0.3 * Memory + 0.3 * GPU`
- Sorts processes by importance

### 4. Aggregation
- Computes total CPU/memory usage
- Counts GPU-using processes
- Generates top 5 lists (by CPU, memory, GPU)

### 5. Metadata Addition
- Adds processing timestamp
- Adds processor version
- Adds processing statistics

## Configuration Options

All configuration is in `../../infra.json`:

### gRPC Configuration

```json
{
  "grpc_server": {
    "address": "localhost:50051",
    "max_message_size": 104857600
  }
}
```

### MQTT Configuration

```json
{
  "mqtt_broker": {
    "address": "localhost",
    "port": 1883,
    "topic": "monitoring/compute-node",
    "qos": 1,
    "keepalive": 60
  }
}
```

### Kafka Configuration

```json
{
  "kafka": {
    "use_mock": false,
    "bootstrap_servers": ["localhost:9093"],
    "topic": "raw_data",
    "key_field": "node_id"
  }
}
```

### Processing Configuration

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

## Command Line Arguments

### gRPC Server

```bash
python3 run_grpc_server.py [OPTIONS]

Options:
  --config PATH       Configuration file path (default: ../../infra.json)
  --port PORT         gRPC server port (overrides config)
  --mock-kafka        Use mock Kafka publisher
  -h, --help          Show help message
```

### MQTT Server

```bash
python3 run_mqtt_server.py [OPTIONS]

Options:
  --config PATH       Configuration file path (default: ../../infra.json)
  --broker ADDRESS    MQTT broker address (overrides config)
  --port PORT         MQTT broker port (overrides config)
  --topic TOPIC       MQTT topic to subscribe (overrides config)
  --mock-kafka        Use mock Kafka publisher
  -h, --help          Show help message
```

## Testing Without Kafka

For testing without a Kafka broker:

```bash
# Option 1: Use command line flag
python3 run_grpc_server.py --mock-kafka
python3 run_mqtt_server.py --mock-kafka

# Option 2: Edit infra.json
{
  "kafka": {
    "use_mock": true
  }
}
```

The `MockKafkaPublisher` will log messages instead of publishing to Kafka.

## Verifying Kafka Messages

To consume messages from Kafka and verify they're being published:

```bash
# Using Kafka console consumer
kafka-console-consumer.sh \
  --bootstrap-server localhost:9093 \
  --topic raw_data \
  --from-beginning

# Or with Docker
docker exec -it <kafka-container> kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic raw_data \
  --from-beginning
```

## Troubleshooting

### Error: "Module not found: grpc"

**Solution:** Install dependencies:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Error: "No module named 'monitor_pb2'"

**Solution:** Generate protobuf code:
```bash
./generate_proto.sh
```

### Error: "Failed to connect to Kafka"

**Solutions:**
1. Check if Kafka is running: `docker ps` or check Kafka process
2. Verify port in `infra.json` matches your Kafka setup
3. Use `--mock-kafka` flag to test without Kafka

### Error: "Connection refused" (gRPC)

**Solution:** Make sure the gRPC server is running first.

### Error: "Connection refused" (MQTT)

**Solution:** Make sure MQTT broker (e.g., Mosquitto) is running:
```bash
# Install Mosquitto (if not installed)
brew install mosquitto         # macOS
sudo apt install mosquitto     # Linux

# Start Mosquitto
brew services start mosquitto  # macOS
sudo systemctl start mosquitto # Linux
```

## Related Documentation

- **Compute Node Agent**: `../Compute Node Agent/README.md`
- **Sample Application**: `../Compute Node Agent/SAMPLE_README.md`
- **Architecture Overview**: `../../CLAUDE.md`
- **Protocol Definition**: `../Utils/monitor.proto`

## License

See repository root for license information.
