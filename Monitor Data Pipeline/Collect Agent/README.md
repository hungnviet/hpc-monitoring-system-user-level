# Collect Agent

The Collect Agent receives monitoring data from Compute Nodes via multiple transport protocols (gRPC and MQTT).

## Architecture

The Collect Agent supports two transport protocols:
- **gRPC**: High-performance RPC framework with protobuf serialization
- **MQTT**: Lightweight pub/sub messaging protocol for IoT devices

Both servers share the same data processing logic and can run independently or simultaneously.

## Setup

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Install MQTT Broker (Optional, for MQTT transport)

If you want to use MQTT, you need an MQTT broker (like Mosquitto):

```bash
# Ubuntu/Debian
sudo apt-get install mosquitto mosquitto-clients

# macOS
brew install mosquitto

# Start the broker
sudo systemctl start mosquitto  # Linux
brew services start mosquitto   # macOS
```

## Running the Servers

### gRPC Server

```bash
cd "Monitor Data Pipeline/Collect Agent/gRPC"
python server.py
```

The gRPC server will:
- Read configuration from `../../../infra.json`
- Listen on the configured port (default: 50051)
- Accept connections from compute node agents

### MQTT Server

```bash
cd "Monitor Data Pipeline/Collect Agent/MQTT"
python server.py
```

The MQTT server will:
- Read configuration from `../../../infra.json`
- Connect to the MQTT broker (default: localhost:1883)
- Subscribe to the configured topic (default: monitoring/compute-node)
- Process messages from compute node agents

## Configuration

All configuration is centralized in `infra.json` at the repository root:

```json
{
  "grpc_server": {
    "address": "localhost:50051",
    "max_message_size": 104857600
  },
  "mqtt_broker": {
    "address": "localhost",
    "port": 1883,
    "topic": "monitoring/compute-node",
    "qos": 1,
    "keepalive": 60
  }
}
```

## Testing

You can run both servers simultaneously in different terminals to test multi-transport data collection:

**Terminal 1 (gRPC):**
```bash
cd "Monitor Data Pipeline/Collect Agent/gRPC"
python server.py
```

**Terminal 2 (MQTT):**
```bash
cd "Monitor Data Pipeline/Collect Agent/MQTT"
python server.py
```

Then run the compute node agent which will send data to both servers.

## Data Format

Both servers receive the same data structure:
- Node ID
- Timestamp
- GPU Global State (power, temperature, utilization)
- Process Metrics (PID, CPU%, memory, GPU usage, command)

The servers display:
- Snapshot metadata
- GPU state
- Top 10 CPU-consuming processes
- Statistics (total snapshots, processes, nodes seen)
