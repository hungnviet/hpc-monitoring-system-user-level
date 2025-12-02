# Compute Node Agent

The Compute Node Agent collects system resource usage (CPU, Memory, GPU) and sends the data to Collect Agents via multiple transport protocols.

## Architecture

### Design Pattern: Strategy Pattern

The agent uses the **Strategy Pattern** to support multiple transport protocols:

```
┌─────────────────────────────┐
│   Main Program              │
│  (Orchestrator)             │
└──────────┬──────────────────┘
           │
           ├──► ComputeNodeUsage (Data Collection)
           │    ├─ CPU Monitor (eBPF)
           │    ├─ Memory Monitor (eBPF)
           │    └─ GPU Monitor (nvidia-smi)
           │
           └──► Transport Clients (Strategy)
                ├─ GrpcClient (protobuf)
                └─ MqttClient (JSON)
```

### Key Components

1. **ComputeNodeUsage**: Collects real metrics from the system using eBPF and nvidia-smi
2. **SimulatedDataGenerator**: Generates fake metrics for testing without real hardware
3. **TransportClient (Abstract)**: Base interface for all transport protocols
4. **GrpcClient**: Implements gRPC transport with protobuf serialization
5. **MqttClient**: Implements MQTT transport with JSON serialization
6. **Main Program**: Orchestrates data collection and transport

## Features

- **Multi-Transport Support**: Send data via gRPC, MQTT, or both simultaneously
- **Simulated Data Mode**: Test without real hardware using randomly generated metrics
- **Pluggable Architecture**: Easy to add new transport protocols
- **Configuration-Driven**: All settings in `infra.json`
- **Separation of Concerns**: Data collection is independent of transport

## Build

### Install Dependencies

```bash
make install-deps
```

This installs:
- Build tools (gcc, clang, make)
- eBPF dependencies (libbpf, kernel headers)
- gRPC/Protobuf libraries
- MQTT libraries (paho-mqtt)
- JSON library (nlohmann-json, header-only)

### Compile

```bash
make clean
make
```

Build process:
1. Generates `vmlinux.h` from kernel BTF
2. Compiles eBPF programs (`cputime.bpf.c`, `memleak.bpf.c`)
3. Generates BPF skeleton headers
4. Generates gRPC/Protobuf C++ code
5. Compiles all C++ sources
6. Links final executable: `compute_node_monitor`

## Configuration

Edit `../../infra.json`:

```json
{
  "grpc_server": {
    "address": "localhost:50051"
  },
  "mqtt_broker": {
    "address": "localhost",
    "port": 1883,
    "topic": "monitoring/compute-node",
    "qos": 1,
    "keepalive": 60
  },
  "compute_nodes": [
    {
      "node_id": "compute-node-01",
      "hostname": "cn-01.cluster.local"
    }
  ],
  "monitoring": {
    "snapshot_interval_seconds": 1,
    "enable_gpu": true,
    "use_simulated_data": true
  },
  "transport": {
    "enable_grpc": true,
    "enable_mqtt": true
  }
}
```

### Configuration Options

- `monitoring.use_simulated_data`:
  - `true`: Use simulated data (no root required, no real hardware needed)
  - `false`: Use real eBPF/GPU monitoring (requires root)

- `transport.enable_grpc`: Enable gRPC transport
- `transport.enable_mqtt`: Enable MQTT transport
- `monitoring.snapshot_interval_seconds`: How often to collect and send data

## Running

### With Simulated Data (No Root Required)

```bash
# Set use_simulated_data: true in infra.json
./compute_node_monitor
```

This mode is perfect for:
- Testing the transport layer
- Developing without real hardware
- Running without root privileges

### With Real Monitoring (Requires Root)

```bash
# Set use_simulated_data: false in infra.json
make run
# or
sudo ./compute_node_monitor
```

This mode:
- Uses eBPF to collect real CPU and memory metrics
- Parses nvidia-smi for GPU metrics
- Requires root for eBPF programs

## Example Output

```
========================================
  Compute Node Monitor (Multi-Transport)
========================================
Press Ctrl+C to exit

[Config] Node ID: compute-node-01
[Config] Snapshot interval: 1 seconds
[Config] Using simulated data: YES
[Config] Transport: gRPC=ON, MQTT=ON

[Main] Initializing simulated data generator...
[Main] ✓ Simulated data generator ready

[GrpcClient] Initializing gRPC client for localhost:50051
[GrpcClient] Connecting to localhost:50051...
[GrpcClient] ✓ Connected successfully

[MqttClient] Initializing MQTT client for tcp://localhost:1883
[MqttClient] Topic: monitoring/compute-node, QoS: 1
[MqttClient] Connecting to tcp://localhost:1883...
[MqttClient] ✓ Connected successfully

[Main] Active transport clients: 2
  - gRPC
  - MQTT

[Main] Starting monitoring loop...

=== Snapshot #1 (timestamp: 1701234567) ===
Processes: 15
GPU: 45% @ 67°C, 125.3W
[GrpcClient] ✓ Received snapshot #1 with 15 processes
[MqttClient] ✓ Published snapshot to topic 'monitoring/compute-node' (1245 bytes)
```

## Transport Protocol Differences

| Feature | gRPC | MQTT |
|---------|------|------|
| Serialization | Protobuf (binary) | JSON (text) |
| Message Size | Smaller | Larger |
| Performance | Faster | Moderate |
| Debugging | Harder | Easier (human-readable) |
| Reliability | Direct connection | Broker-based pub/sub |
| Use Case | High-performance RPC | IoT, decoupled systems |

## Adding New Transport Protocols

1. Create new class inheriting from `TransportClient`
2. Implement `connect()`, `disconnect()`, `sendSnapshot()`
3. Add instantiation logic in `main.cpp`
4. Update `infra.json` with new config section
5. Update Makefile with new dependencies

Example:
```cpp
class KafkaClient : public TransportClient {
public:
    bool connect() override { /* ... */ }
    bool disconnect() override { /* ... */ }
    bool sendSnapshot(const ComputeNodeSnapshotInternal& snapshot) override { /* ... */ }
    std::string getTransportType() const override { return "Kafka"; }
};
```

## Troubleshooting

### Build Errors

- **eBPF errors**: Ensure kernel headers are installed and BTF is enabled
- **gRPC errors**: Check protobuf/grpc libraries are installed correctly
- **MQTT errors**: Install `libpaho-mqtt-dev` and `libpaho-mqttpp-dev`

### Runtime Errors

- **gRPC connection failed**: Ensure gRPC server is running on configured port
- **MQTT connection failed**: Ensure MQTT broker (mosquitto) is running
- **eBPF load failed**: Must run with sudo/root privileges
- **No GPU found**: Set `enable_gpu: false` or use simulated data

## Commands Summary

```bash
# Install dependencies
make install-deps

# Build
make clean
make

# Run with simulated data (no root)
./compute_node_monitor

# Run with real monitoring (requires root)
make run
```
