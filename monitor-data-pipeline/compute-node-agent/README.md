# Compute Node Agent

A comprehensive system monitoring agent that collects process-level metrics (CPU, RAM, Disk, Network, GPU) and streams them to a centralized gRPC server with etcd-based configuration management.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Compute Node Agent                       │
│                                                             │
│  ┌──────────────┐    ┌────────────────┐   ┌──────────────┐ │
│  │ VirtualSensor│───▶│ MetricsStream  │──▶│ gRPC Server  │ │
│  │  (Collector) │    │     Client     │   │              │ │
│  └──────────────┘    └────────────────┘   └──────────────┘ │
│         │                                                    │
│         ├─ CPU Collector (eBPF)                             │
│         ├─ RAM Collector                                    │
│         ├─ Disk Collector (eBPF)                            │
│         ├─ Network Collector (eBPF)                         │
│         └─ GPU Collector (NVML)                             │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              etcd Configuration                      │   │
│  │  - gRPC server address                               │   │
│  │  - Collection window                                 │   │
│  │  - Status control (running/stopped)                  │   │
│  │  - Heartbeat management                              │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. VirtualSensor (`collector/main.py`)
Combines 5 specialized collectors to gather comprehensive process metrics:
- **CPU**: Process CPU time using eBPF/BCC
- **RAM**: Memory usage from `/proc/{pid}/status`
- **Disk**: I/O read/write bytes using eBPF
- **Network**: Network RX/TX bytes using eBPF
- **GPU**: GPU memory usage using NVML (NVIDIA GPUs)

### 2. MetricsStreamClient (`client/main.py`)
gRPC client that:
- Converts Python dict metrics to protobuf messages
- Maintains unidirectional stream to gRPC server
- Queues messages during temporary connection loss
- Implements retry logic (max 3 attempts)

### 3. ComputeNodeAgent (`main.py`)
Main orchestrator that:
- Reads configuration from `infra.json` and etcd
- Manages etcd heartbeat to indicate node liveness
- Controls collection lifecycle based on etcd status flag
- Coordinates VirtualSensor and MetricsStreamClient

## Setup

### Prerequisites

1. **System Requirements**:
   - Linux kernel with eBPF support (4.1+)
   - Root/sudo access (required for BPF)
   - NVIDIA GPU with drivers (optional, for GPU monitoring)

2. **Install Dependencies**:
```bash
# On Debian/Ubuntu
sudo apt update
sudo apt install -y bpfcc-tools libbpfcc libbpfcc-dev python3-bpfcc linux-headers-$(uname -r)

# Install Python packages
pip install -r requirements.txt
```

### Generate Protobuf Files

```bash
cd proto
bash generate.sh
```

This generates:
- `proto/metrics_pb2.py` - Protobuf message definitions
- `proto/metrics_pb2_grpc.py` - gRPC service stubs

**Note**: The proto folder is now local to compute-node-agent and separate from the collection server.

## Configuration

### 1. infra.json
Local configuration file:
```json
{
    "node_id": "node_id_1",
    "ectd_endpoint": "http://localhost:2379"
}
```

### 2. etcd Configuration Keys

The agent reads the following keys from etcd:

| Key | Description | Example Value |
|-----|-------------|---------------|
| `/config/compute_node/<node_id>/target_collect_agent` | gRPC server address | `localhost:50051` |
| `/config/compute_node/<node_id>/window` | Collection window (seconds) | `5.0` |
| `/config/compute_node/<node_id>/status` | Control flag | `running` or `stopped` |
| `/config/compute_node/<node_id>/heartbeat_interval` | Heartbeat interval (seconds) | `10.0` |

**Heartbeat Key** (written by agent):
- `/nodes/<node_id>/heartbeat` - Contains timestamp, status, and collection state

### Setting up etcd Keys

```bash
# Set gRPC server address
etcdctl put /config/compute_node/node_id_1/target_collect_agent "localhost:50051"

# Set collection window
etcdctl put /config/compute_node/node_id_1/window "5.0"

# Enable collection
etcdctl put /config/compute_node/node_id_1/status "running"

# Optional: Set heartbeat interval
etcdctl put /config/compute_node/node_id_1/heartbeat_interval "10.0"
```

## Usage

### Running the Agent

```bash
cd compute-node-agent
sudo python3 main.py
```

**Note**: Requires `sudo` for eBPF/BCC operations.

### Controlling Collection

The agent monitors the etcd status key and automatically starts/stops collection:

```bash
# Start collection
etcdctl put /config/compute_node/node_id_1/status "running"

# Stop collection
etcdctl put /config/compute_node/node_id_1/status "stopped"
```

### Monitoring Heartbeat

```bash
# Watch heartbeat updates
etcdctl watch /nodes/node_id_1/heartbeat

# Get current heartbeat
etcdctl get /nodes/node_id_1/heartbeat
```

## Data Flow

1. **Initialization**:
   - Load `infra.json` → Get node_id and etcd endpoint
   - Connect to etcd with retry (max 3 attempts)
   - Fetch gRPC server address and configuration from etcd
   - Initialize VirtualSensor and MetricsStreamClient

2. **Collection Loop** (when status = "running"):
   - VirtualSensor collects metrics from all 5 collectors
   - Returns `Dict[int, Dict[str, Any]]` keyed by PID
   - MetricsStreamClient converts to protobuf
   - Streams to gRPC server

3. **Heartbeat Loop** (background thread):
   - Sends heartbeat to etcd every N seconds
   - Includes timestamp, status, and collection state

4. **Status Watch Loop** (background thread):
   - Watches etcd status key for changes
   - Enables/disables collection dynamically

## Output Data Format

Each process metrics report contains:

```python
{
    "pid": int,                    # Process ID
    "cpu_ontime_ns": int,         # CPU time in nanoseconds
    "uid": int,                   # User ID
    "comm": str,                  # Command name
    "read_bytes": int,            # Disk read bytes
    "write_bytes": int,           # Disk write bytes
    "net_rx_bytes": int,          # Network received bytes
    "net_tx_bytes": int,          # Network transmitted bytes
    "avg_rss_bytes": int,         # Average RSS memory
    "process_name": str,          # Full process name
    "gpu_used_memory_mib": int    # GPU memory usage (MiB)
}
```

## Error Handling

- **Connection Failures**: Both etcd and gRPC connections retry up to 3 times with exponential backoff
- **Message Queue**: If gRPC server is temporarily unavailable, messages are queued (max 1000)
- **Graceful Shutdown**: SIGINT/SIGTERM handlers ensure clean shutdown

## Troubleshooting

### Permission Denied Errors
```bash
# Run with sudo for eBPF operations
sudo python3 main.py
```

### etcd Connection Failed
```bash
# Check etcd is running
etcdctl endpoint health

# Verify endpoint in infra.json
cat infra.json
```

### gRPC Connection Failed
```bash
# Check gRPC server address in etcd
etcdctl get /config/compute_node/node_id_1/target_collect_agent

# Verify gRPC server is running
netstat -tlnp | grep 50051
```

### GPU Metrics Not Available
```bash
# Check NVIDIA drivers
nvidia-smi

# Install pynvml
pip install pynvml
```

## Development

### Project Structure
```
compute-node-agent/
├── main.py                    # Main agent orchestrator
├── infra.json                 # Local configuration
├── requirements.txt           # Python dependencies
├── collector/
│   ├── main.py               # VirtualSensor
│   ├── cpu_collector.py      # CPU metrics (eBPF)
│   ├── ram_collector.py      # RAM metrics
│   ├── disk_collector.py     # Disk I/O (eBPF)
│   ├── network_collector.py  # Network I/O (eBPF)
│   └── gpu_process_collector.py  # GPU metrics (NVML)
└── client/
    └── main.py               # gRPC streaming client
```

### Adding New Collectors
1. Create collector class with `collect()` method
2. Add to VirtualSensor initialization in `collector/main.py`
3. Update `merge()` function to include new metrics
4. Update protobuf schema in `proto/metrics.proto`

## License

See project root for license information.
