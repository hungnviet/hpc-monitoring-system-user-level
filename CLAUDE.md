# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a monitoring data pipeline system for high-performance computing clusters. It collects process-level metrics (CPU, Memory, GPU) from compute nodes and streams them through a data pipeline for analysis.

**Key Architecture Components:**
1. **Compute Node Agent** (C++/eBPF) - Runs on compute nodes to collect metrics
2. **Collect Agent** (Python) - Receives data via gRPC/MQTT from compute nodes
3. **Streaming Section** (Kafka/Spark) - Data streaming and processing pipeline
4. **Application** - Frontend/Backend for visualization and analysis

The system uses a shared `MonitoringData` object format that flows through the pipeline, with each module modifying the data object at different phases. Configuration for inter-module communication is centralized in `infra.json` at the repository root.

**Transport Layer (Strategy Pattern):**
The system supports multiple transport protocols for flexibility:
- **gRPC**: High-performance binary protocol with Protobuf serialization
- **MQTT**: Lightweight pub/sub protocol with JSON serialization
- Both transports can run simultaneously for redundancy/testing

## Build and Development Commands

### Compute Node Agent (Primary Component)

The compute node monitor is a C++ application using eBPF for low-overhead system monitoring and gRPC for data transmission.

**Location:** `Monitor Data Pipeline/Compute Node Agent/`

**Prerequisites:**
```bash
cd "Monitor Data Pipeline/Compute Node Agent"
make install-deps  # Install all dependencies (Debian/Ubuntu)
```

**Build:**
```bash
cd "Monitor Data Pipeline/Compute Node Agent"
make               # Full build: generates eBPF skeletons, protobuf code, compiles binary
make clean         # Remove all build artifacts
```

**Run:**
```bash
cd "Monitor Data Pipeline/Compute Node Agent"
make run           # Runs with sudo (required for eBPF)
```

The build process:
1. Generates `vmlinux.h` from kernel BTF
2. Compiles eBPF programs (`cputime.bpf.c`, `memleak.bpf.c`) to `.o` files
3. Generates BPF skeletons (`.skel.h` headers)
4. Generates gRPC/protobuf C++ code from `monitor.proto`
5. Compiles final `compute_node_monitor` executable

### gRPC Server (Collect Agent)

**Location:** `Monitor Data Pipeline/Collect Agent/gRPC/`

The Python gRPC server receives snapshots from compute nodes. Requires protobuf code generation before running.

## Architecture Details

### Compute Node Agent Architecture (Strategy Pattern)

The agent uses the **Strategy Pattern** to decouple data collection from transport:

**1. Data Collection Layer** (`ComputeNodeUsage/`)
- `cpu_usage.cpp/h` - eBPF-based CPU time tracking per process
- `memory_usage.cpp/h` - eBPF-based memory allocation tracking
- `gpu_usage.cpp/h` - NVIDIA GPU metrics via nvidia-smi parsing
- `simulated_data.h` - Generates fake metrics for testing (no root/hardware needed)
- `types.h` - Internal data structures (`ProcessMetricsInternal`, `ComputeNodeSnapshotInternal`)

**2. Transport Abstraction Layer** (`Agent/`)
- `transport_client.h` - Abstract base class defining transport interface
- All transports implement: `connect()`, `disconnect()`, `sendSnapshot()`
- New transports can be added without modifying data collection code

**3. Transport Implementations**
- `Agent/gRPC/grpc_client.cpp/h` - Protobuf binary serialization, direct RPC
- `Agent/MQTT/mqtt_client.cpp/h` - JSON text serialization, pub/sub via broker

**4. Orchestration Layer** (`main.cpp`)
- Reads `infra.json` configuration
- Initializes data source (real monitoring or simulated data)
- Creates and connects enabled transport clients
- Main loop: collect data → send via all transports → sleep
- Handles graceful shutdown on SIGINT/SIGTERM

### eBPF Programs

Located in `ComputeNodeUsage/ebpf/`:
- `cpu-usage/cputime.bpf.c` - Tracks process CPU time via kernel tracepoints
- `memory-allocation/memleak.bpf.c` - Tracks memory allocations per process

eBPF programs are compiled to BPF bytecode, then skeleton headers are generated for C++ integration using `bpftool`.

### gRPC Protocol (`monitor.proto`)

Shared protocol definition in `Monitor Data Pipeline/Utils/monitor.proto`:
- `ComputeNodeSnapshot` - Complete snapshot with timestamp, node_id, GPU state, process list
- `ProcessMetrics` - Per-process metrics (PID, UID, command, CPU%, memory, GPU metrics)
- `MonitorService.SendSnapshot()` - RPC for sending snapshots

The C++ client and Python server both generate code from this single source of truth.

### Collect Agent Architecture

**Location:** `Monitor Data Pipeline/Collect Agent/`

Both gRPC and MQTT servers share a common `MonitoringDataCollector` class for processing:

**gRPC Server** (`gRPC/server.py`)
- Listens on configured port (default: 50051)
- Receives Protobuf messages via RPC calls
- Converts protobuf to Python dict for processing

**MQTT Server** (`MQTT/server.py`)
- Connects to MQTT broker (default: localhost:1883)
- Subscribes to configured topic (default: monitoring/compute-node)
- Receives JSON messages via pub/sub
- Parses JSON for processing

Both display: snapshot metadata, GPU state, top 10 CPU processes, and statistics.

### Configuration System

`infra.json` (repository root) contains all configuration:

**Transport Configuration:**
- `grpc_server.address` - Server endpoint (default: localhost:50051)
- `mqtt_broker.address` - MQTT broker host (default: localhost)
- `mqtt_broker.port` - MQTT broker port (default: 1883)
- `mqtt_broker.topic` - MQTT topic (default: monitoring/compute-node)
- `mqtt_broker.qos` - MQTT quality of service (default: 1)
- `transport.enable_grpc` - Enable/disable gRPC transport
- `transport.enable_mqtt` - Enable/disable MQTT transport

**Monitoring Configuration:**
- `compute_nodes[]` - Node identifiers and hostnames
- `monitoring.snapshot_interval_seconds` - Collection frequency
- `monitoring.enable_gpu` - GPU monitoring toggle
- `monitoring.use_simulated_data` - Use fake data (true) or real eBPF (false)

Both compute node agent and collect agent servers read this config at startup.

### Data Flow

1. Compute node agent collects metrics from eBPF programs + GPU parsing
2. Aggregates into `ComputeNodeSnapshotInternal` structure
3. Converts to protobuf `ComputeNodeSnapshot` message
4. Sends via gRPC to collection server (port 50051)
5. Collection server receives and can forward to streaming pipeline

## Important Technical Notes

- **Root privileges required**: eBPF programs require sudo/root to load
- **Kernel compatibility**: Requires kernel with BTF support and eBPF enabled
- **GPU monitoring**: Uses `nvidia-smi` parsing, only works with NVIDIA GPUs
- **Build dependencies**: The Makefile handles protobuf generation, eBPF compilation, and skeleton generation automatically
- **Error handling**: Agent continues local monitoring if gRPC connection fails
- **Process filtering**: Monitors all processes system-wide, aggregates by PID
