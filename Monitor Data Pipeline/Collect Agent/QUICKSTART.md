# Quick Start Guide - Collect Agent

## ✅ Issue Fixed

Your setup completed successfully! The issue was that you need to **activate the virtual environment** before running the server scripts.

## 📋 Correct Startup Procedure

### Option 1: Step by Step

```bash
# 1. Navigate to Collect Agent directory
cd "Monitor Data Pipeline/Collect Agent"

# 2. Activate virtual environment
source venv/bin/activate

# 3. Generate protobuf code (first time only)
./generate_proto.sh

# 4. Run a server
python3 run_grpc_server.py --mock-kafka
# OR
python3 run_mqtt_server.py --mock-kafka
```

### Option 2: One-Liner

```bash
cd "Monitor Data Pipeline/Collect Agent" && source venv/bin/activate && python3 run_grpc_server.py --mock-kafka
```

## 🔍 What Was the Problem?

Your setup log shows:
```
✓ All dependencies installed  # ← Dependencies installed in venv/
```

But when you ran:
```bash
python3 run_grpc_server.py  # ← Used system Python, not venv Python!
```

**Result:** System Python couldn't find the packages because they're in `venv/`, not in your system Python.

## ✅ Updated Files

### 1. `.gitignore` - Now Excludes Python Files

Added comprehensive Python ignores:
- `venv/`, `env/`, `.venv/` - Virtual environments
- `__pycache__/`, `*.pyc` - Python bytecode
- `*_pb2.py`, `*_pb2_grpc.py` - Generated protobuf files
- And many more Python-specific patterns

### 2. Launcher Scripts - Now Check for venv

Both `run_grpc_server.py` and `run_mqtt_server.py` now check if venv is activated:

```bash
# If you forget to activate venv, you'll see:
================================================================================
  ERROR: Virtual Environment Not Activated
================================================================================

You must activate the virtual environment before running this script.

Steps:
  1. cd 'Monitor Data Pipeline/Collect Agent'
  2. source venv/bin/activate
  3. python3 run_grpc_server.py
```

## 🎯 Complete Test Run

Here's how to test the complete pipeline:

### Terminal 1: Start gRPC Server (with mock Kafka)

```bash
cd "Monitor Data Pipeline/Collect Agent"
source venv/bin/activate
./generate_proto.sh  # First time only
python3 run_grpc_server.py --mock-kafka
```

Expected output:
```
================================================================================
  gRPC Monitoring Collection Server
================================================================================

[2025-12-06 00:10:00] [__main__] [INFO] ✓ Loaded configuration from ../../infra.json
[2025-12-06 00:10:00] [__main__] [INFO] Configuration:
[2025-12-06 00:10:00] [__main__] [INFO]   gRPC: 0.0.0.0:50051
[2025-12-06 00:10:00] [__main__] [INFO]   Kafka: ['localhost:9093']
[2025-12-06 00:10:00] [__main__] [INFO]   Topic: raw_data
[2025-12-06 00:10:00] [__main__] [INFO]   Mock Kafka: True

[2025-12-06 00:10:00] [__main__] [INFO] [1/3] Initializing DataProcessor...
[2025-12-06 00:10:00] [processing.processor] [INFO] DataProcessor initialized with config: {...}
[2025-12-06 00:10:00] [__main__] [INFO] ✓ DataProcessor ready

[2025-12-06 00:10:00] [__main__] [INFO] [2/3] Initializing KafkaPublisher...
[2025-12-06 00:10:00] [__main__] [INFO] Using MockKafkaPublisher (no real Kafka)
[2025-12-06 00:10:00] [publishing.kafka_publisher] [INFO] ✓ MockKafkaPublisher initialized
[2025-12-06 00:10:00] [__main__] [INFO] ✓ KafkaPublisher ready

[2025-12-06 00:10:00] [__main__] [INFO] [3/3] Initializing gRPC Server...
[2025-12-06 00:10:00] [__main__] [INFO] ✓ gRPC Server listening on port 50051

================================================================================
  Server ready - waiting for compute node connections...
  Press Ctrl+C to stop
================================================================================
```

### Terminal 2: Send Test Data

```bash
cd "Monitor Data Pipeline/Compute Node Agent"

# Build and run sample client
make sample
./sample_grpc_monitor
```

## 🔧 Common Commands Reference

### Virtual Environment

```bash
# Activate (always do this first!)
source venv/bin/activate

# Deactivate (when done)
deactivate

# Check if activated
which python3  # Should show: .../venv/bin/python3
```

### Protobuf Code Generation

```bash
# Only needed for gRPC server, only once (or when .proto changes)
source venv/bin/activate
./generate_proto.sh
```

### Running Servers

```bash
# Always activate venv first!
source venv/bin/activate

# gRPC Server
python3 run_grpc_server.py --mock-kafka          # Test mode
python3 run_grpc_server.py --port 50052          # Custom port
python3 run_grpc_server.py                        # With real Kafka

# MQTT Server
python3 run_mqtt_server.py --mock-kafka          # Test mode
python3 run_mqtt_server.py --topic my/topic      # Custom topic
python3 run_mqtt_server.py                        # With real Kafka
```

### Viewing Installed Packages

```bash
source venv/bin/activate
pip list

# Should show:
# grpcio          1.76.0
# grpcio-tools    1.76.0
# protobuf        6.33.1
# paho-mqtt       2.1.0
# kafka-python    2.3.0
# colorlog        6.10.1
# ...
```

## 📝 Pro Tips

### 1. Add to Shell Profile for Auto-Activation

Add this to your `~/.zshrc` or `~/.bashrc`:

```bash
# Auto-activate venv when entering Collect Agent directory
cd_auto_venv() {
    if [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
    fi
}
alias cda='cd "/path/to/Monitor Data Pipeline/Collect Agent" && cd_auto_venv'
```

Then just type `cda` to go there and auto-activate!

### 2. Create Convenience Aliases

```bash
# In ~/.zshrc or ~/.bashrc
alias collect-grpc='cd "/path/to/Collect Agent" && source venv/bin/activate && python3 run_grpc_server.py --mock-kafka'
alias collect-mqtt='cd "/path/to/Collect Agent" && source venv/bin/activate && python3 run_mqtt_server.py --mock-kafka'
```

### 3. Use Screen or Tmux for Persistent Sessions

```bash
# Start a named screen session
screen -S collect-agent

# Activate venv and run server
cd "Monitor Data Pipeline/Collect Agent"
source venv/bin/activate
python3 run_grpc_server.py

# Detach: Ctrl+A, then D
# Reattach: screen -r collect-agent
```

## 🎓 Understanding Virtual Environments

### Why Virtual Environments?

- **Isolation**: Each project has its own packages
- **No conflicts**: Different projects can use different package versions
- **Clean system**: Doesn't pollute system Python
- **Reproducible**: `requirements.txt` ensures same versions everywhere

### Visual Explanation

```
System Python:           Virtual Environment (venv):
/usr/bin/python3        ./venv/bin/python3
├── pip                 ├── pip (newer)
├── setuptools          ├── setuptools
└── (basic packages)    ├── grpcio ✓
                        ├── paho-mqtt ✓
                        ├── kafka-python ✓
                        └── colorlog ✓
```

When you run:
- `python3 script.py` WITHOUT activation → Uses system Python → ❌ Packages not found
- `python3 script.py` WITH activation → Uses venv Python → ✅ All packages available

## 📚 Next Steps

1. **Test the pipeline end-to-end:**
   - Start gRPC server (Terminal 1)
   - Run sample client (Terminal 2)
   - Verify data flow

2. **Set up Kafka for production:**
   - Start Kafka broker
   - Change `"use_mock": false` in `infra.json`
   - Restart server without `--mock-kafka` flag

3. **Add more compute nodes:**
   - Deploy compute node agent on multiple machines
   - Point them all to the same gRPC/MQTT server
   - See aggregated monitoring data

## ❓ Still Having Issues?

### Check Virtual Environment Status

```bash
# Are you in the venv?
echo $VIRTUAL_ENV  # Should show: /path/to/venv

# Which Python is being used?
which python3      # Should show: /path/to/venv/bin/python3

# Are packages installed?
pip list | grep grpc  # Should show grpcio and grpcio-tools
```

### Regenerate Virtual Environment

If venv is corrupted:

```bash
cd "Monitor Data Pipeline/Collect Agent"
rm -rf venv
./setup.sh
source venv/bin/activate
./generate_proto.sh
```

## 🎉 Summary

**The three magic commands:**
```bash
cd "Monitor Data Pipeline/Collect Agent"    # 1. Go there
source venv/bin/activate                     # 2. Activate venv (crucial!)
python3 run_grpc_server.py --mock-kafka     # 3. Run server
```

Now you're ready to go! 🚀
