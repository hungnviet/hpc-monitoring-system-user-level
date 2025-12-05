# Collect Agent - Updated Structure

## New Clean Structure

```
Collect Agent/                          # Clean root directory
├── README.md                          # Main documentation
├── QUICKSTART.md                      # Quick start guide
├── STRUCTURE.md                       # This file
├── requirements.txt                   # Python dependencies
├── setup.sh                          # Environment setup
├── generate_proto.sh                 # Protobuf code generator
│
├── run_grpc_server.py                # ✨ gRPC launcher
├── run_mqtt_server.py                # ✨ MQTT launcher (auto-starts broker!)
│
├── venv/                             # Virtual environment (gitignored)
│
├── common/                           # Shared data models
│   ├── __init__.py
│   └── schema.py
│
├── processing/                       # Data processing logic
│   ├── __init__.py
│   └── processor.py
│
├── publishing/                       # Kafka publisher
│   ├── __init__.py
│   └── kafka_publisher.py
│
├── gRPC/                             # gRPC server module
│   ├── server.py
│   ├── requirements.txt
│   └── generated/                    # Generated protobuf code
│       ├── __init__.py
│       ├── monitor_pb2.py
│       └── monitor_pb2_grpc.py
│
└── MQTT/                             # ✨ MQTT module (self-contained!)
    ├── server.py                     # MQTT server adapter
    ├── docker-compose.yml            # ✨ Mosquitto broker config
    ├── mqtt-broker.sh                # ✨ Broker control script
    ├── README_BROKER.md              # ✨ Broker setup guide
    └── mosquitto/                    # ✨ Mosquitto configuration
        ├── config/
        │   └── mosquitto.conf
        ├── data/                     # Persistent data (gitignored)
        └── log/                      # Log files (gitignored)
```

## What Changed?

### Before (Messy Root)
```
Collect Agent/
├── docker-compose.mqtt.yml           # ❌ In root
├── mqtt-broker.sh                    # ❌ In root
├── MQTT_SETUP.md                     # ❌ In root
├── mosquitto/                        # ❌ In root
├── run_grpc_server.py
├── run_mqtt_server.py
├── common/
├── processing/
├── publishing/
├── gRPC/
└── MQTT/
```

### After (Clean Root)
```
Collect Agent/                         # ✅ Clean!
├── run_grpc_server.py                # Core launchers
├── run_mqtt_server.py
├── common/                           # Core modules only
├── processing/
├── publishing/
├── gRPC/
└── MQTT/                             # ✅ All MQTT stuff inside!
    ├── server.py
    ├── docker-compose.yml
    ├── mqtt-broker.sh
    ├── README_BROKER.md
    └── mosquitto/
```

## Key Features

### 1. Auto-Starting MQTT Broker

The `run_mqtt_server.py` script now **automatically checks and starts** the MQTT broker:

```python
# When you run:
python3 run_mqtt_server.py

# It automatically:
# 1. Checks if Docker is available
# 2. Checks if MQTT broker is running
# 3. If not running, starts it automatically
# 4. Then starts the MQTT server
```

**No more manual steps!** Just run the server and everything starts automatically.

### 2. Self-Contained MQTT Module

Everything MQTT-related is now in the `MQTT/` directory:
- Server code
- Docker Compose configuration
- Broker control scripts
- Documentation
- Mosquitto configuration

### 3. Consistent Module Structure

All modules follow the same pattern:
- `gRPC/` - Contains gRPC server + generated protobuf code
- `MQTT/` - Contains MQTT server + broker infrastructure
- `common/` - Shared data models
- `processing/` - Data processing logic
- `publishing/` - Kafka publisher

## How to Use

### Quick Start (Single Command)

```bash
cd "Monitor Data Pipeline/Collect Agent"
source venv/bin/activate
python3 run_mqtt_server.py --mock-kafka
```

That's it! The broker starts automatically.

### What Happens Behind the Scenes

```
1. Check virtual environment ✓
2. Check Docker availability ✓
3. Check if MQTT broker running
   ├─ Already running? → Skip to step 4
   └─ Not running? → Start it automatically
4. Load configuration ✓
5. Initialize DataProcessor ✓
6. Initialize KafkaPublisher ✓
7. Initialize MQTT Server ✓
8. Connect to MQTT Broker ✓
9. Start receiving messages ✓
```

### Manual Broker Control (Optional)

If you need manual control:

```bash
cd MQTT

# Start broker manually
./mqtt-broker.sh start

# Check status
./mqtt-broker.sh status

# View logs
./mqtt-broker.sh logs

# Stop broker
./mqtt-broker.sh stop
```

## Command Reference

### Start MQTT Server (Automatic)

```bash
# The broker starts automatically!
python3 run_mqtt_server.py --mock-kafka
```

Expected output:
```
================================================================================
  MQTT Monitoring Collection Server
================================================================================

[0/4] Checking MQTT Broker...
Starting MQTT broker (Mosquitto)...
✓ MQTT broker started successfully

[1/4] Initializing DataProcessor...
✓ DataProcessor ready

[2/4] Initializing KafkaPublisher...
✓ KafkaPublisher ready

[3/4] Initializing MQTT Server...
✓ MQTT Server ready

[4/4] Connecting to MQTT Broker...
Broker: localhost:1883
Topic: monitoring/compute-node

✓ Connected to MQTT broker at localhost:1883
```

### Start gRPC Server

```bash
# gRPC doesn't need a broker
python3 run_grpc_server.py --mock-kafka
```

## Benefits of New Structure

1. **Cleaner Root Directory**
   - Only essential files in root
   - Easy to find what you need
   - Better organization

2. **Self-Contained Modules**
   - Each module has everything it needs
   - Easy to understand dependencies
   - Easy to deploy separately

3. **Automatic Startup**
   - No manual broker startup
   - Fewer commands to remember
   - Better user experience

4. **Better Version Control**
   - Clear module boundaries
   - Easier to track changes
   - Better .gitignore organization

5. **Cross-Platform Consistency**
   - Same structure on all platforms
   - Docker handles platform differences
   - Reproducible everywhere

## Migration Notes

### Old Commands (Before)

```bash
# Old way (3 separate steps)
./mqtt-broker.sh start
source venv/bin/activate
python3 run_mqtt_server.py
```

### New Commands (After)

```bash
# New way (automatic!)
source venv/bin/activate
python3 run_mqtt_server.py
```

### File Locations Changed

| Old Location | New Location | Reason |
|--------------|--------------|--------|
| `docker-compose.mqtt.yml` | `MQTT/docker-compose.yml` | Module organization |
| `mqtt-broker.sh` | `MQTT/mqtt-broker.sh` | Module organization |
| `MQTT_SETUP.md` | `MQTT/README_BROKER.md` | Module organization |
| `mosquitto/` | `MQTT/mosquitto/` | Module organization |

### No Code Changes Required

If you have existing compute node agents or scripts:
- ✅ No changes needed to clients
- ✅ Same ports (1883, 9001)
- ✅ Same topics
- ✅ Same configuration in `infra.json`

## Troubleshooting

### Broker Won't Start Automatically

Check Docker:
```bash
docker info
# If error: Start Docker Desktop
```

### Manual Override

If automatic startup fails, start manually:
```bash
cd MQTT
./mqtt-broker.sh start
cd ..
python3 run_mqtt_server.py
```

### View Broker Logs

```bash
cd MQTT
./mqtt-broker.sh logs
```

## Summary

The new structure provides:
- ✅ **Cleaner** root directory
- ✅ **Automatic** broker startup
- ✅ **Self-contained** MQTT module
- ✅ **Better** organization
- ✅ **Easier** to use

Just run `python3 run_mqtt_server.py` and everything works! 🚀
