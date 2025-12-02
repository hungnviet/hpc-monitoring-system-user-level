# Testing Guide - Full Pipeline

This guide walks you through testing the complete monitoring pipeline:
**Compute Node Agent → Collect Agent → Kafka**

## Step 1: Start Kafka

### 1.1 Navigate to Kafka directory

```bash
cd "Monitor Data Pipeline/Streaming Section/Kafka"
```

### 1.2 Start Kafka with Docker Compose

```bash
docker-compose up -d
```

This will download and start:
- Zookeeper (port 2181)
- Kafka (ports 9092, 9093)
- Kafka UI (port 8080)
- kafka-init (creates raw_data topic)

**Note:** First run may take 5-10 minutes to download images.

### 1.3 Verify Kafka is running

```bash
# Check containers
docker-compose ps

# Should show 4 containers: zookeeper, kafka, kafka-ui, kafka-init
```

### 1.4 Verify topic was created

```bash
docker-compose exec kafka kafka-topics --list --bootstrap-server localhost:9092
```

You should see: `raw_data`

### 1.5 Open Kafka UI

Open browser: http://localhost:8080

You should see the Kafka UI dashboard with the `raw_data` topic.

## Step 2: Start Collect Agent (gRPC Server)

### 2.1 Open a new terminal

### 2.2 Install Python dependencies (if not done)

```bash
cd "Monitor Data Pipeline/Collect Agent"
pip install -r requirements.txt
```

### 2.3 Start gRPC server

```bash
cd "Monitor Data Pipeline/Collect Agent/gRPC"
python server.py
```

You should see:
```
================================================================================
gRPC Monitoring Server (Modular Architecture)
================================================================================
gRPC Configuration: 0.0.0.0:50051
Kafka Configuration: {'use_mock': False, 'bootstrap_servers': ['localhost:9093'], ...}

[1/3] Initializing DataProcessor...
✓ DataProcessor ready

[2/3] Initializing KafkaPublisher...
✓ Connected to Kafka successfully
✓ KafkaPublisher ready

[3/3] Initializing gRPC Server...
✓ gRPC Server listening on port 50051

================================================================================
Server ready - waiting for compute node connections...
================================================================================
```

**Keep this terminal open!**

## Step 3: Start Compute Node Agent

### 3.1 Open a new terminal

### 3.2 Navigate to Compute Node Agent

```bash
cd "Monitor Data Pipeline/Compute Node Agent"
```

### 3.3 Verify configuration

Check `../../infra.json` has:
```json
{
  "monitoring": {
    "use_simulated_data": true
  },
  "transport": {
    "enable_grpc": true,
    "enable_mqtt": false
  },
  "kafka": {
    "use_mock": false,
    "bootstrap_servers": ["localhost:9093"],
    "topic": "raw_data"
  }
}
```

### 3.4 Run compute node agent (simulated data)

```bash
./compute_node_monitor
```

You should see:
```
========================================
  Compute Node Monitor (Multi-Transport)
========================================

[Config] Node ID: compute-node-01
[Config] Using simulated data: YES
[Config] Transport: gRPC=ON, MQTT=OFF

[GrpcClient] Connecting to localhost:50051...
[GrpcClient] ✓ Connected successfully

[Main] Active transport clients: 1
  - gRPC

=== Snapshot #1 (timestamp: 1701234567) ===
Processes: 15
GPU: 45% @ 67°C, 125.3W
[GrpcClient] ✓ Received snapshot #1 with 15 processes
```

**Keep this terminal open!**

## Step 4: Verify Data Flow

### 4.1 Check Collect Agent logs

In the Collect Agent terminal, you should see:
```
[__main__.GrpcServerAdapter] INFO Received snapshot #1 from compute-node-01 (15 processes)
[processing.processor] INFO Successfully processed snapshot from compute-node-01
[publishing.kafka_publisher] INFO ✓ Published to Kafka: topic=raw_data, partition=0, offset=0, size=2456 bytes
```

### 4.2 Check Kafka messages

#### Option A: Use Kafka Console Consumer

```bash
cd "Monitor Data Pipeline/Streaming Section/Kafka"
docker-compose exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic raw_data \
  --from-beginning \
  --property print.key=true \
  --property print.timestamp=true \
  --max-messages 5
```

You should see JSON messages with monitoring data.

#### Option B: Use Kafka UI

1. Open http://localhost:8080
2. Click on "Topics"
3. Click on "raw_data"
4. Click on "Messages"
5. You should see messages arriving in real-time!

### 4.3 Verify message structure

Each message should contain:
```json
{
  "timestamp": 1701234567,
  "node_id": "compute-node-01",
  "gpu_global_state": {
    "power_watts": 125.3,
    "temperature_celsius": 67,
    "total_load_percent": 45
  },
  "processes": [...],
  "aggregated_metrics": {
    "total_cpu_percent": 123.45,
    "total_memory_gb": 4.56,
    "num_processes": 15
  },
  "top_processes": {
    "by_cpu": [...],
    "by_memory": [...]
  },
  "processing_metadata": {
    "processed_at": "2025-12-02T...",
    "processor_version": "1.0.0"
  }
}
```

## Step 5: Test with MQTT (Optional)

### 5.1 Update infra.json

```json
{
  "transport": {
    "enable_grpc": true,
    "enable_mqtt": true
  }
}
```

### 5.2 Install and start MQTT broker

```bash
# macOS
brew install mosquitto
brew services start mosquitto

# Ubuntu/Debian
sudo apt-get install mosquitto
sudo systemctl start mosquitto
```

### 5.3 Start MQTT Collect Agent server

```bash
cd "Monitor Data Pipeline/Collect Agent/MQTT"
python server.py
```

### 5.4 Restart Compute Node Agent

The agent will now send to both gRPC and MQTT servers!

## Monitoring and Statistics

### Compute Node Agent Statistics

Press Ctrl+C to gracefully stop the agent. You'll see:
```
[Main] Monitor stopped gracefully.

=== Statistics ===
Snapshots collected: 100

gRPC Client:
  - Sent: 100
  - Failed: 0

MQTT Client:
  - Sent: 100
  - Failed: 0
```

### Collect Agent Statistics

Press Ctrl+C to stop the server:
```
=== Statistics ===
Processor: {'processed_count': 100, 'validation_errors': 0, ...}
Publisher: {'published_count': 100, 'failed_count': 0, 'total_mb_sent': 2.45}
```

### Kafka Statistics

```bash
# Check topic size
docker-compose exec kafka kafka-run-class kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 \
  --topic raw_data

# Check consumer lag
docker-compose exec kafka kafka-consumer-groups \
  --bootstrap-server localhost:9092 \
  --list
```

## Architecture Verification

### Full Pipeline Flow

```
┌───────────────────┐
│ Compute Node      │
│ Agent (C++)       │
│ - Simulated data  │
│ - gRPC client     │
└─────────┬─────────┘
          │
          │ Protobuf
          ↓
┌───────────────────┐
│ Collect Agent     │
│ (Python)          │
│ - gRPC server     │
│ - DataProcessor   │
│ - KafkaPublisher  │
└─────────┬─────────┘
          │
          │ JSON
          ↓
┌───────────────────┐
│ Kafka             │
│ (Docker)          │
│ - raw_data topic  │
│ - 3 partitions    │
└───────────────────┘
```

## Troubleshooting

### Kafka won't start

```bash
# Clean and restart
cd "Monitor Data Pipeline/Streaming Section/Kafka"
docker-compose down -v
docker-compose up -d
```

### Collect Agent can't connect to Kafka

1. Check Kafka is running: `docker-compose ps`
2. Check port: `nc -zv localhost 9093`
3. Check logs: `docker-compose logs kafka`
4. Verify infra.json has `"use_mock": false`

### Compute Node Agent can't connect to gRPC server

1. Check gRPC server is running
2. Check port 50051 is not in use: `lsof -i :50051`
3. Check firewall settings

### No messages in Kafka

1. Check Collect Agent logs for errors
2. Check KafkaPublisher is not in mock mode
3. Verify topic name matches: `raw_data`
4. Check Compute Node Agent is sending data

## Performance Testing

### High-frequency data collection

Edit `infra.json`:
```json
{
  "monitoring": {
    "snapshot_interval_seconds": 0.1
  }
}
```

This will send 10 snapshots per second!

### Monitor Kafka throughput

Watch Kafka UI dashboard at http://localhost:8080

### Check resource usage

```bash
# Docker stats
docker stats

# System resources
top
```

## Clean Up

```bash
# Stop Compute Node Agent
Ctrl+C

# Stop Collect Agent
Ctrl+C

# Stop Kafka
cd "Monitor Data Pipeline/Streaming Section/Kafka"
docker-compose down

# Remove all data
docker-compose down -v
```

## Success Criteria

✅ All services start without errors
✅ Compute Node Agent connects to gRPC server
✅ Collect Agent receives and processes snapshots
✅ Messages appear in Kafka raw_data topic
✅ Kafka UI shows messages in real-time
✅ No errors in any logs
✅ Statistics show 100% success rate

## Next Steps

After successful testing:

1. **Add real data collection** - Set `use_simulated_data: false` and run with sudo
2. **Add MQTT transport** - Enable MQTT in config
3. **Add Spark processing** - Consume from Kafka and process
4. **Add monitoring** - Grafana dashboards for metrics
5. **Scale up** - Multiple compute nodes, multiple brokers

Congratulations! Your monitoring pipeline is working! 🎉
