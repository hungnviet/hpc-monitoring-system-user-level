# Kafka Streaming Service

This directory contains the Kafka setup for the monitoring data pipeline using Docker Compose.

## Architecture

```
┌─────────────────┐
│   Zookeeper     │  Port 2181 - Coordination service
└────────┬────────┘
         │
┌────────▼────────┐
│   Kafka Broker  │  Port 9092 (internal), 9093 (external)
└────────┬────────┘
         │
         ├─► raw_data topic (3 partitions)
         │
┌────────▼────────┐
│   Kafka UI      │  Port 8080 - Web interface
└─────────────────┘
```

## Prerequisites

- Docker and Docker Compose installed
- Ports available: 2181, 9092, 9093, 8080

## Quick Start

### 1. Start Kafka

```bash
cd "Monitor Data Pipeline/Streaming Section/Kafka"
docker-compose up -d
```

This will start:
- **Zookeeper** on port 2181
- **Kafka** on ports 9092 (internal) and 9093 (external/localhost)
- **Kafka UI** on port 8080
- **kafka-init** container that creates the `raw_data` topic

### 2. Check Status

```bash
# Check all containers are running
docker-compose ps

# View logs
docker-compose logs -f kafka

# Check if topic was created
docker-compose exec kafka kafka-topics --list --bootstrap-server localhost:9092
```

### 3. Access Kafka UI

Open your browser: http://localhost:8080

You can:
- View topics
- See messages
- Monitor consumer groups
- Inspect topic configurations

### 4. Stop Kafka

```bash
docker-compose down
```

To also remove volumes (data):
```bash
docker-compose down -v
```

## Topic Configuration

### raw_data Topic

- **Partitions**: 3 (for parallel processing)
- **Replication Factor**: 1 (single broker)
- **Retention**: 7 days (604800000 ms)
- **Compression**: gzip

This topic receives monitoring snapshots from the Collect Agent.

## Manual Topic Management

### List Topics

```bash
docker-compose exec kafka kafka-topics --list \
  --bootstrap-server localhost:9092
```

### Describe Topic

```bash
docker-compose exec kafka kafka-topics --describe \
  --topic raw_data \
  --bootstrap-server localhost:9092
```

## Testing Kafka

### Consume Messages from raw_data

```bash
docker-compose exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic raw_data \
  --from-beginning \
  --property print.key=true \
  --property print.timestamp=true
```

This will show all messages published to the `raw_data` topic.

## Configuration

### Connection from Collect Agent

The Collect Agent uses:
- **Bootstrap servers**: `localhost:9093`
- **Topic**: `raw_data`

Configured in `infra.json`:

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

### Port Explanation

- **9092**: Internal Docker network (kafka:9092)
- **9093**: External localhost (localhost:9093)
- **2181**: Zookeeper
- **8080**: Kafka UI

## Kafka UI Dashboard

Visit http://localhost:8080 to:
- View topics and messages
- Monitor consumer groups
- See broker health
- Inspect configurations

## Troubleshooting

### Check if Kafka is running

```bash
docker-compose ps
```

All services should show "Up".

### View Kafka logs

```bash
docker-compose logs -f kafka
```

### Restart Kafka

```bash
docker-compose restart
```

### Clean and restart

```bash
docker-compose down -v
docker-compose up -d
```
