# Kafka - Message Broker

This folder contains the docker-compose setup for Apache Kafka with KRaft mode (no Zookeeper) and Kafka UI for web management.

## Quick Start

```bash
# Start Kafka and Kafka UI
docker-compose up -d

# Verify Kafka is running
docker logs kafka

# Access Kafka UI
# Open http://localhost:8081 in browser
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| kafka | 9092 | Kafka broker (PLAINTEXT) |
| kafka | 9093 | Kafka controller |
| kafka-ui | 8081 | Web UI (http://localhost:8081) |

## Configuration

### For Remote Access

If running on a remote server, update `KAFKA_ADVERTISED_LISTENERS` in docker-compose.yaml:

```yaml
KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092,PLAINTEXT_HOST://<YOUR_SERVER_IP>:29092
```

And expose port 29092:
```yaml
ports:
  - "9092:9092"
  - "9093:9093"
  - "29092:29092"  # Add this for external access
```

## Operations

### Create Topic

```bash
docker exec kafka /opt/kafka/bin/kafka-topics.sh \
    --create \
    --topic metrics \
    --bootstrap-server localhost:9092 \
    --partitions 3 \
    --replication-factor 1
```

### List Topics

```bash
docker exec kafka /opt/kafka/bin/kafka-topics.sh \
    --list \
    --bootstrap-server localhost:9092
```

### Describe Topic

```bash
docker exec kafka /opt/kafka/bin/kafka-topics.sh \
    --describe \
    --topic metrics \
    --bootstrap-server localhost:9092
```

### Consume Messages

```bash
# From beginning
docker exec kafka /opt/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server localhost:9092 \
    --topic metrics \
    --from-beginning

# Latest only
docker exec kafka /opt/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server localhost:9092 \
    --topic metrics
```

### Produce Test Message

```bash
docker exec -it kafka /opt/kafka/bin/kafka-console-producer.sh \
    --bootstrap-server localhost:9092 \
    --topic metrics
```

### Check Consumer Groups

```bash
docker exec kafka /opt/kafka/bin/kafka-consumer-groups.sh \
    --bootstrap-server localhost:9092 \
    --list
```

## Kafka UI Features

Access at http://localhost:8081

- **Dashboard**: Overview of cluster health
- **Brokers**: View broker status and configuration
- **Topics**: Create, view, and manage topics
- **Consumers**: Monitor consumer groups and lag
- **Messages**: Browse and search messages in topics
- **Schema Registry**: (if configured) Manage schemas

## Shutdown

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (delete all data)
docker-compose down -v
```

## Troubleshooting

### Kafka not starting

```bash
# Check logs
docker logs kafka

# Common issues:
# - Port 9092 already in use
# - Insufficient memory (Kafka needs ~1GB)
```

### Cannot connect from external host

1. Update `KAFKA_ADVERTISED_LISTENERS` with server IP
2. Expose port 29092
3. Check firewall allows the port

### Kafka UI cannot connect

```bash
# Verify Kafka is healthy
docker exec kafka /opt/kafka/bin/kafka-broker-api-versions.sh \
    --bootstrap-server localhost:9092

# Check network
docker network ls
docker network inspect kafka_kafka-network
```
