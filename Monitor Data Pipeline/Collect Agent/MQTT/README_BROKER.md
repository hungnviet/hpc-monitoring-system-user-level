# MQTT Broker Setup Guide

This guide explains how to set up and use the Mosquitto MQTT broker using Docker Compose for the Collect Agent.

## Why Docker?

Using Docker Compose for the MQTT broker provides:
- ✅ **Cross-platform**: Works on macOS, Linux, Windows
- ✅ **Isolated**: Doesn't interfere with system packages
- ✅ **Reproducible**: Same setup everywhere
- ✅ **Easy to manage**: Simple start/stop/restart commands
- ✅ **No installation hassle**: No brew/apt-get required

## Prerequisites

### Install Docker

If you don't have Docker installed:

**macOS:**
```bash
# Download from: https://www.docker.com/products/docker-desktop
# Or using Homebrew:
brew install --cask docker
```

**Linux:**
```bash
# Ubuntu/Debian:
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker
```

**Windows:**
- Download Docker Desktop from https://www.docker.com/products/docker-desktop
- Run installer and restart

### Verify Docker Installation

```bash
docker --version
docker compose version
```

## Quick Start

### Option 1: Using the Control Script (Recommended)

We provide a convenient shell script to manage the MQTT broker:

```bash
cd "Monitor Data Pipeline/Collect Agent"

# Start the broker
./mqtt-broker.sh start

# View logs
./mqtt-broker.sh logs

# Check status
./mqtt-broker.sh status

# Stop the broker
./mqtt-broker.sh stop
```

### Option 2: Using Docker Compose Directly

```bash
cd "Monitor Data Pipeline/Collect Agent"

# Start the broker
docker compose -f docker-compose.mqtt.yml up -d

# View logs
docker compose -f docker-compose.mqtt.yml logs -f

# Stop the broker
docker compose -f docker-compose.mqtt.yml down
```

## Complete Setup Instructions

### Step 1: Start MQTT Broker

```bash
cd "Monitor Data Pipeline/Collect Agent"

# Start Mosquitto broker
./mqtt-broker.sh start
```

**Expected output:**
```
Starting MQTT Broker (Mosquitto)...
[+] Running 2/2
 ✔ Network monitoring-network  Created
 ✔ Container mqtt-broker       Started

✓ MQTT Broker started successfully

Connection details:
  Host: localhost
  Port: 1883 (MQTT)
  Port: 9001 (WebSocket)
```

### Step 2: Verify Broker is Running

```bash
# Check status
./mqtt-broker.sh status

# Or check Docker directly
docker ps | grep mqtt-broker
```

### Step 3: Start MQTT Collect Agent

```bash
# Activate virtual environment
source venv/bin/activate

# Start MQTT server
python3 run_mqtt_server.py --mock-kafka
```

**Expected output:**
```
[2025-12-06 00:16:57] [MQTT.server] [INFO] ✓ Connected to MQTT broker at localhost:1883
[2025-12-06 00:16:57] [MQTT.server] [INFO] Subscribing to topic: monitoring/compute-node
[2025-12-06 00:16:57] [MQTT.server] [INFO] ✓ Subscribed successfully
```

## Testing the MQTT Broker

### Test 1: Publish a Test Message

```bash
# Publish directly using mosquitto_pub in the container
docker exec mqtt-broker mosquitto_pub \
  -t monitoring/compute-node \
  -m '{"test": "message", "timestamp": 1234567890}'
```

Your MQTT server should receive and log this message!

### Test 2: Subscribe to All Topics

```bash
# Subscribe to all topics to see what's being published
docker exec mqtt-broker mosquitto_sub -t '#' -v
```

### Test 3: Check Broker Statistics

```bash
# View broker system information
docker exec mqtt-broker mosquitto_sub -t '$SYS/#' -C 10
```

## Control Script Commands

The `mqtt-broker.sh` script provides convenient management:

### Start Broker
```bash
./mqtt-broker.sh start
```

### Stop Broker
```bash
./mqtt-broker.sh stop
```

### Restart Broker
```bash
./mqtt-broker.sh restart
```

### View Status
```bash
./mqtt-broker.sh status
```

**Output:**
```
MQTT Broker Status:

NAME           IMAGE                    STATUS          PORTS
mqtt-broker    eclipse-mosquitto:2.0    Up 5 minutes    0.0.0.0:1883->1883/tcp

✓ Broker is running

Connection test:
mosquitto version 2.0.18
```

### View Logs (Live)
```bash
./mqtt-broker.sh logs
```

Press `Ctrl+C` to stop viewing logs.

### Clean All Data
```bash
./mqtt-broker.sh clean
```

**Warning:** This deletes all stored messages and logs!

## Configuration

### Mosquitto Configuration File

Location: `mosquitto/config/mosquitto.conf`

Key settings:

```conf
# MQTT TCP listener
listener 1883
protocol mqtt

# MQTT WebSocket listener
listener 9001
protocol websockets

# Allow anonymous connections (development only!)
allow_anonymous true

# Persistence
persistence true
persistence_location /mosquitto/data/

# Max message size (100 MB)
message_size_limit 104857600
```

### Customizing Configuration

1. Edit `mosquitto/config/mosquitto.conf`
2. Restart the broker:
   ```bash
   ./mqtt-broker.sh restart
   ```

### Production Configuration

For production, you should:

1. **Enable Authentication:**
   ```conf
   allow_anonymous false
   password_file /mosquitto/config/passwd
   ```

2. **Enable TLS/SSL:**
   ```conf
   listener 8883
   cafile /mosquitto/config/ca.crt
   certfile /mosquitto/config/server.crt
   keyfile /mosquitto/config/server.key
   ```

3. **Restrict Connections:**
   ```conf
   bind_address 192.168.1.100
   ```

## Directory Structure

```
Collect Agent/
├── docker-compose.mqtt.yml     # Docker Compose configuration
├── mqtt-broker.sh              # Control script
└── mosquitto/
    ├── config/
    │   └── mosquitto.conf      # Mosquitto configuration
    ├── data/                   # Persistent data (gitignored)
    └── log/                    # Log files (gitignored)
```

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 1883 | MQTT TCP | Standard MQTT connections |
| 9001 | WebSocket | MQTT over WebSockets (for web clients) |

To change ports, edit `docker-compose.mqtt.yml`:

```yaml
ports:
  - "1883:1883"  # Change left side: "HOST:CONTAINER"
  - "9001:9001"
```

## Troubleshooting

### Error: "Cannot connect to the Docker daemon"

**Solution:** Start Docker Desktop or Docker service
```bash
# macOS: Start Docker Desktop app

# Linux:
sudo systemctl start docker
```

### Error: "Port 1883 is already in use"

**Solution:** Another MQTT broker is running
```bash
# Find what's using port 1883
lsof -i :1883

# If it's Mosquitto installed via brew:
brew services stop mosquitto

# Then start Docker version:
./mqtt-broker.sh start
```

### Error: "Connection refused" from MQTT server

**Solutions:**

1. Check if broker is running:
   ```bash
   ./mqtt-broker.sh status
   ```

2. Check broker logs:
   ```bash
   ./mqtt-broker.sh logs
   ```

3. Restart broker:
   ```bash
   ./mqtt-broker.sh restart
   ```

### Broker Won't Start

Check Docker logs:
```bash
docker compose -f docker-compose.mqtt.yml logs
```

Common issues:
- Port already in use
- Permission issues with data/log directories
- Invalid configuration in `mosquitto.conf`

## Performance Tuning

### Adjust Resources

Edit `docker-compose.mqtt.yml` to add resource limits:

```yaml
services:
  mosquitto:
    # ... existing config ...
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
```

### Monitor Performance

```bash
# Container stats
docker stats mqtt-broker

# Check connections
docker exec mqtt-broker mosquitto_sub -t '$SYS/broker/clients/connected' -C 1
```

## Multi-Machine Setup

### Server Machine (Runs Broker)

```bash
# 1. Update mosquitto.conf to listen on all interfaces
bind_address 0.0.0.0

# 2. Start broker
./mqtt-broker.sh start

# 3. Note the server's IP address
ip addr show  # Linux
ifconfig      # macOS
```

### Client Machines (Run Compute Nodes)

Update `infra.json` on each client:

```json
{
  "mqtt_broker": {
    "address": "192.168.1.100",  # Server IP
    "port": 1883,
    "topic": "monitoring/compute-node"
  }
}
```

**Security Note:** For production, use TLS/SSL and authentication!

## Advanced Topics

### Bridge Multiple Brokers

Edit `mosquitto.conf`:

```conf
connection bridge-to-main
address main-broker:1883
topic # both 0
```

### Enable WebSocket for Web Clients

Already enabled on port 9001! Test with:

```javascript
// JavaScript MQTT client
const client = mqtt.connect('ws://localhost:9001');
```

### Enable MQTT v5 Features

Add to `mosquitto.conf`:

```conf
# Enable MQTT v5
protocol mqtt
```

## Summary

```bash
# Quick reference commands:

# Start broker
./mqtt-broker.sh start

# Start MQTT server
source venv/bin/activate
python3 run_mqtt_server.py --mock-kafka

# Test publish
docker exec mqtt-broker mosquitto_pub -t monitoring/compute-node -m '{"test": true}'

# View logs
./mqtt-broker.sh logs

# Stop broker
./mqtt-broker.sh stop
```

## Related Documentation

- **Collect Agent README**: `README.md`
- **Quick Start Guide**: `QUICKSTART.md`
- **Docker Compose File**: `docker-compose.mqtt.yml`
- **Mosquitto Docs**: https://mosquitto.org/documentation/

## License

See repository root for license information.
