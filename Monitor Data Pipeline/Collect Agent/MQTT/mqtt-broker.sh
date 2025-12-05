#!/bin/bash
# MQTT Broker Control Script
# Manages the Mosquitto MQTT broker using Docker Compose

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 {start|stop|restart|status|logs|clean}"
    echo ""
    echo "Commands:"
    echo "  start    - Start the MQTT broker"
    echo "  stop     - Stop the MQTT broker"
    echo "  restart  - Restart the MQTT broker"
    echo "  status   - Show broker status"
    echo "  logs     - View broker logs (live)"
    echo "  clean    - Stop and remove broker data (WARNING: deletes all data!)"
    echo ""
    echo "Examples:"
    echo "  $0 start          # Start broker"
    echo "  $0 logs           # View logs"
    echo "  $0 stop           # Stop broker"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: Docker is not installed${NC}"
        echo "Please install Docker from https://www.docker.com/get-started"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        echo -e "${RED}Error: Docker daemon is not running${NC}"
        echo "Please start Docker Desktop or the Docker daemon"
        exit 1
    fi
}

start_broker() {
    echo -e "${GREEN}Starting MQTT Broker (Mosquitto)...${NC}"

    # Create directories if they don't exist
    mkdir -p "$SCRIPT_DIR/mosquitto/data"
    mkdir -p "$SCRIPT_DIR/mosquitto/log"

    docker compose -f "$COMPOSE_FILE" up -d

    echo ""
    echo -e "${GREEN}✓ MQTT Broker started successfully${NC}"
    echo ""
    echo "Connection details:"
    echo "  Host: localhost"
    echo "  Port: 1883 (MQTT)"
    echo "  Port: 9001 (WebSocket)"
    echo ""
    echo "Test connection:"
    echo "  docker exec mqtt-broker mosquitto_sub -t '#' -v"
    echo ""
    echo "View logs:"
    echo "  $0 logs"
}

stop_broker() {
    echo -e "${YELLOW}Stopping MQTT Broker...${NC}"
    docker compose -f "$COMPOSE_FILE" down
    echo -e "${GREEN}✓ MQTT Broker stopped${NC}"
}

restart_broker() {
    echo -e "${YELLOW}Restarting MQTT Broker...${NC}"
    docker compose -f "$COMPOSE_FILE" restart
    echo -e "${GREEN}✓ MQTT Broker restarted${NC}"
}

show_status() {
    echo "MQTT Broker Status:"
    echo ""
    docker compose -f "$COMPOSE_FILE" ps
    echo ""

    if docker ps | grep -q mqtt-broker; then
        echo -e "${GREEN}✓ Broker is running${NC}"
        echo ""
        echo "Connection test:"
        docker exec mqtt-broker mosquitto_sub -t '$SYS/broker/version' -C 1 2>/dev/null || echo "Could not connect to broker"
    else
        echo -e "${RED}✗ Broker is not running${NC}"
        echo ""
        echo "Start it with: $0 start"
    fi
}

view_logs() {
    echo "Viewing MQTT Broker logs (Press Ctrl+C to exit)..."
    echo ""
    docker compose -f "$COMPOSE_FILE" logs -f mosquitto
}

clean_broker() {
    echo -e "${RED}WARNING: This will stop the broker and delete all data!${NC}"
    read -p "Are you sure? (yes/no): " confirm

    if [ "$confirm" = "yes" ]; then
        echo -e "${YELLOW}Stopping and cleaning MQTT Broker...${NC}"
        docker compose -f "$COMPOSE_FILE" down -v
        rm -rf "$SCRIPT_DIR/mosquitto/data"/*
        rm -rf "$SCRIPT_DIR/mosquitto/log"/*
        echo -e "${GREEN}✓ MQTT Broker cleaned${NC}"
    else
        echo "Cancelled"
    fi
}

# Main script
check_docker

case "${1:-}" in
    start)
        start_broker
        ;;
    stop)
        stop_broker
        ;;
    restart)
        restart_broker
        ;;
    status)
        show_status
        ;;
    logs)
        view_logs
        ;;
    clean)
        clean_broker
        ;;
    *)
        print_usage
        exit 1
        ;;
esac
