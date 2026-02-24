#!/bin/bash
# Setup script to configure etcd with initial values for compute nodes and collect agents

set -e

# Usage function
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --node NODE_ID           Configure compute node (default: node_id_1)"
    echo "  --grpc SERVER            gRPC server address (default: localhost:50051)"
    echo "  --window SECONDS         Collection window (default: 5.0)"
    echo "  --heartbeat SECONDS      Heartbeat interval (default: 10.0)"
    echo ""
    echo "  --collect-agent ID       Configure collect agent (default: collect_agent_1)"
    echo "  --kafka BROKERS          Kafka brokers (default: localhost:9092)"
    echo "  --topic TOPIC            Kafka topic (default: metrics)"
    echo "  --port PORT              gRPC port (default: 50051)"
    echo ""
    echo "Examples:"
    echo "  $0                       # Setup both node_id_1 and collect_agent_1 with defaults"
    echo "  $0 --node node_1 --grpc 192.168.1.100:50051"
    echo "  $0 --collect-agent collect_agent_1 --kafka 192.168.1.100:9092"
    echo "  $0 --node node_1 --collect-agent agent_1 --grpc 10.0.0.5:50051 --kafka 10.0.0.10:9092"
}

# Default values
NODE_ID=""
GRPC_SERVER="localhost:50051"
COLLECTION_WINDOW="5.0"
HEARTBEAT_INTERVAL="10.0"

COLLECT_AGENT_ID=""
KAFKA_BROKERS="localhost:9092"
KAFKA_TOPIC="monitoring_metrics"
GRPC_PORT="50051"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --node)
            NODE_ID="$2"
            shift 2
            ;;
        --grpc)
            GRPC_SERVER="$2"
            shift 2
            ;;
        --window)
            COLLECTION_WINDOW="$2"
            shift 2
            ;;
        --heartbeat)
            HEARTBEAT_INTERVAL="$2"
            shift 2
            ;;
        --collect-agent)
            COLLECT_AGENT_ID="$2"
            shift 2
            ;;
        --kafka)
            KAFKA_BROKERS="$2"
            shift 2
            ;;
        --topic)
            KAFKA_TOPIC="$2"
            shift 2
            ;;
        --port)
            GRPC_PORT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Default to both node and collect-agent configuration if nothing specified
if [[ -z "$NODE_ID" && -z "$COLLECT_AGENT_ID" ]]; then
    NODE_ID="node_id_1"
    COLLECT_AGENT_ID="collect_agent_1"
fi

# Wait for etcd to be ready
echo "Waiting for etcd to be ready..."
until docker exec etcd-server etcdctl endpoint health > /dev/null 2>&1; do
    echo "  etcd not ready yet, waiting..."
    sleep 2
done
echo "etcd is ready!"
echo

# Configure compute node
if [[ -n "$NODE_ID" ]]; then
    echo "=========================================="
    echo "Setting up Compute Node configuration"
    echo "=========================================="
    echo "Node ID: $NODE_ID"
    echo "gRPC Server: $GRPC_SERVER"
    echo "Collection Window: ${COLLECTION_WINDOW}s"
    echo "Heartbeat Interval: ${HEARTBEAT_INTERVAL}s"
    echo "=========================================="

    echo "Setting gRPC server address..."
    docker exec etcd-server etcdctl put "/config/compute_node/${NODE_ID}/target_collect_agent" "$GRPC_SERVER"

    echo "Setting collection window..."
    docker exec etcd-server etcdctl put "/config/compute_node/${NODE_ID}/window" "$COLLECTION_WINDOW"

    echo "Setting heartbeat interval..."
    docker exec etcd-server etcdctl put "/config/compute_node/${NODE_ID}/heartbeat_interval" "$HEARTBEAT_INTERVAL"

    echo "Setting initial status to 'stopped'..."
    docker exec etcd-server etcdctl put "/config/compute_node/${NODE_ID}/status" "stopped"

    echo
    echo "Compute Node configuration complete!"
    echo
    echo "Commands:"
    echo "  View config:     docker exec etcd-server etcdctl get --prefix /config/compute_node/${NODE_ID}"
    echo "  Start collection: docker exec etcd-server etcdctl put /config/compute_node/${NODE_ID}/status running"
    echo "  Stop collection:  docker exec etcd-server etcdctl put /config/compute_node/${NODE_ID}/status stopped"
    echo "  Watch heartbeat:  docker exec etcd-server etcdctl watch /nodes/${NODE_ID}/heartbeat"
fi

# Configure collect agent
if [[ -n "$COLLECT_AGENT_ID" ]]; then
    echo "=========================================="
    echo "Setting up Collect Agent configuration"
    echo "=========================================="
    echo "Collect Agent ID: $COLLECT_AGENT_ID"
    echo "Kafka Brokers: $KAFKA_BROKERS"
    echo "Kafka Topic: $KAFKA_TOPIC"
    echo "gRPC Port: $GRPC_PORT"
    echo "=========================================="

    echo "Setting Kafka brokers..."
    docker exec etcd-server etcdctl put "/config/collect_agent/${COLLECT_AGENT_ID}/kafka_brokers" "[\"${KAFKA_BROKERS}\"]"

    echo "Setting Kafka topic..."
    docker exec etcd-server etcdctl put "/config/collect_agent/${COLLECT_AGENT_ID}/kafka_topic" "$KAFKA_TOPIC"

    echo "Setting gRPC port..."
    docker exec etcd-server etcdctl put "/config/collect_agent/${COLLECT_AGENT_ID}/grpc_port" "$GRPC_PORT"

    echo "Setting default threshold rules..."
    docker exec etcd-server etcdctl put "/config/collect_agent/${COLLECT_AGENT_ID}/threshold_rules" '{
        "cpu_usage_percent": {"max": 90},
        "memory_usage_percent": {"max": 85},
        "gpu_max_temperature_celsius": {"max": 85},
        "gpu_max_power_watts": {"max": 300},
        "gpu_max_utilization_percent": {"max": 95}
    }'

    echo
    echo "Collect Agent configuration complete!"
    echo
    echo "Commands:"
    echo "  View config: docker exec etcd-server etcdctl get --prefix /config/collect_agent/${COLLECT_AGENT_ID}"
fi

echo
echo "=========================================="
echo "To view all configuration:"
echo "  docker exec etcd-server etcdctl get --prefix /config"
echo "=========================================="
