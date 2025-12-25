#!/bin/bash
# Setup script to configure etcd with initial values for testing

set -e

NODE_ID="${1:-node_id_1}"
GRPC_SERVER="${2:-localhost:50051}"
COLLECTION_WINDOW="${3:-5.0}"
HEARTBEAT_INTERVAL="${4:-10.0}"

echo "=========================================="
echo "Setting up etcd configuration"
echo "=========================================="
echo "Node ID: $NODE_ID"
echo "gRPC Server: $GRPC_SERVER"
echo "Collection Window: ${COLLECTION_WINDOW}s"
echo "Heartbeat Interval: ${HEARTBEAT_INTERVAL}s"
echo "=========================================="

# Wait for etcd to be ready
echo "Waiting for etcd to be ready..."
until docker exec etcd-server etcdctl endpoint health > /dev/null 2>&1; do
    echo "  etcd not ready yet, waiting..."
    sleep 2
done
echo "etcd is ready!"
echo

# Set gRPC server address
echo "Setting gRPC server address..."
docker exec etcd-server etcdctl put "/config/compute_node/${NODE_ID}/target_collect_agent" "$GRPC_SERVER"

# Set collection window
echo "Setting collection window..."
docker exec etcd-server etcdctl put "/config/compute_node/${NODE_ID}/window" "$COLLECTION_WINDOW"

# Set heartbeat interval
echo "Setting heartbeat interval..."
docker exec etcd-server etcdctl put "/config/compute_node/${NODE_ID}/heartbeat_interval" "$HEARTBEAT_INTERVAL"

# Set initial status to stopped
echo "Setting initial status to 'stopped'..."
docker exec etcd-server etcdctl put "/config/compute_node/${NODE_ID}/status" "stopped"

echo
echo "=========================================="
echo "Configuration complete!"
echo "=========================================="
echo
echo "To view configuration:"
echo "  docker exec etcd-server etcdctl get --prefix /config/compute_node/${NODE_ID}"
echo
echo "To start collection:"
echo "  docker exec etcd-server etcdctl put /config/compute_node/${NODE_ID}/status running"
echo
echo "To stop collection:"
echo "  docker exec etcd-server etcdctl put /config/compute_node/${NODE_ID}/status stopped"
echo
echo "To watch heartbeat:"
echo "  docker exec etcd-server etcdctl watch /nodes/${NODE_ID}/heartbeat"
echo
echo "To view all keys:"
echo "  docker exec etcd-server etcdctl get --prefix /"
echo "=========================================="
