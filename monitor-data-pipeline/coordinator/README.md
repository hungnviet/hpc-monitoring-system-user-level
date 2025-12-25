# Coordinator - etcd Server

This folder contains the docker-compose setup for running etcd server.

## Quick Start

```bash
# Start etcd
docker-compose up -d

# Setup configuration
./setup-etcd.sh node_id_1 localhost:50051

# Check status
docker exec etcd-server etcdctl endpoint health

# View configuration
docker exec etcd-server etcdctl get --prefix /config

# Start collection
docker exec etcd-server etcdctl put /config/compute_node/node_id_1/status running

# Stop collection
docker exec etcd-server etcdctl put /config/compute_node/node_id_1/status stopped

# Watch heartbeat
docker exec etcd-server etcdctl watch /nodes/node_id_1/heartbeat

# Stop etcd
docker-compose down
```

## Services

- **etcd**: Port 2379 (client), 2380 (peer)
- **etcdkeeper**: Port 8080 (web UI at http://localhost:8080)
