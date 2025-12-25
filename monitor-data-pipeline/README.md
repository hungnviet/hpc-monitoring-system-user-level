## Testing

1. Start etcd: `cd ../coordinator && docker-compose up -d`
2. Configure etcd: `./setup-etcd.sh`
3. Start this server: `python3 simple-server.py`
4. Start agent: `cd ../compute-node-agent && sudo python3 main.py`
5. Enable collection: `docker exec etcd-server etcdctl put /config/compute_node/node_id_1/status running`
