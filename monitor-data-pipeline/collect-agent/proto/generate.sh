#!/bin/bash

cd "$(dirname "$0")"

python3 -m grpc_tools.protoc \
    -I. \
    --python_out=. \
    --grpc_python_out=. \
    metrics.proto

python3 -m grpc_tools.protoc \
    -I. \
    --python_out=. \
    --grpc_python_out=. \
    alerts.proto

echo "Generated proto files in collect-agent/proto/:"
echo "  - metrics_pb2.py"
echo "  - metrics_pb2_grpc.py"
echo "  - alerts_pb2.py"
echo "  - alerts_pb2_grpc.py"
