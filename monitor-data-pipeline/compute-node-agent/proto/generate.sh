#!/bin/bash
# Script to generate Python gRPC code from proto file
#
# Prerequisites:
# pip install grpcio grpcio-tools
#
# Usage:
# cd compute-node-agent/proto
# bash generate.sh

cd "$(dirname "$0")"

python3 -m grpc_tools.protoc \
    -I. \
    --python_out=. \
    --grpc_python_out=. \
    metrics.proto

echo "Generated proto files in compute-node-agent/proto/:"
echo "  - metrics_pb2.py"
echo "  - metrics_pb2_grpc.py"
