#!/bin/bash

PROTO_DIR="../../Utils"
OUTPUT_DIR="generated"

mkdir -p $OUTPUT_DIR

echo "Generating Python gRPC code..."

# Activate conda if available
if [ -f "/usr/local/anaconda/bin/activate" ]; then
    source /usr/local/anaconda/bin/activate
    echo "Using Anaconda Python: $(which python)"
fi

python -m grpc_tools.protoc \
    -I$PROTO_DIR \
    --python_out=$OUTPUT_DIR \
    --grpc_python_out=$OUTPUT_DIR \
    $PROTO_DIR/monitor.proto

if [ $? -eq 0 ]; then
    echo "✓ Generated files in $OUTPUT_DIR/"
    ls -lh $OUTPUT_DIR/
else
    echo "✗ Failed to generate protobuf files"
    exit 1
fi