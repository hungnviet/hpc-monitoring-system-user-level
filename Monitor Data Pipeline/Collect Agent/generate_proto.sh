#!/bin/bash
# Generate protobuf and gRPC code for Python
# This script generates Python code from monitor.proto

set -e  # Exit on error

echo "========================================"
echo "  Protobuf Code Generation"
echo "========================================"
echo ""

# Check if virtual environment is activated
if [ -z "$VIRTUAL_ENV" ]; then
    echo "Warning: Virtual environment not activated"
    echo "Activating venv..."
    if [ -d "venv" ]; then
        source venv/bin/activate
        echo "✓ Virtual environment activated"
    else
        echo "Error: Virtual environment not found"
        echo "Run ./setup.sh first to create the virtual environment"
        exit 1
    fi
fi
echo ""

# Locate proto file
PROTO_FILE="../Utils/monitor.proto"
OUTPUT_DIR="gRPC/generated"

if [ ! -f "$PROTO_FILE" ]; then
    echo "Error: monitor.proto not found at $PROTO_FILE"
    exit 1
fi

echo "Proto file: $PROTO_FILE"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Create output directory
echo "[1/2] Creating output directory..."
mkdir -p "$OUTPUT_DIR"
touch "$OUTPUT_DIR/__init__.py"
echo "✓ Output directory ready"
echo ""

# Generate Python code
echo "[2/2] Generating Python code from protobuf..."
python3 -m grpc_tools.protoc \
    -I ../Utils \
    --python_out="$OUTPUT_DIR" \
    --grpc_python_out="$OUTPUT_DIR" \
    "$PROTO_FILE"

if [ $? -eq 0 ]; then
    echo "✓ Protobuf code generated successfully"
    echo ""
    echo "Generated files:"
    ls -lh "$OUTPUT_DIR"/*.py
else
    echo "✗ Failed to generate protobuf code"
    exit 1
fi

echo ""
echo "========================================"
echo "  Generation Complete!"
echo "========================================"
echo ""
echo "You can now start the gRPC server:"
echo "  python3 run_grpc_server.py"
echo ""
