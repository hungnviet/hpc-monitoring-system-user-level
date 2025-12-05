#!/bin/bash
# Collect Agent - Setup Script
# This script sets up the virtual environment and installs all dependencies

set -e  # Exit on error

echo "========================================"
echo "  Collect Agent Setup"
echo "========================================"
echo ""

# Check Python version
echo "[1/5] Checking Python version..."
python3 --version || { echo "Error: Python 3 is required"; exit 1; }
echo "✓ Python 3 found"
echo ""

# Create virtual environment
echo "[2/5] Creating virtual environment..."
if [ -d "venv" ]; then
    echo "Virtual environment already exists"
    read -p "Do you want to recreate it? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing existing venv..."
        rm -rf venv
        python3 -m venv venv
        echo "✓ Virtual environment created"
    else
        echo "Using existing virtual environment"
    fi
else
    python3 -m venv venv
    echo "✓ Virtual environment created"
fi
echo ""

# Activate virtual environment
echo "[3/5] Activating virtual environment..."
source venv/bin/activate
echo "✓ Virtual environment activated"
echo ""

# Upgrade pip
echo "[4/5] Upgrading pip..."
pip install --upgrade pip
echo "✓ pip upgraded"
echo ""

# Install dependencies
echo "[5/5] Installing dependencies from requirements.txt..."
pip install -r requirements.txt
echo "✓ All dependencies installed"
echo ""

echo "========================================"
echo "  Setup Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Activate the virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  2. Generate protobuf code (if needed):"
echo "     ./generate_proto.sh"
echo ""
echo "  3. Start a server:"
echo "     python3 run_grpc_server.py     # For gRPC"
echo "     python3 run_mqtt_server.py     # For MQTT"
echo ""
