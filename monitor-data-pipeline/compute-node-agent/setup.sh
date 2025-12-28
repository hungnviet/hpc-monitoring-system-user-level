#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Compute Node Agent Setup ==="

# Check if BCC is installed
if ! python3 -c "from bcc import BPF" 2>/dev/null; then
    echo "ERROR: BCC is not installed as a system package."
    echo "Please install it first:"
    echo "  Ubuntu/Debian: sudo apt-get install python3-bpfcc bpfcc-tools"
    echo "  CentOS/RHEL:   sudo yum install python3-bcc bcc-tools"
    echo "  Fedora:        sudo dnf install python3-bcc bcc-tools"
    exit 1
fi
echo "[OK] BCC is installed"

# Remove old venv if exists
if [ -d ".venv" ]; then
    echo "Removing existing virtual environment..."
    rm -rf .venv
fi

# Create venv with system site-packages (for BCC access)
echo "Creating virtual environment with system site-packages..."
python3 -m venv .venv --system-site-packages

# Install dependencies into the venv
echo "Installing Python dependencies..."
.venv/bin/pip install --upgrade pip
.venv/bin/pip install --ignore-installed grpcio grpcio-tools protobuf etcd3-py pynvml typing-extensions

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To run the agent:"
echo "  sudo $SCRIPT_DIR/.venv/bin/python $SCRIPT_DIR/main.py"
echo ""
echo "Or use the run script:"
echo "  sudo ./run.sh"
