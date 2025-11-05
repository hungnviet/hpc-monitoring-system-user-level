# Makefile for memleak eBPF monitoring tool

CXX = g++
CLANG = clang
BPFTOOL = /usr/sbin/bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Application name
APP = memleak

# Source files
BPF_SRC = $(APP).bpf.c
USER_SRC = $(APP).cpp
SHARED_H = $(APP).shared.h

# Generated files
VMLINUX_H = vmlinux.h
BPF_OBJ = $(APP).bpf.o
SKEL_H = $(APP).skel.h
TARGET = $(APP)

# Build flags
CXXFLAGS = -I. -Wall -O2 -std=c++14
CLANG_FLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I/usr/include
LDFLAGS = -lbpf -lelf

# Default target
.PHONY: all
all: $(TARGET)

# Check required tools
.PHONY: check-tools, check-tools-debian
check-tools:
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "Error: clang not found"; exit 1; }
	@test -x $(BPFTOOL) || { echo "Error: bpftool not found at $(BPFTOOL)."; exit 1; }
	@command -v $(CXX) >/dev/null 2>&1 || { echo "Error: g++ not found"; exit 1; }
	@test -f /sys/kernel/btf/vmlinux || { echo "Error: /sys/kernel/btf/vmlinux not found. Kernel BTF support required."; exit 1; }
	@test -f /usr/lib64/libbpf.so.1 -o -f /usr/lib64/libbpf.so -o -f /usr/lib/x86_64-linux-gnu/libbpf.so || { echo "Error: libbpf runtime not found"; exit 1; }
	@echo "All tools verified!"

# Check required tools (Debian specific)
check-tools-debian:
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "Error: clang not found"; exit 1; }
	@test -x $(BPFTOOL) || { echo "Error: bpftool not found at $(BPFTOOL) (Debian path)"; exit 1; }
	@command -v $(CXX) >/dev/null 2>&1 || { echo "Error: g++ not found"; exit 1; }
	@test -f /sys/kernel/btf/vmlinux || { echo "Error: /sys/kernel/btf/vmlinux not found. Kernel BTF support required."; exit 1; }
	@test -f /usr/lib/x86_64-linux-gnu/libbpf.so || { echo "Error: libbpf runtime not found at /usr/lib/x86_64-linux-gnu/libbpf.so (Debian path)"; exit 1; }
	@echo "All tools verified! (Debian)"

# Generate vmlinux.h from kernel BTF
$(VMLINUX_H): check-tools-debian
	@echo "  GEN     $@"
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile eBPF program
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H) $(SHARED_H)
	@echo "  CLANG   $< -> $@"
	@$(CLANG) $(CLANG_FLAGS) -c $< -o $@

# Generate BPF skeleton
$(SKEL_H): $(BPF_OBJ)
	@echo "  SKEL    $< -> $@"
	@$(BPFTOOL) gen skeleton $< > $@

# Compile user-space program
$(TARGET): $(USER_SRC) $(SKEL_H) $(SHARED_H)
	@echo "  CXX     $< -> $@"
	@$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)
	@echo "Build complete: ./$(TARGET)"

# Clean all generated files
.PHONY: clean
clean:
	@echo "  CLEAN"
	@rm -f $(TARGET) $(BPF_OBJ) $(SKEL_H) $(VMLINUX_H)

# Install dependencies (Rocky Linux/RHEL)
.PHONY: install-deps
install-deps:
	@echo "Installing dependencies for Rocky Linux (dnf)..."
	sudo dnf install -y clang llvm libbpf elfutils-libelf-devel kernel-devel perf elfutils-devel gcc gcc-c++ bpftool
	@echo "Done! Run 'make check-tools' to verify."

# Install dependencies (Debian/Ubuntu)
.PHONY: install-deps-debian
install-deps-debian:
	@echo "Installing dependencies for Debian/Ubuntu (apt)..."
	sudo apt-get update
	sudo apt-get install -y clang llvm libbpf-dev libelf-dev g++ bpftool
	@echo "Done! Run 'make check-tools-debian' to verify."

# Run the program (requires root)
.PHONY: run
run: $(TARGET)
	@echo "Running $(TARGET) (requires root)..."
	@echo "Usage: sudo ./$(TARGET) -p <PID>  OR  sudo ./$(TARGET) -a"

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all                 - Build the application (default)"
	@echo "  check-tools         - Verify required tools are installed (generic)"
	@echo "  check-tools-debian  - Verify required tools are installed (Debian)"
	@echo "  install-deps        - Install dependencies (Rocky/RHEL/Fedora using dnf)"
	@echo "  install-deps-debian - Install dependencies (Debian/Ubuntu using apt)"
	@echo "  run                 - Build and run with sudo"
	@echo "  run-debian          - Build and run with sudo (Debian alias)"
	@echo "  clean               - Remove all generated files"
	@echo "  help                - Show this help message"