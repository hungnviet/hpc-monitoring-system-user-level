# Makefile for memleak eBPF monitoring tool

CXX = g++
CLANG = clang
BPFTOOL = bpftool
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
LDFLAGS = -L/usr/lib64 -lbpf -lelf -lz

# Default target
.PHONY: all
all: $(TARGET)

# Check required tools
.PHONY: check-tools
check-tools:
	@command -v $(CLANG) >/dev/null 2>&1 || (echo "Error: clang not found" && exit 1)
	@command -v $(BPFTOOL) >/dev/null 2>&1 || (echo "Error: bpftool not found" && exit 1)
	@command -v $(CXX) >/dev/null 2>&1 || (echo "Error: g++ not found" && exit 1)
	@test -f /sys/kernel/btf/vmlinux || (echo "Error: /sys/kernel/btf/vmlinux not found. Kernel BTF support required." && exit 1)
	@test -f /usr/lib64/libbpf.so.1 -o -f /usr/lib64/libbpf.so || (echo "Error: libbpf runtime not found" && exit 1)
	@echo "All tools verified!"

# Generate vmlinux.h from kernel BTF
$(VMLINUX_H): check-tools
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
	@echo "Installing dependencies for Rocky Linux..."
	@sudo dnf install -y clang llvm libbpf elfutils-libelf-devel kernel-devel perf elfutils-devel gcc gcc-c++
	@echo "Done! Run 'make check-tools' to verify."

# Run the program (requires root)
.PHONY: run
run: $(TARGET)
	@echo "Running $(TARGET) (requires root)..."
	@echo "Usage: sudo ./$(TARGET) -p <PID>  OR  sudo ./$(TARGET) -a"

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all          - Build the application (default)"
	@echo "  check-tools  - Verify required tools are installed"
	@echo "  install-deps - Install build dependencies (Rocky Linux)"
	@echo "  run          - Show usage"
	@echo "  clean        - Remove all generated files"
	@echo "  help         - Show this help message"