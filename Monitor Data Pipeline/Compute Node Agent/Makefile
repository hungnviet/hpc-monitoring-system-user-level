CXX = g++
CLANG = clang
BPFTOOL = /usr/sbin/bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

APP = compute_node_monitor

# Directories
USAGE_DIR = ComputeNodeUsage
GRPC_DIR = Agent/gRPC
UTILS_DIR = ../Utils

# Source files
CPP_SRCS = main.cpp \
	       $(USAGE_DIR)/compute_node_usage.cpp \
	       $(USAGE_DIR)/cpu_usage.cpp \
	       $(USAGE_DIR)/memory_usage.cpp \
	       $(USAGE_DIR)/gpu_usage.cpp \
	       $(GRPC_DIR)/grpc_client.cpp \
	       Agent/MQTT/mqtt_client.cpp

BPF_SRCS = $(USAGE_DIR)/ebpf/cpu-usage/cputime.bpf.c \
	       $(USAGE_DIR)/ebpf/memory-allocation/memleak.bpf.c

# Generated eBPF files
CPUTIME_OBJ = $(USAGE_DIR)/ebpf/cpu-usage/cputime.bpf.o
CPUTIME_SKEL = $(USAGE_DIR)/ebpf/cpu-usage/cputime.skel.h
MEMLEAK_OBJ = $(USAGE_DIR)/ebpf/memory-allocation/memleak.bpf.o
MEMLEAK_SKEL = $(USAGE_DIR)/ebpf/memory-allocation/memleak.skel.h
VMLINUX_H = $(USAGE_DIR)/vmlinux.h

# Generated gRPC files
PROTO_FILE = $(UTILS_DIR)/monitor.proto
PROTO_SRCS = $(GRPC_DIR)/monitor.pb.cc $(GRPC_DIR)/monitor.grpc.pb.cc
PROTO_HDRS = $(GRPC_DIR)/monitor.pb.h $(GRPC_DIR)/monitor.grpc.pb.h

# Build flags
CXXFLAGS = -I. -I$(USAGE_DIR) -I$(USAGE_DIR)/ebpf/cpu-usage -I$(USAGE_DIR)/ebpf/memory-allocation \
	       -I$(GRPC_DIR) -Wall -O2 -std=c++17 -g

CLANG_FLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I$(USAGE_DIR) -I/usr/include

# Use pkg-config to get correct library flags
PKG_CONFIG_LIBS = $(shell pkg-config --libs protobuf grpc++ grpc 2>/dev/null || echo "-lprotobuf -lgrpc++ -lgrpc -lgpr -lupb -lre2 -lz -lcares -laddress_sorting")
MQTT_LIBS = -lpaho-mqttpp3 -lpaho-mqtt3as
LDFLAGS = -lbpf -lelf -lpthread $(PKG_CONFIG_LIBS) $(MQTT_LIBS)

GRPC_CPP_PLUGIN = grpc_cpp_plugin
GRPC_CPP_PLUGIN_PATH ?= $(shell which $(GRPC_CPP_PLUGIN))

TARGET = $(APP)

.PHONY: all clean run install-deps check-libs

all: check-libs $(TARGET)

check-libs:
	@echo "[CHECK] Verifying library availability..."
	@pkg-config --exists protobuf || echo "WARNING: protobuf not found via pkg-config"
	@pkg-config --exists grpc++ || echo "WARNING: grpc++ not found via pkg-config"
	@pkg-config --exists grpc || echo "WARNING: grpc not found via pkg-config"
	@echo "[CHECK] Libraries check complete"

# Generate protobuf and gRPC code
$(PROTO_SRCS) $(PROTO_HDRS): $(PROTO_FILE)
	@echo "[BUILD] Generating protobuf and gRPC code..."
	@mkdir -p $(GRPC_DIR)
	@protoc -I $(UTILS_DIR) --cpp_out=$(GRPC_DIR) --grpc_out=$(GRPC_DIR) \
	    --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN_PATH) $(PROTO_FILE)

# Generate vmlinux.h
$(VMLINUX_H):
	@echo "[BUILD] Generating vmlinux.h..."
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile eBPF programs
$(CPUTIME_OBJ): $(USAGE_DIR)/ebpf/cpu-usage/cputime.bpf.c $(VMLINUX_H)
	@echo "[BUILD] Compiling cputime.bpf.c..."
	@$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(CPUTIME_SKEL): $(CPUTIME_OBJ)
	@echo "[BUILD] Generating cputime skeleton..."
	@$(BPFTOOL) gen skeleton $< > $@

$(MEMLEAK_OBJ): $(USAGE_DIR)/ebpf/memory-allocation/memleak.bpf.c $(VMLINUX_H)
	@echo "[BUILD] Compiling memleak.bpf.c..."
	@$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(MEMLEAK_SKEL): $(MEMLEAK_OBJ)
	@echo "[BUILD] Generating memleak skeleton..."
	@$(BPFTOOL) gen skeleton $< > $@

# Build final executable
$(TARGET): $(CPP_SRCS) $(PROTO_SRCS) $(CPUTIME_SKEL) $(MEMLEAK_SKEL)
	@echo "[BUILD] Building $(TARGET)..."
	@echo "[BUILD] Using LDFLAGS: $(LDFLAGS)"
	@$(CXX) $(CXXFLAGS) $(CPP_SRCS) $(PROTO_SRCS) -o $@ $(LDFLAGS)
	@echo "[BUILD] ✓ Build complete: ./$(TARGET)"

clean:
	@echo "[CLEAN] Removing build artifacts..."
	@rm -f $(TARGET) $(CPUTIME_OBJ) $(CPUTIME_SKEL) $(MEMLEAK_OBJ) $(MEMLEAK_SKEL) $(VMLINUX_H)
	@rm -f $(PROTO_SRCS) $(PROTO_HDRS)
	@echo "[CLEAN] Done"

run: $(TARGET)
	@echo "[RUN] Starting $(TARGET) (requires root)..."
	@sudo ./$(TARGET)

install-deps:
	@echo "[DEPS] Installing dependencies..."
	@sudo apt-get update
	@sudo apt-get install -y \
	    build-essential \
	    clang \
	    libbpf-dev \
	    libelf-dev \
	    linux-headers-$(shell uname -r) \
	    libprotobuf-dev \
	    protobuf-compiler \
	    libgrpc++-dev \
	    libgrpc-dev \
	    protobuf-compiler-grpc \
	    pkg-config \
	    libabsl-dev \
	    libre2-dev \
	    libssl-dev \
	    zlib1g-dev \
	    libc-ares-dev \
	    libpaho-mqtt-dev \
	    libpaho-mqttpp-dev
	@echo "[DEPS] ✓ Dependencies installed"