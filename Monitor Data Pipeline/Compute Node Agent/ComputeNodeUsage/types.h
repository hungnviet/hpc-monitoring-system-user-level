#ifndef TYPES_H
#define TYPES_H

#include <string>
#include <vector>
#include <cstdint>

namespace monitor {

// GPU usage data for a single process (internal use)
struct GpuProcessInfo {
    int pid;
    std::string type;       // G (Graphics) or C (Compute)
    int sm;                 // Streaming Multiprocessor usage %
    int mem;                // Memory controller usage %
    int enc;                // Encoder usage %
    int dec;                // Decoder usage %
    int jpg;                // JPEG engine usage %
    int ofa;                // Optical Flow Accelerator usage %
    std::string command;
    
    GpuProcessInfo() : pid(0), sm(0), mem(0), enc(0), dec(0), jpg(0), ofa(0) {}
};

// Global GPU state (internal use)
struct GpuGlobalStateInternal {
    double power_watts;
    int temperature_celsius;
    int total_load_percent;
    
    GpuGlobalStateInternal() : power_watts(0.0), temperature_celsius(0), total_load_percent(0) {}
};

// Per-process metrics (internal use)
struct ProcessMetricsInternal {
    int pid;
    uint32_t uid;
    std::string command;
    
    // CPU usage as percentage (0-100% per core)
    double cpu_usage_percent;
    
    // Memory in bytes
    uint64_t memory_bytes;
    
    // GPU metrics (percentage 0-100, -1 if not using GPU)
    double gpu_sm_percent;
    double gpu_mem_percent;
    int gpu_mem_mib;        // GPU memory in MiB
    
    ProcessMetricsInternal() 
        : pid(0), uid(0), cpu_usage_percent(0.0), memory_bytes(0),
          gpu_sm_percent(-1.0), gpu_mem_percent(-1.0), gpu_mem_mib(0) {}
};

// Complete snapshot of compute node (internal use)
struct ComputeNodeSnapshotInternal {
    uint64_t timestamp;                              // Unix timestamp in seconds
    GpuGlobalStateInternal gpu_global_state;
    std::vector<ProcessMetricsInternal> processes;
    
    ComputeNodeSnapshotInternal() : timestamp(0) {}
};

} // namespace monitor

#endif