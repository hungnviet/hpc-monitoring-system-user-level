#ifndef GPU_USAGE_H
#define GPU_USAGE_H

#include "types.h"
#include <map>
#include <string>

namespace monitor {

// Simple struct for GPU process usage (sm and mem percentages)
struct GpuProcessUsage {
    int sm;          // Streaming Multiprocessor usage %
    int mem;         // Memory usage %
    int mem_mib;     // Memory usage in MiB
    
    GpuProcessUsage() : sm(0), mem(0), mem_mib(0) {}
};

class GpuUsage {
private:
    bool initialized_;
    
    // Execute shell command and return output
    std::string executeCommand(const std::string& cmd);
    
public:
    GpuUsage();
    ~GpuUsage() = default;
    
    // Check GPU availability
    bool initialize();
    
    // Get global GPU state (power, temperature, utilization)
    GpuGlobalStateInternal getGlobalState();
    
    // Get GPU usage for all processes
    std::map<int, GpuProcessUsage> getProcessUsage();
    
    // Check if GPU is available
    bool isAvailable() const { return initialized_; }
};

} // namespace monitor

#endif