#ifndef COMPUTE_NODE_USAGE_H
#define COMPUTE_NODE_USAGE_H

#include "types.h"
#include "cpu_usage.h"
#include "memory_usage.h"
#include "gpu_usage.h"
#include <memory>

namespace monitor {

class ComputeNodeUsage {
private:
    std::unique_ptr<CpuUsage> cpu_monitor_;
    std::unique_ptr<MemoryUsage> mem_monitor_;
    std::unique_ptr<GpuUsage> gpu_monitor_;
    bool initialized_;
    
    // Helper functions
    bool processExists(int pid) const;
    uint32_t getUidForPid(int pid) const;
    std::string getCommForPid(int pid) const;
    
public:
    ComputeNodeUsage();
    ~ComputeNodeUsage() = default;
    
    // Initialize all monitors
    bool initialize();
    
    // Collect complete snapshot (internal format)
    ComputeNodeSnapshotInternal collectSnapshot();
    
    // Check initialization status
    bool isInitialized() const { return initialized_; }
};

} // namespace monitor

#endif