#ifndef MEMORY_USAGE_H
#define MEMORY_USAGE_H

#include "types.h"
#include "ebpf/memory-allocation/memleak.skel.h"
#include <map>
#include <memory>

namespace monitor {

class MemoryUsage {
private:
    std::unique_ptr<struct memleak_bpf, decltype(&memleak_bpf__destroy)> skel_;
    bool initialized_;
    
public:
    MemoryUsage();
    ~MemoryUsage() = default;
    
    // Initialize eBPF program (pid = -1 for all processes)
    bool initialize(int target_pid = -1);
    
    // Get current memory allocation for all processes (in bytes)
    std::map<int, uint64_t> getProcessMemoryAllocs();
    
    // Check if initialized
    bool isInitialized() const { return initialized_; }
};

} // namespace monitor

#endif