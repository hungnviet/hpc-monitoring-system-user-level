#include "memory_usage.h"
#include <bpf/bpf.h>
#include <iostream>

namespace monitor {

MemoryUsage::MemoryUsage() 
    : skel_(nullptr, memleak_bpf__destroy), initialized_(false) {}

bool MemoryUsage::initialize(int target_pid) {
    // Open BPF skeleton
    struct memleak_bpf* raw_skel = memleak_bpf__open();
    if (!raw_skel) {
        std::cerr << "[MemoryUsage] Failed to open BPF skeleton" << std::endl;
        return false;
    }
    skel_.reset(raw_skel);
    
    // Configure target PID (if specified)
    skel_->rodata->target_pid = target_pid;
    
    // Load BPF program
    if (memleak_bpf__load(skel_.get()) != 0) {
        std::cerr << "[MemoryUsage] Failed to load BPF program" << std::endl;
        return false;
    }
    
    // Attach BPF program
    if (memleak_bpf__attach(skel_.get()) != 0) {
        std::cerr << "[MemoryUsage] Failed to attach BPF program" << std::endl;
        return false;
    }
    
    initialized_ = true;
    std::cout << "[MemoryUsage] Initialized successfully" << std::endl;
    return true;
}

std::map<int, uint64_t> MemoryUsage::getProcessMemoryAllocs() {
    std::map<int, uint64_t> result;
    
    if (!initialized_) {
        return result;
    }
    
    int map_fd = bpf_map__fd(skel_->maps.current_allocs);
    if (map_fd < 0) {
        std::cerr << "[MemoryUsage] Invalid map file descriptor" << std::endl;
        return result;
    }
    
    // Read all process memory allocations from BPF map
    pid_t tgid_key = -1, next_tgid_key;
    uint64_t current_bytes;
    
    while (bpf_map_get_next_key(map_fd, &tgid_key, &next_tgid_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_tgid_key, &current_bytes) == 0) {
            if (current_bytes > 0) {
                result[next_tgid_key] = current_bytes;
            }
        }
        tgid_key = next_tgid_key;
    }
    
    return result;
}

} // namespace monitor