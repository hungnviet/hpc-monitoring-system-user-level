#include "cpu_usage.h"
#include <iostream>
#include <unistd.h>
#include <bpf/libbpf.h>

namespace monitor {

CpuUsage::CpuUsage() : skel_(nullptr), first_sample_(true) {}

CpuUsage::~CpuUsage() {
    cleanup();
}

bool CpuUsage::initialize() {
    skel_ = cputime_bpf__open_and_load();
    if (!skel_) {
        std::cerr << "[CpuUsage] Failed to load BPF program" << std::endl;
        return false;
    }
    
    if (cputime_bpf__attach(skel_) != 0) {
        std::cerr << "[CpuUsage] Failed to attach BPF program" << std::endl;
        cputime_bpf__destroy(skel_);
        skel_ = nullptr;
        return false;
    }
    
    prev_time_ = std::chrono::steady_clock::now();
    std::cout << "[CpuUsage] Initialized successfully" << std::endl;
    return true;
}

void CpuUsage::cleanup() {
    if (skel_) {
        cputime_bpf__destroy(skel_);
        skel_ = nullptr;
    }
}

std::map<pid_t, double> CpuUsage::getProcessCpuUsage() {
    std::map<pid_t, double> result;
    
    if (!skel_) {
        return result;
    }
    
    auto current_time = std::chrono::steady_clock::now();
    auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        current_time - prev_time_).count();
    
    // Read current CPU times from BPF map
    std::map<pid_t, uint64_t> current_cpu_ns;
    
    pid_t key = 0;
    pid_t next_key;
    uint64_t value;
    
    // Removed unused 'fd' variable
    
    // Use the correct libbpf API functions
    while (bpf_map__get_next_key(skel_->maps.cpu_total_ns, &key, &next_key, sizeof(next_key)) == 0) {
        if (bpf_map__lookup_elem(skel_->maps.cpu_total_ns, &next_key, sizeof(next_key), &value, sizeof(value), 0) == 0) {
            current_cpu_ns[next_key] = value;
        }
        key = next_key;
    }
    
    // If first sample, just store the values and return empty
    if (first_sample_) {
        prev_cpu_ns_ = current_cpu_ns;
        prev_time_ = current_time;
        first_sample_ = false;
        return result;
    }
    
    // Calculate CPU usage percentage for each process
    for (const auto& [pid, current_ns] : current_cpu_ns) {
        auto prev_it = prev_cpu_ns_.find(pid);
        if (prev_it != prev_cpu_ns_.end()) {
            uint64_t cpu_delta_ns = current_ns - prev_it->second;
            
            // CPU usage % = (cpu_time_used / elapsed_time) * 100
            // This gives usage per core (0-100% per core)
            double cpu_percent = (static_cast<double>(cpu_delta_ns) / elapsed_ns) * 100.0;
            
            if (cpu_percent > 0.01) {  // Filter out very small values
                result[pid] = cpu_percent;
            }
        }
    }
    
    // Update previous values
    prev_cpu_ns_ = current_cpu_ns;
    prev_time_ = current_time;
    
    return result;
}

} // namespace monitor