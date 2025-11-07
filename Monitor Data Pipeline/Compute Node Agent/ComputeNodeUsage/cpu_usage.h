#ifndef CPU_USAGE_H
#define CPU_USAGE_H

#include "types.h"
#include "ebpf/cpu-usage/cputime.skel.h"
#include <map>
#include <memory>
#include <chrono>

namespace monitor {

class CpuUsage {
public:
    CpuUsage();
    ~CpuUsage();
    
    bool initialize();
    void cleanup();
    
    // Returns CPU usage percentage per process (0-100% per core)
    std::map<pid_t, double> getProcessCpuUsage();
    
private:
    struct cputime_bpf *skel_;
    std::map<pid_t, uint64_t> prev_cpu_ns_;  // Previous CPU time in nanoseconds
    std::chrono::steady_clock::time_point prev_time_;  // Previous snapshot time
    bool first_sample_;
};

} // namespace monitor

#endif // CPU_USAGE_H