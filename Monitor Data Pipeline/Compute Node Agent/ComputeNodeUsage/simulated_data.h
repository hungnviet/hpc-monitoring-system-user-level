#ifndef SIMULATED_DATA_H
#define SIMULATED_DATA_H

#include "types.h"
#include <random>
#include <chrono>
#include <vector>
#include <string>

namespace monitor {

class SimulatedDataGenerator {
private:
    std::mt19937 rng_;
    std::uniform_real_distribution<double> cpu_dist_;
    std::uniform_int_distribution<uint64_t> mem_dist_;
    std::uniform_real_distribution<double> gpu_sm_dist_;
    std::uniform_real_distribution<double> gpu_mem_dist_;
    std::uniform_int_distribution<int> gpu_temp_dist_;
    std::uniform_real_distribution<double> gpu_power_dist_;
    std::uniform_int_distribution<int> gpu_load_dist_;
    std::uniform_int_distribution<int> process_count_dist_;

    std::vector<std::string> sample_commands_ = {
        "python3", "gcc", "make", "node", "java",
        "docker", "nginx", "postgres", "redis", "tensorflow"
    };

public:
    SimulatedDataGenerator()
        : rng_(std::chrono::steady_clock::now().time_since_epoch().count()),
          cpu_dist_(0.0, 100.0),
          mem_dist_(100 * 1024 * 1024, 4ULL * 1024 * 1024 * 1024),  // 100MB to 4GB
          gpu_sm_dist_(0.0, 100.0),
          gpu_mem_dist_(0.0, 100.0),
          gpu_temp_dist_(30, 85),
          gpu_power_dist_(50.0, 250.0),
          gpu_load_dist_(0, 100),
          process_count_dist_(5, 20) {
    }

    ComputeNodeSnapshotInternal generateSnapshot() {
        ComputeNodeSnapshotInternal snapshot;

        // Set timestamp
        snapshot.timestamp = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now()
        );

        // Generate GPU global state
        snapshot.gpu_global_state.power_watts = gpu_power_dist_(rng_);
        snapshot.gpu_global_state.temperature_celsius = gpu_temp_dist_(rng_);
        snapshot.gpu_global_state.total_load_percent = gpu_load_dist_(rng_);

        // Generate processes
        int num_processes = process_count_dist_(rng_);
        for (int i = 0; i < num_processes; ++i) {
            ProcessMetricsInternal proc;

            proc.pid = 1000 + i;
            proc.uid = 1000;
            proc.command = sample_commands_[i % sample_commands_.size()];
            proc.cpu_usage_percent = cpu_dist_(rng_);
            proc.memory_bytes = mem_dist_(rng_);

            // Some processes use GPU (about 30%)
            if (i % 3 == 0) {
                proc.gpu_sm_percent = gpu_sm_dist_(rng_);
                proc.gpu_mem_percent = gpu_mem_dist_(rng_);
                proc.gpu_mem_mib = static_cast<int>(proc.gpu_mem_percent * 160);  // Simulated GPU mem
            }

            snapshot.processes.push_back(proc);
        }

        return snapshot;
    }
};

} // namespace monitor

#endif
