#include "compute_node_usage.h"
#include <chrono>
#include <set>
#include <fstream>
#include <iostream>
#include <sys/stat.h>

namespace monitor {

ComputeNodeUsage::ComputeNodeUsage() : initialized_(false) {
    cpu_monitor_ = std::make_unique<CpuUsage>();
    mem_monitor_ = std::make_unique<MemoryUsage>();
    gpu_monitor_ = std::make_unique<GpuUsage>();
}

bool ComputeNodeUsage::initialize() {
    std::cout << "[ComputeNodeUsage] Initializing monitors..." << std::endl;
    
    if (!cpu_monitor_->initialize()) {
        std::cerr << "[ComputeNodeUsage] Failed to initialize CPU monitor" << std::endl;
        return false;
    }
    
    if (!mem_monitor_->initialize(-1)) {
        std::cerr << "[ComputeNodeUsage] Failed to initialize Memory monitor" << std::endl;
        return false;
    }
    
    gpu_monitor_->initialize();
    
    initialized_ = true;
    std::cout << "[ComputeNodeUsage] All monitors initialized successfully" << std::endl;
    return true;
}

bool ComputeNodeUsage::processExists(int pid) const {
    struct stat statbuf;
    std::string proc_path = "/proc/" + std::to_string(pid);
    return (stat(proc_path.c_str(), &statbuf) == 0);
}

uint32_t ComputeNodeUsage::getUidForPid(int pid) const {
    std::ifstream status_file("/proc/" + std::to_string(pid) + "/status");
    if (!status_file.is_open()) {
        return 0;
    }
    
    std::string line;
    while (std::getline(status_file, line)) {
        if (line.rfind("Uid:", 0) == 0) {
            try {
                size_t start = line.find_first_not_of(" \t", 4);
                size_t end = line.find_first_of(" \t", start);
                std::string uid_str = line.substr(start, end - start);
                return std::stoul(uid_str);
            } catch (...) {
                return 0;
            }
        }
    }
    return 0;
}

std::string ComputeNodeUsage::getCommForPid(int pid) const {
    std::ifstream comm_file("/proc/" + std::to_string(pid) + "/comm");
    if (!comm_file.is_open()) {
        return "[exited]";
    }
    
    std::string comm;
    std::getline(comm_file, comm);
    
    if (!comm.empty() && comm.back() == '\n') {
        comm.pop_back();
    }
    
    return comm.empty() ? "[unknown]" : comm;
}

ComputeNodeSnapshotInternal ComputeNodeUsage::collectSnapshot() {
    ComputeNodeSnapshotInternal snapshot;
    
    if (!initialized_) {
        std::cerr << "[ComputeNodeUsage] Cannot collect snapshot - not initialized" << std::endl;
        return snapshot;
    }
    
    // Set timestamp
    auto now = std::chrono::system_clock::now();
    snapshot.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()
    ).count();
    
    // Get GPU global state
    auto gpu_state = gpu_monitor_->getGlobalState();
    snapshot.gpu_global_state.power_watts = gpu_state.power_watts;
    snapshot.gpu_global_state.temperature_celsius = gpu_state.temperature_celsius;
    snapshot.gpu_global_state.total_load_percent = gpu_state.total_load_percent;
    
    // Collect data from all monitors
    auto cpu_data = cpu_monitor_->getProcessCpuUsage();
    auto mem_data = mem_monitor_->getProcessMemoryAllocs();
    auto gpu_data = gpu_monitor_->getProcessUsage();
    
    // Merge all PIDs
    std::set<int> all_pids;
    for (const auto& [pid, _] : cpu_data) all_pids.insert(pid);
    for (const auto& [pid, _] : mem_data) all_pids.insert(pid);
    for (const auto& [pid, _] : gpu_data) all_pids.insert(pid);
    
    // Build ProcessMetrics for each PID
    for (int pid : all_pids) {
        if (!processExists(pid)) {
            continue;
        }
        
        std::string command = getCommForPid(pid);
        if (command == "[exited]") {
            continue;
        }
        
        ProcessMetricsInternal proc;
        proc.pid = pid;
        proc.uid = getUidForPid(pid);
        proc.command = command;
        
        auto cpu_it = cpu_data.find(pid);
        if (cpu_it != cpu_data.end()) {
            proc.cpu_usage_percent = cpu_it->second;
        } else {
            proc.cpu_usage_percent = 0.0;
        }
        
        auto mem_it = mem_data.find(pid);
        if (mem_it != mem_data.end()) {
            proc.memory_bytes = mem_it->second;
        } else {
            proc.memory_bytes = 0;
        }
        
        auto gpu_it = gpu_data.find(pid);
        if (gpu_it != gpu_data.end()) {
            proc.gpu_sm_percent = static_cast<double>(gpu_it->second.sm);
            proc.gpu_mem_percent = static_cast<double>(gpu_it->second.mem);
            proc.gpu_mem_mib = gpu_it->second.mem_mib;
        } else {
            proc.gpu_sm_percent = -1.0;
            proc.gpu_mem_percent = -1.0;
            proc.gpu_mem_mib = 0;
        }
        
        snapshot.processes.push_back(proc);
    }
    
    return snapshot;
}

} // namespace monitor