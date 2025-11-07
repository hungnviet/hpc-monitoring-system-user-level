#include "gpu_usage.h"
#include <iostream>
#include <sstream>
#include <array>
#include <memory>
#include <cstdio>
#include <regex>
#include <algorithm>

namespace monitor {

GpuUsage::GpuUsage() : initialized_(false) {}

bool GpuUsage::initialize() {
    // Check if nvidia-smi is available
    FILE* pipe = popen("nvidia-smi --version 2>/dev/null", "r");
    if (!pipe) {
        std::cerr << "[GpuUsage] nvidia-smi not found" << std::endl;
        return false;
    }
    
    char buffer[128];
    bool found = false;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        if (std::string(buffer).find("NVIDIA-SMI") != std::string::npos) {
            found = true;
            break;
        }
    }
    pclose(pipe);
    
    if (!found) {
        std::cerr << "[GpuUsage] nvidia-smi not functional" << std::endl;
        return false;
    }
    
    initialized_ = true;
    std::cout << "[GpuUsage] Initialized successfully" << std::endl;
    return true;
}

std::string GpuUsage::executeCommand(const std::string& cmd) {
    std::array<char, 256> buffer;
    std::string result;
    
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        return "";
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    
    return result;
}

GpuGlobalStateInternal GpuUsage::getGlobalState() {
    GpuGlobalStateInternal state;
    state.power_watts = 0.0;
    state.temperature_celsius = 0;
    state.total_load_percent = 0;
    
    if (!initialized_) {
        return state;
    }
    
    // Execute nvidia-smi
    std::string output = executeCommand("nvidia-smi 2>/dev/null");
    if (output.empty()) {
        return state;
    }
    
    std::istringstream stream(output);
    std::string line;
    
    // Parse the output line by line
    while (std::getline(stream, line)) {
        // Look for the GPU stats line
        // Example: "|  0%   32C    P8             22W /  225W |     596MiB /   8192MiB |     10%      Default |"
        
        // Match pattern: "| <fan>% <temp>C <perf> <power>W / <max_power>W | <mem>MiB / <total_mem>MiB | <util>% <compute_mode> |"
        std::regex gpu_stats_regex(R"(\|\s*(\d+)%\s+(\d+)C\s+\S+\s+(\d+)W\s*/\s*\d+W\s*\|.*\|\s*(\d+)%\s+\S+\s*\|)");
        std::smatch match;
        
        if (std::regex_search(line, match, gpu_stats_regex)) {
            // match[1] = fan%, match[2] = temp, match[3] = power, match[4] = GPU util%
            try {
                state.temperature_celsius = std::stoi(match[2].str());
                state.power_watts = std::stod(match[3].str());
                state.total_load_percent = std::stoi(match[4].str());
            } catch (...) {
                // Keep default values
            }
            break;  // Found the GPU stats line
        }
    }
    
    return state;
}

std::map<int, GpuProcessUsage> GpuUsage::getProcessUsage() {
    std::map<int, GpuProcessUsage> result;
    
    if (!initialized_) {
        return result;
    }
    
    // Step 1: Get GPU memory usage from nvidia-smi (for MiB values)
    std::map<int, int> pid_memory_map;  // pid -> mem_mib
    int total_mem_mib = 0;
    
    std::string smi_output = executeCommand("nvidia-smi 2>/dev/null");
    if (!smi_output.empty()) {
        std::istringstream stream(smi_output);
        std::string line;
        bool in_process_section = false;
        
        // Get total memory
        std::istringstream stream_mem(smi_output);
        while (std::getline(stream_mem, line)) {
            std::regex mem_regex(R"(\|\s*(\d+)MiB\s*/\s*(\d+)MiB\s*\|)");
            std::smatch match;
            if (std::regex_search(line, match, mem_regex)) {
                total_mem_mib = std::stoi(match[2].str());
                break;
            }
        }
        
        // Parse process memory usage
        while (std::getline(stream, line)) {
            if (line.find("Processes:") != std::string::npos) {
                in_process_section = true;
                continue;
            }
            
            if (!in_process_section) continue;
            
            if (line.find("+---") != std::string::npos || 
                line.find("===") != std::string::npos ||
                line.find("GPU   GI   CI") != std::string::npos) {
                continue;
            }
            
            // Parse: "|    0   N/A  N/A     57258      G   /usr/lib/xorg/Xorg                            138MiB |"
            std::regex process_regex(R"(\|\s*\d+\s+\S+\s+\S+\s+(\d+)\s+[GC]\s+.*?(\d+)MiB\s*\|)");
            std::smatch match;
            
            if (std::regex_search(line, match, process_regex)) {
                try {
                    int pid = std::stoi(match[1].str());
                    int mem_mib = std::stoi(match[2].str());
                    pid_memory_map[pid] = mem_mib;
                } catch (...) {}
            }
        }
    }
    
    // Step 2: Get real-time SM and MEM utilization from nvidia-smi pmon
    std::string pmon_output = executeCommand("nvidia-smi pmon -c 1 2>/dev/null");
    if (pmon_output.empty()) {
        // If pmon fails, return processes with memory info only
        for (const auto& [pid, mem_mib] : pid_memory_map) {
            GpuProcessUsage usage;
            usage.sm = 0;
            usage.mem = total_mem_mib > 0 ? (mem_mib * 100) / total_mem_mib : 0;
            usage.mem_mib = mem_mib;
            result[pid] = usage;
        }
        return result;
    }
    
    std::istringstream pmon_stream(pmon_output);
    std::string line;
    
    // Skip header lines (first 2 lines)
    std::getline(pmon_stream, line);  // "# gpu  pid  type  sm  mem  enc  dec  jpg  ofa  command"
    std::getline(pmon_stream, line);  // "# Idx    #   C/G   %    %    %    %    %    %  name"
    
    // Parse each process line
    // Format: "    0       2039     G      -      -      -      -      -      -    Xorg"
    while (std::getline(pmon_stream, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        std::istringstream iss(line);
        int gpu_id, pid;
        std::string type, sm_str, mem_str, enc_str, dec_str, jpg_str, ofa_str, command;
        
        // Parse: gpu pid type sm mem enc dec jpg ofa command
        if (iss >> gpu_id >> pid >> type >> sm_str >> mem_str >> enc_str >> dec_str 
               >> jpg_str >> ofa_str >> command) {
            
            GpuProcessUsage usage;
            
            // Parse SM utilization ("-" means 0%)
            if (sm_str == "-") {
                usage.sm = 0;
            } else {
                try {
                    usage.sm = std::stoi(sm_str);
                } catch (...) {
                    usage.sm = 0;
                }
            }
            
            // Parse MEM utilization ("-" means 0%)
            if (mem_str == "-") {
                usage.mem = 0;
            } else {
                try {
                    usage.mem = std::stoi(mem_str);
                } catch (...) {
                    usage.mem = 0;
                }
            }
            
            // Get memory MiB from earlier nvidia-smi query
            auto mem_it = pid_memory_map.find(pid);
            if (mem_it != pid_memory_map.end()) {
                usage.mem_mib = mem_it->second;
                
                // If pmon reports "-" for mem%, calculate from memory usage
                if (usage.mem == 0 && total_mem_mib > 0 && usage.mem_mib > 0) {
                    usage.mem = (usage.mem_mib * 100) / total_mem_mib;
                }
            } else {
                usage.mem_mib = 0;
            }
            
            result[pid] = usage;
        }
    }
    
    // Add any processes that were in nvidia-smi but not in pmon
    for (const auto& [pid, mem_mib] : pid_memory_map) {
        if (result.find(pid) == result.end()) {
            GpuProcessUsage usage;
            usage.sm = 0;
            usage.mem = total_mem_mib > 0 ? (mem_mib * 100) / total_mem_mib : 0;
            usage.mem_mib = mem_mib;
            result[pid] = usage;
        }
    }
    
    return result;
}

} // namespace monitor