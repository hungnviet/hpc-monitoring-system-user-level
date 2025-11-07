#include "ComputeNodeUsage/compute_node_usage.h"
#include "Agent/gRPC/grpc_client.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>
#include <fstream>
#include <nlohmann/json.hpp>

static volatile bool g_running = true;

void signalHandler(int signum) {
    std::cout << "\n[Main] Received signal " << signum << ", shutting down..." << std::endl;
    g_running = false;
}

int main() {
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::cout << "=== Compute Node Monitor with gRPC ===" << std::endl;
    std::cout << "Process-level monitoring of CPU, Memory, and GPU" << std::endl;
    std::cout << "Press Ctrl+C to exit\n" << std::endl;
    
    // Read configuration from infra.json
    std::string server_address = "localhost:50051";  // Default
    std::string node_id = "compute-node-01";         // Default
    
    std::ifstream config_file("../../infra.json");
    if (config_file.is_open()) {
        try {
            nlohmann::json config;
            config_file >> config;
            
            if (config.contains("grpc_server")) {
                server_address = config["grpc_server"]["address"].get<std::string>();
            }
            if (config.contains("node_id")) {
                node_id = config["node_id"].get<std::string>();
            }
            
            std::cout << "[Config] Server: " << server_address << std::endl;
            std::cout << "[Config] Node ID: " << node_id << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "[Config] Warning: Failed to parse config: " << e.what() << std::endl;
            std::cout << "[Config] Using defaults" << std::endl;
        }
    } else {
        std::cout << "[Config] No config file found, using defaults" << std::endl;
    }
    
    // Create and initialize monitor
    monitor::ComputeNodeUsage node_monitor;
    
    if (!node_monitor.initialize()) {
        std::cerr << "[Main] Failed to initialize compute node monitor" << std::endl;
        return 1;
    }
    
    // Create gRPC client
    monitor::GrpcClient grpc_client(server_address, node_id);
    
    if (!grpc_client.isConnected()) {
        std::cerr << "[Main] Warning: gRPC client not connected" << std::endl;
        std::cerr << "[Main] Will continue monitoring locally only" << std::endl;
    }
    
    std::cout << "\n[Main] Monitor started. Collecting data every 1 second...\n" << std::endl;
    
    // Statistics
    uint64_t snapshots_collected = 0;
    uint64_t snapshots_sent = 0;
    uint64_t snapshots_failed = 0;
    
    // Main monitoring loop
    while (g_running) {
        auto snapshot = node_monitor.collectSnapshot();
        snapshots_collected++;
        
        std::cout << "\n=== Snapshot #" << snapshots_collected 
                  << " (timestamp: " << snapshot.timestamp << ") ===" << std::endl;
        std::cout << "Processes: " << snapshot.processes.size() << std::endl;
        std::cout << "GPU: " << snapshot.gpu_global_state.total_load_percent << "% @ " 
                  << snapshot.gpu_global_state.temperature_celsius << "°C" << std::endl;
        
        // Send to gRPC server
        if (grpc_client.isConnected()) {
            if (grpc_client.sendSnapshot(snapshot)) {
                snapshots_sent++;
            } else {
                snapshots_failed++;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    std::cout << "\n[Main] Monitor stopped gracefully." << std::endl;
    std::cout << "[Main] Statistics:" << std::endl;
    std::cout << "  - Snapshots collected: " << snapshots_collected << std::endl;
    std::cout << "  - Snapshots sent: " << snapshots_sent << std::endl;
    std::cout << "  - Snapshots failed: " << snapshots_failed << std::endl;
    
    return 0;
}