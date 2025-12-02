#include "ComputeNodeUsage/compute_node_usage.h"
#include "ComputeNodeUsage/simulated_data.h"
#include "Agent/transport_client.h"
#include "Agent/gRPC/grpc_client.h"
#include "Agent/MQTT/mqtt_client.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>
#include <fstream>
#include <vector>
#include <memory>
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

    std::cout << "========================================" << std::endl;
    std::cout << "  Compute Node Monitor (Multi-Transport)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Press Ctrl+C to exit\n" << std::endl;

    // Read configuration from infra.json
    std::string config_path = "../../infra.json";
    std::ifstream config_file(config_path);

    if (!config_file.is_open()) {
        std::cerr << "[Main] Error: Cannot open config file: " << config_path << std::endl;
        return 1;
    }

    nlohmann::json config;
    try {
        config_file >> config;
    } catch (const std::exception& e) {
        std::cerr << "[Main] Error: Failed to parse config: " << e.what() << std::endl;
        return 1;
    }

    // Extract configuration
    std::string node_id = config.value("compute_nodes", nlohmann::json::array())[0].value("node_id", "compute-node-01");
    int snapshot_interval = config["monitoring"].value("snapshot_interval_seconds", 1);
    bool use_simulated_data = config["monitoring"].value("use_simulated_data", false);
    bool enable_grpc = config["transport"].value("enable_grpc", true);
    bool enable_mqtt = config["transport"].value("enable_mqtt", true);

    std::cout << "[Config] Node ID: " << node_id << std::endl;
    std::cout << "[Config] Snapshot interval: " << snapshot_interval << " seconds" << std::endl;
    std::cout << "[Config] Using simulated data: " << (use_simulated_data ? "YES" : "NO") << std::endl;
    std::cout << "[Config] Transport: gRPC=" << (enable_grpc ? "ON" : "OFF")
              << ", MQTT=" << (enable_mqtt ? "ON" : "OFF") << std::endl;
    std::cout << std::endl;

    // Initialize data source (real or simulated)
    std::unique_ptr<monitor::ComputeNodeUsage> real_monitor;
    std::unique_ptr<monitor::SimulatedDataGenerator> sim_generator;

    if (use_simulated_data) {
        std::cout << "[Main] Initializing simulated data generator..." << std::endl;
        sim_generator = std::make_unique<monitor::SimulatedDataGenerator>();
        std::cout << "[Main] ✓ Simulated data generator ready" << std::endl;
    } else {
        std::cout << "[Main] Initializing real compute node monitor..." << std::endl;
        real_monitor = std::make_unique<monitor::ComputeNodeUsage>();
        if (!real_monitor->initialize()) {
            std::cerr << "[Main] Failed to initialize compute node monitor" << std::endl;
            return 1;
        }
        std::cout << "[Main] ✓ Real monitor ready" << std::endl;
    }
    std::cout << std::endl;

    // Initialize transport clients (Strategy Pattern)
    std::vector<std::unique_ptr<monitor::TransportClient>> transport_clients;

    // Create gRPC client if enabled
    if (enable_grpc) {
        std::string grpc_address = config["grpc_server"].value("address", "localhost:50051");
        auto grpc_client = std::make_unique<monitor::GrpcClient>(grpc_address, node_id);
        if (grpc_client->connect()) {
            transport_clients.push_back(std::move(grpc_client));
        } else {
            std::cerr << "[Main] Warning: gRPC client failed to connect" << std::endl;
        }
    }

    // Create MQTT client if enabled
    if (enable_mqtt) {
        std::string mqtt_address = config["mqtt_broker"].value("address", "localhost");
        int mqtt_port = config["mqtt_broker"].value("port", 1883);
        std::string mqtt_topic = config["mqtt_broker"].value("topic", "monitoring/compute-node");
        int mqtt_qos = config["mqtt_broker"].value("qos", 1);
        int mqtt_keepalive = config["mqtt_broker"].value("keepalive", 60);

        auto mqtt_client = std::make_unique<monitor::MqttClient>(
            mqtt_address, mqtt_port, mqtt_topic, mqtt_qos, mqtt_keepalive, node_id
        );
        if (mqtt_client->connect()) {
            transport_clients.push_back(std::move(mqtt_client));
        } else {
            std::cerr << "[Main] Warning: MQTT client failed to connect" << std::endl;
        }
    }

    if (transport_clients.empty()) {
        std::cerr << "[Main] Error: No transport clients available" << std::endl;
        return 1;
    }

    std::cout << "\n[Main] Active transport clients: " << transport_clients.size() << std::endl;
    for (const auto& client : transport_clients) {
        std::cout << "  - " << client->getTransportType() << std::endl;
    }
    std::cout << "\n[Main] Starting monitoring loop...\n" << std::endl;

    // Statistics
    uint64_t snapshots_collected = 0;
    std::map<std::string, uint64_t> sent_count;
    std::map<std::string, uint64_t> failed_count;

    for (auto& client : transport_clients) {
        sent_count[client->getTransportType()] = 0;
        failed_count[client->getTransportType()] = 0;
    }

    // Main monitoring loop
    while (g_running) {
        // Collect snapshot (real or simulated)
        monitor::ComputeNodeSnapshotInternal snapshot;

        if (use_simulated_data) {
            snapshot = sim_generator->generateSnapshot();
        } else {
            snapshot = real_monitor->collectSnapshot();
        }

        snapshots_collected++;

        std::cout << "\n=== Snapshot #" << snapshots_collected
                  << " (timestamp: " << snapshot.timestamp << ") ===" << std::endl;
        std::cout << "Processes: " << snapshot.processes.size() << std::endl;
        std::cout << "GPU: " << snapshot.gpu_global_state.total_load_percent << "% @ "
                  << snapshot.gpu_global_state.temperature_celsius << "°C, "
                  << snapshot.gpu_global_state.power_watts << "W" << std::endl;

        // Send snapshot via all transport clients
        for (auto& client : transport_clients) {
            if (client->isConnected()) {
                if (client->sendSnapshot(snapshot)) {
                    sent_count[client->getTransportType()]++;
                } else {
                    failed_count[client->getTransportType()]++;
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(snapshot_interval));
    }

    // Graceful shutdown
    std::cout << "\n[Main] Shutting down..." << std::endl;

    for (auto& client : transport_clients) {
        client->disconnect();
    }

    std::cout << "\n[Main] Monitor stopped gracefully." << std::endl;
    std::cout << "\n=== Statistics ===" << std::endl;
    std::cout << "Snapshots collected: " << snapshots_collected << std::endl;

    for (const auto& client : transport_clients) {
        std::string type = client->getTransportType();
        std::cout << "\n" << type << " Client:" << std::endl;
        std::cout << "  - Sent: " << sent_count[type] << std::endl;
        std::cout << "  - Failed: " << failed_count[type] << std::endl;
    }

    return 0;
}
