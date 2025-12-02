#include "mqtt_client.h"
#include <iostream>
#include <sstream>

namespace monitor {

MqttClient::MqttClient(const std::string& broker_address, int port,
                       const std::string& topic, int qos, int keepalive,
                       const std::string& node_id)
    : TransportClient(node_id),
      topic_(topic),
      qos_(qos),
      keepalive_(keepalive) {

    std::stringstream ss;
    ss << "tcp://" << broker_address << ":" << port;
    broker_address_ = ss.str();

    std::cout << "[MqttClient] Initializing MQTT client for " << broker_address_ << std::endl;
    std::cout << "[MqttClient] Topic: " << topic_ << ", QoS: " << qos_ << std::endl;

    // Create MQTT client with unique client ID
    std::string client_id = node_id_ + "_mqtt_client";
    client_ = std::make_unique<mqtt::async_client>(broker_address_, client_id);
}

bool MqttClient::connect() {
    try {
        std::cout << "[MqttClient] Connecting to " << broker_address_ << "..." << std::endl;

        mqtt::connect_options conn_opts;
        conn_opts.set_keep_alive_interval(keepalive_);
        conn_opts.set_clean_session(true);
        conn_opts.set_automatic_reconnect(true);

        auto tok = client_->connect(conn_opts);
        tok->wait();

        if (client_->is_connected()) {
            connected_ = true;
            std::cout << "[MqttClient] ✓ Connected successfully" << std::endl;
            return true;
        } else {
            connected_ = false;
            std::cerr << "[MqttClient] ✗ Failed to connect" << std::endl;
            return false;
        }
    } catch (const mqtt::exception& e) {
        std::cerr << "[MqttClient] ✗ Connection failed: " << e.what() << std::endl;
        connected_ = false;
        return false;
    }
}

bool MqttClient::disconnect() {
    try {
        std::cout << "[MqttClient] Disconnecting..." << std::endl;

        if (client_ && client_->is_connected()) {
            auto tok = client_->disconnect();
            tok->wait();
        }

        connected_ = false;
        std::cout << "[MqttClient] ✓ Disconnected successfully" << std::endl;
        return true;
    } catch (const mqtt::exception& e) {
        std::cerr << "[MqttClient] ✗ Disconnect failed: " << e.what() << std::endl;
        return false;
    }
}

std::string MqttClient::convertToJson(const ComputeNodeSnapshotInternal& snapshot) {
    nlohmann::json j;

    j["timestamp"] = snapshot.timestamp;
    j["node_id"] = node_id_;

    // GPU global state
    j["gpu_global_state"] = {
        {"power_watts", snapshot.gpu_global_state.power_watts},
        {"temperature_celsius", snapshot.gpu_global_state.temperature_celsius},
        {"total_load_percent", snapshot.gpu_global_state.total_load_percent}
    };

    // Processes
    j["processes"] = nlohmann::json::array();
    for (const auto& proc : snapshot.processes) {
        nlohmann::json proc_json = {
            {"pid", proc.pid},
            {"uid", proc.uid},
            {"command", proc.command},
            {"cpu_usage_percent", proc.cpu_usage_percent},
            {"memory_bytes", proc.memory_bytes},
            {"gpu_sm_percent", proc.gpu_sm_percent},
            {"gpu_mem_percent", proc.gpu_mem_percent},
            {"gpu_mem_mib", proc.gpu_mem_mib}
        };
        j["processes"].push_back(proc_json);
    }

    return j.dump();
}

bool MqttClient::sendSnapshot(const ComputeNodeSnapshotInternal& snapshot) {
    if (!connected_) {
        std::cerr << "[MqttClient] Not connected to broker" << std::endl;
        return false;
    }

    try {
        std::string json_payload = convertToJson(snapshot);

        auto msg = mqtt::make_message(topic_, json_payload);
        msg->set_qos(qos_);

        auto tok = client_->publish(msg);
        tok->wait();

        std::cout << "[MqttClient] ✓ Published snapshot to topic '" << topic_
                  << "' (" << json_payload.length() << " bytes)" << std::endl;
        return true;
    } catch (const mqtt::exception& e) {
        std::cerr << "[MqttClient] ✗ Publish failed: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "[MqttClient] ✗ Error: " << e.what() << std::endl;
        return false;
    }
}

} // namespace monitor
