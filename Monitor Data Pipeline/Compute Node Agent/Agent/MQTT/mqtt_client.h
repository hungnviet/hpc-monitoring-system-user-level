#ifndef MQTT_CLIENT_H
#define MQTT_CLIENT_H

#include "../transport_client.h"
#include "../../ComputeNodeUsage/types.h"
#include <mqtt/async_client.h>
#include <nlohmann/json.hpp>
#include <memory>
#include <string>

namespace monitor {

class MqttClient : public TransportClient {
private:
    std::unique_ptr<mqtt::async_client> client_;
    std::string broker_address_;
    std::string topic_;
    int qos_;
    int keepalive_;

    // Convert internal C++ snapshot to JSON string
    std::string convertToJson(const ComputeNodeSnapshotInternal& snapshot);

public:
    MqttClient(const std::string& broker_address, int port,
               const std::string& topic, int qos, int keepalive,
               const std::string& node_id);
    ~MqttClient() override = default;

    // Implement TransportClient interface
    bool connect() override;
    bool disconnect() override;
    bool sendSnapshot(const ComputeNodeSnapshotInternal& snapshot) override;
    std::string getTransportType() const override { return "MQTT"; }
};

} // namespace monitor

#endif
