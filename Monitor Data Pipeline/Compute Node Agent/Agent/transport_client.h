#ifndef TRANSPORT_CLIENT_H
#define TRANSPORT_CLIENT_H

#include "../ComputeNodeUsage/types.h"
#include <string>

namespace monitor {

// Abstract base class for transport clients
// Implements Strategy Pattern for different transport mechanisms
class TransportClient {
protected:
    std::string node_id_;
    bool connected_;

public:
    TransportClient(const std::string& node_id)
        : node_id_(node_id), connected_(false) {}

    virtual ~TransportClient() = default;

    // Pure virtual methods that must be implemented by concrete clients
    virtual bool connect() = 0;
    virtual bool disconnect() = 0;
    virtual bool sendSnapshot(const ComputeNodeSnapshotInternal& snapshot) = 0;

    // Common interface methods
    virtual bool isConnected() const { return connected_; }
    virtual std::string getNodeId() const { return node_id_; }
    virtual std::string getTransportType() const = 0;
};

} // namespace monitor

#endif
