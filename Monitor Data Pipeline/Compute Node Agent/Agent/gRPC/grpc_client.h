#ifndef GRPC_CLIENT_H
#define GRPC_CLIENT_H

#include "../../ComputeNodeUsage/types.h"
#include "monitor.grpc.pb.h"
#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>

namespace monitor {

class GrpcClient {
private:
    std::unique_ptr<::monitor::MonitorService::Stub> stub_;
    std::string node_id_;
    bool connected_;
    
public:
    GrpcClient(const std::string& server_address, const std::string& node_id);
    ~GrpcClient() = default;
    
    // Convert internal C++ snapshot to protobuf message
    ::monitor::ComputeNodeSnapshot convertToProto(const ComputeNodeSnapshotInternal& snapshot);
    
    // Send a single snapshot to the server
    bool sendSnapshot(const ComputeNodeSnapshotInternal& snapshot);
    
    // Check if connected
    bool isConnected() const { return connected_; }
};

} // namespace monitor

#endif