#ifndef GRPC_CLIENT_H
#define GRPC_CLIENT_H

#include "../transport_client.h"
#include "../../ComputeNodeUsage/types.h"
#include "monitor.grpc.pb.h"
#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>

namespace monitor {

class GrpcClient : public TransportClient {
private:
    std::unique_ptr<::monitor::MonitorService::Stub> stub_;
    std::string server_address_;
    std::shared_ptr<grpc::Channel> channel_;

    // Convert internal C++ snapshot to protobuf message
    ::monitor::ComputeNodeSnapshot convertToProto(const ComputeNodeSnapshotInternal& snapshot);

public:
    GrpcClient(const std::string& server_address, const std::string& node_id);
    ~GrpcClient() override = default;

    // Implement TransportClient interface
    bool connect() override;
    bool disconnect() override;
    bool sendSnapshot(const ComputeNodeSnapshotInternal& snapshot) override;
    std::string getTransportType() const override { return "gRPC"; }
};

} // namespace monitor

#endif