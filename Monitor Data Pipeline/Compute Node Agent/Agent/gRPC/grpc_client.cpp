#include "grpc_client.h"
#include <iostream>
#include <grpcpp/grpcpp.h>

namespace monitor {

GrpcClient::GrpcClient(const std::string& server_address, const std::string& node_id)
    : node_id_(node_id), connected_(false) {
    
    std::cout << "[GrpcClient] Connecting to " << server_address << "..." << std::endl;
    
    auto channel = grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials());
    stub_ = ::monitor::MonitorService::NewStub(channel);
    
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(5);
    if (channel->WaitForConnected(deadline)) {
        connected_ = true;
        std::cout << "[GrpcClient] ✓ Connected successfully" << std::endl;
    } else {
        std::cerr << "[GrpcClient] ✗ Failed to connect (timeout)" << std::endl;
    }
}

::monitor::ComputeNodeSnapshot GrpcClient::convertToProto(const ComputeNodeSnapshotInternal& snapshot) {
    ::monitor::ComputeNodeSnapshot proto_snapshot;
    
    proto_snapshot.set_timestamp(snapshot.timestamp);
    proto_snapshot.set_node_id(node_id_);
    
    // Set GPU global state
    auto* gpu_state = proto_snapshot.mutable_gpu_global_state();
    gpu_state->set_power_watts(snapshot.gpu_global_state.power_watts);
    gpu_state->set_temperature_celsius(snapshot.gpu_global_state.temperature_celsius);
    gpu_state->set_total_load_percent(snapshot.gpu_global_state.total_load_percent);
    
    // Add all processes
    for (const auto& proc : snapshot.processes) {
        auto* proto_proc = proto_snapshot.add_processes();
        
        proto_proc->set_pid(proc.pid);
        proto_proc->set_uid(proc.uid);
        proto_proc->set_command(proc.command);
        proto_proc->set_cpu_usage_percent(proc.cpu_usage_percent);
        proto_proc->set_memory_bytes(proc.memory_bytes);
        proto_proc->set_gpu_sm_percent(proc.gpu_sm_percent);
        proto_proc->set_gpu_mem_percent(proc.gpu_mem_percent);
        proto_proc->set_gpu_mem_mib(proc.gpu_mem_mib);
    }
    
    return proto_snapshot;
}

bool GrpcClient::sendSnapshot(const ComputeNodeSnapshotInternal& snapshot) {
    if (!connected_) {
        std::cerr << "[GrpcClient] Not connected to server" << std::endl;
        return false;
    }
    
    auto proto_snapshot = convertToProto(snapshot);
    
    grpc::ClientContext context;
    ::monitor::SnapshotResponse response;
    
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(5);
    context.set_deadline(deadline);
    
    grpc::Status status = stub_->SendSnapshot(&context, proto_snapshot, &response);
    
    if (status.ok()) {
        if (response.success()) {
            std::cout << "[GrpcClient] ✓ " << response.message() << std::endl;
            return true;
        } else {
            std::cerr << "[GrpcClient] ✗ Server rejected: " << response.message() << std::endl;
            return false;
        }
    } else {
        std::cerr << "[GrpcClient] ✗ RPC failed: " << status.error_code() 
                  << " - " << status.error_message() << std::endl;
        return false;
    }
}

} // namespace monitor