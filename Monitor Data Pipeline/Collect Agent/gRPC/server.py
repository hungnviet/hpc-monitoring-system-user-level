import grpc
from concurrent import futures
import time
import sys
import os

# Add path to generated protobuf files
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'generated'))

import monitor_pb2
import monitor_pb2_grpc

class MonitorServiceServicer(monitor_pb2_grpc.MonitorServiceServicer):
    def __init__(self):
        self.snapshot_count = 0
        self.total_processes = 0
    
    def SendSnapshot(self, request, context):
        self.snapshot_count += 1
        self.total_processes += len(request.processes)
        
        print(f"\n{'='*80}")
        print(f"Received Snapshot #{self.snapshot_count}")
        print(f"{'='*80}")
        print(f"Node ID: {request.node_id}")
        print(f"Timestamp: {request.timestamp}")
        print(f"Processes: {len(request.processes)}")
        
        # GPU State
        gpu = request.gpu_global_state
        print(f"\nGPU State:")
        print(f"  Power: {gpu.power_watts:.2f}W")
        print(f"  Temperature: {gpu.temperature_celsius}°C")
        print(f"  Utilization: {gpu.total_load_percent}%")
        
        # Top 10 CPU processes
        processes = sorted(request.processes, key=lambda p: p.cpu_usage_percent, reverse=True)
        print(f"\nTop 10 CPU Processes:")
        print(f"{'PID':<10} {'UID':<10} {'CPU%':<10} {'MEM(MB)':<12} {'GPU_SM%':<10} {'COMMAND':<20}")
        print("-" * 80)
        
        for i, proc in enumerate(processes[:10]):
            mem_mb = proc.memory_bytes / (1024 * 1024)
            gpu_sm = proc.gpu_sm_percent if proc.gpu_sm_percent >= 0 else 0
            print(f"{proc.pid:<10} {proc.uid:<10} {proc.cpu_usage_percent:<10.2f} "
                  f"{mem_mb:<12.2f} {gpu_sm:<10.1f} {proc.command:<20}")
        
        # Statistics
        print(f"\nServer Statistics:")
        print(f"  Total snapshots received: {self.snapshot_count}")
        print(f"  Total processes seen: {self.total_processes}")
        print(f"  Avg processes/snapshot: {self.total_processes/self.snapshot_count:.1f}")
        
        return monitor_pb2.SnapshotResponse(
            success=True,
            message=f"Received snapshot #{self.snapshot_count} with {len(request.processes)} processes",
            server_timestamp=int(time.time())
        )

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    monitor_pb2_grpc.add_MonitorServiceServicer_to_server(
        MonitorServiceServicer(), server
    )
    
    server.add_insecure_port('[::]:50051')
    server.start()
    
    print("="*80)
    print("gRPC Monitor Server Started")
    print("="*80)
    print("Listening on port 50051")
    print("Waiting for compute node connections...\n")
    
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        print("\n\nShutting down gracefully...")
        server.stop(0)

if __name__ == '__main__':
    serve()