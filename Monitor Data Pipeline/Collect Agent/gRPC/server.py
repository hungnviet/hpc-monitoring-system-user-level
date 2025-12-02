#!/usr/bin/env python3
"""
gRPC Server for Collect Agent

Receives monitoring data from compute nodes via gRPC protocol.
Implements modular architecture:
1. Receive gRPC data
2. Convert to common schema
3. Process via DataProcessor
4. Publish to Kafka
"""

import grpc
from concurrent import futures
import time
import sys
import os
import json
import logging
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Add path to generated protobuf files
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'generated'))

import monitor_pb2
import monitor_pb2_grpc

from common.schema import MonitoringSnapshot, ProcessMetrics, GpuState
from processing.processor import DataProcessor
from publishing.kafka_publisher import KafkaPublisher, MockKafkaPublisher


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class GrpcServerAdapter(monitor_pb2_grpc.MonitorServiceServicer):
    """
    gRPC Server Adapter - Input Layer

    Responsibilities:
    1. Receive gRPC requests
    2. Convert protobuf to common schema (MonitoringSnapshot)
    3. Pass to processor
    4. Return response
    """

    def __init__(self, processor: DataProcessor, publisher: KafkaPublisher):
        self.processor = processor
        self.publisher = publisher
        self.snapshot_count = 0
        self.logger = logging.getLogger(f"{__name__}.GrpcServerAdapter")

    def SendSnapshot(self, request, context):
        """Handle incoming snapshot from compute node"""
        self.snapshot_count += 1

        try:
            # Step 1: Convert protobuf to common schema
            snapshot = self._convert_from_protobuf(request)
            snapshot.source_protocol = 'gRPC'

            self.logger.info(
                f"Received snapshot #{self.snapshot_count} from {snapshot.node_id} "
                f"({len(snapshot.processes)} processes)"
            )

            # Step 2: Process data
            processed_data = self.processor.process(snapshot)

            if processed_data is None:
                self.logger.error(f"Processing failed for snapshot from {snapshot.node_id}")
                return monitor_pb2.SnapshotResponse(
                    success=False,
                    message="Processing failed",
                    server_timestamp=int(time.time())
                )

            # Step 3: Publish to Kafka
            publish_success = self.publisher.publish(processed_data)

            if not publish_success:
                self.logger.error(f"Kafka publish failed for snapshot from {snapshot.node_id}")

            # Step 4: Return response
            return monitor_pb2.SnapshotResponse(
                success=True,
                message=f"Processed and published snapshot #{self.snapshot_count}",
                server_timestamp=int(time.time())
            )

        except Exception as e:
            self.logger.error(f"Error handling snapshot: {e}", exc_info=True)
            return monitor_pb2.SnapshotResponse(
                success=False,
                message=f"Error: {str(e)}",
                server_timestamp=int(time.time())
            )

    def _convert_from_protobuf(self, request) -> MonitoringSnapshot:
        """
        Convert protobuf message to common MonitoringSnapshot schema.

        Args:
            request: gRPC protobuf request

        Returns:
            MonitoringSnapshot object
        """
        # Convert GPU state
        gpu_state = GpuState(
            power_watts=request.gpu_global_state.power_watts,
            temperature_celsius=request.gpu_global_state.temperature_celsius,
            total_load_percent=request.gpu_global_state.total_load_percent
        )

        # Convert processes
        processes = []
        for proc in request.processes:
            processes.append(ProcessMetrics(
                pid=proc.pid,
                uid=proc.uid,
                command=proc.command,
                cpu_usage_percent=proc.cpu_usage_percent,
                memory_bytes=proc.memory_bytes,
                gpu_sm_percent=proc.gpu_sm_percent,
                gpu_mem_percent=proc.gpu_mem_percent,
                gpu_mem_mib=proc.gpu_mem_mib
            ))

        # Create snapshot
        return MonitoringSnapshot(
            timestamp=request.timestamp,
            node_id=request.node_id,
            gpu_global_state=gpu_state,
            processes=processes
        )


def load_config():
    """Load configuration from infra.json"""
    config_path = "../../../infra.json"

    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            return config
    except FileNotFoundError:
        logger.warning(f"Config file not found at {config_path}, using defaults")
        return {}
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse config: {e}, using defaults")
        return {}


def serve():
    """Start gRPC server with modular architecture"""
    logger.info("="*80)
    logger.info("gRPC Monitoring Server (Modular Architecture)")
    logger.info("="*80)

    # Load configuration
    config = load_config()
    grpc_config = config.get('grpc_server', {})
    kafka_config = config.get('kafka', {})
    processing_config = config.get('processing', {})

    # Extract gRPC settings
    address = grpc_config.get('address', 'localhost:50051')
    if ':' in address:
        host, port = address.rsplit(':', 1)
        port = int(port)
    else:
        host = '0.0.0.0'
        port = 50051

    logger.info(f"gRPC Configuration: {host}:{port}")
    logger.info(f"Kafka Configuration: {kafka_config}")
    logger.info(f"Processing Configuration: {processing_config}")

    # Initialize components (Modular Design)
    logger.info("\n[1/3] Initializing DataProcessor...")
    processor = DataProcessor(processing_config)
    logger.info("✓ DataProcessor ready")

    logger.info("\n[2/3] Initializing KafkaPublisher...")
    use_mock = kafka_config.get('use_mock', True)
    if use_mock:
        logger.info("Using MockKafkaPublisher (no real Kafka)")
        publisher = MockKafkaPublisher(kafka_config)
    else:
        publisher = KafkaPublisher(kafka_config)
    logger.info("✓ KafkaPublisher ready")

    logger.info("\n[3/3] Initializing gRPC Server...")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    monitor_pb2_grpc.add_MonitorServiceServicer_to_server(
        GrpcServerAdapter(processor, publisher), server
    )

    server.add_insecure_port(f'[::]:{port}')
    server.start()
    logger.info(f"✓ gRPC Server listening on port {port}")

    logger.info("\n" + "="*80)
    logger.info("Server ready - waiting for compute node connections...")
    logger.info("="*80 + "\n")

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("\n\nShutting down gracefully...")

        # Print statistics
        logger.info("\n=== Statistics ===")
        logger.info(f"Processor: {processor.get_statistics()}")
        logger.info(f"Publisher: {publisher.get_statistics()}")

        publisher.close()
        server.stop(0)
        logger.info("✓ Server stopped")


if __name__ == '__main__':
    serve()
