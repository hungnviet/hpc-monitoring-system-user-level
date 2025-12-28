#!/usr/bin/env python3

import sys
import logging
import grpc
from concurrent import futures
import signal
import time
from pathlib import Path

# Add current directory to path to import proto
sys.path.insert(0, str(Path(__file__).parent))
from proto import metrics_pb2, metrics_pb2_grpc

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MetricsCollectorServicer(metrics_pb2_grpc.MetricsCollectorServicer):
    def __init__(self):
        self.total_reports = 0
        self.total_processes = 0

    def StreamMetrics(self, request_iterator, context):
        peer = context.peer()
        logger.info(f"New client connected: {peer}")

        try:
            for report in request_iterator:
                self.total_reports += 1
                process_count = len(report.processes)
                self.total_processes += process_count

                logger.info("=" * 80)
                logger.info(f"Received metrics report #{self.total_reports}")
                logger.info(f"  Node ID: {report.node_id}")
                logger.info(f"  Timestamp: {report.timestamp}")
                logger.info(f"  Collection Window: {report.collection_window_seconds}s")
                logger.info(f"  Process Count: {process_count}")
                logger.info("-" * 80)

                if process_count > 0:
                    sorted_processes = sorted(
                        report.processes,
                        key=lambda p: p.cpu_ontime_ns,
                        reverse=True
                    )[:5]

                    logger.info("Top 5 processes by CPU time:")
                    for i, proc in enumerate(sorted_processes, 1):
                        logger.info(
                            f"  {i}. PID {proc.pid:6d} | "
                            f"CPU: {proc.cpu_ontime_ns:12d}ns | "
                            f"RAM: {proc.avg_rss_bytes:12d}B | "
                            f"Disk R/W: {proc.read_bytes}/{proc.write_bytes}B | "
                            f"Net RX/TX: {proc.net_rx_bytes}/{proc.net_tx_bytes}B | "
                            f"GPU: {proc.gpu_used_memory_mib}MiB | "
                            f"CMD: {proc.comm}"
                        )

                logger.info("=" * 80)
                logger.info(f"Total reports received: {self.total_reports}")
                logger.info(f"Total processes tracked: {self.total_processes}")
                logger.info("=" * 80)

        except Exception as e:
            logger.error(f"Error processing stream: {e}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Error processing metrics: {str(e)}")
            return metrics_pb2.StreamResponse(success=False, message=str(e))

        logger.info(f"Client disconnected: {peer}")
        return metrics_pb2.StreamResponse(
            success=True,
            message=f"Received {self.total_reports} reports"
        )


class SimpleGrpcServer:
    """Simple gRPC server for testing."""

    def __init__(self, port=50051, max_workers=10):
        self.port = port
        self.max_workers = max_workers
        self.server = None

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)

    def start(self):
        """Start the gRPC server."""
        logger.info("=" * 80)
        logger.info("Starting Simple gRPC Metrics Collection Server")
        logger.info("=" * 80)

        # Create server
        self.server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=self.max_workers),
            options=[
                ('grpc.max_send_message_length', 100 * 1024 * 1024),  # 100MB
                ('grpc.max_receive_message_length', 100 * 1024 * 1024),  # 100MB
            ]
        )

        # Add servicer
        metrics_pb2_grpc.add_MetricsCollectorServicer_to_server(
            MetricsCollectorServicer(),
            self.server
        )

        # Bind to port
        server_address = f'[::]:{self.port}'
        self.server.add_insecure_port(server_address)

        # Start server
        self.server.start()

        logger.info(f"Server started on port {self.port}")
        logger.info(f"Listening on {server_address}")
        logger.info("Waiting for connections from compute node agents...")
        logger.info("=" * 80)

        # Keep server running
        try:
            self.server.wait_for_termination()
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
            self.stop()

    def stop(self):
        """Stop the gRPC server."""
        if self.server:
            logger.info("Stopping gRPC server...")
            self.server.stop(grace=5)
            logger.info("Server stopped")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Simple gRPC Metrics Collection Server')
    parser.add_argument(
        '--port',
        type=int,
        default=50051,
        help='Port to listen on (default: 50051)'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=10,
        help='Maximum number of worker threads (default: 10)'
    )

    args = parser.parse_args()

    server = SimpleGrpcServer(port=args.port, max_workers=args.workers)
    server.start()


if __name__ == '__main__':
    main()
