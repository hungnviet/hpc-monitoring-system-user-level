#!/usr/bin/env python3
"""
Unified gRPC Server Launcher

This script starts the gRPC collection server from the Collect Agent root directory.
It receives monitoring data via gRPC, processes it, and publishes to Kafka.

Usage:
    python3 run_grpc_server.py [--config CONFIG_PATH] [--port PORT]

Examples:
    python3 run_grpc_server.py
    python3 run_grpc_server.py --port 50052
    python3 run_grpc_server.py --config custom_config.json
"""

import sys
import os
import argparse
import json
import logging

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import colorlog
    HAS_COLORLOG = True
except ImportError:
    HAS_COLORLOG = False


def check_virtual_env():
    """Check if virtual environment is activated"""
    in_venv = hasattr(sys, 'prefix') and sys.prefix != sys.base_prefix

    if not in_venv:
        print("=" * 80)
        print("  ERROR: Virtual Environment Not Activated")
        print("=" * 80)
        print()
        print("You must activate the virtual environment before running this script.")
        print()
        print("Steps:")
        print("  1. cd 'Monitor Data Pipeline/Collect Agent'")
        print("  2. source venv/bin/activate")
        print("  3. python3 run_grpc_server.py")
        print()
        print("Or run everything at once:")
        print("  source venv/bin/activate && python3 run_grpc_server.py")
        print()
        sys.exit(1)


def setup_logging():
    """Setup colored logging if available"""
    if HAS_COLORLOG:
        handler = colorlog.StreamHandler()
        handler.setFormatter(colorlog.ColoredFormatter(
            '%(log_color)s[%(asctime)s] [%(name)s] [%(levelname)s]%(reset)s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            }
        ))
        logging.basicConfig(level=logging.INFO, handlers=[handler])
    else:
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )


def load_config(config_path: str) -> dict:
    """Load configuration from JSON file"""
    logger = logging.getLogger(__name__)

    if not os.path.exists(config_path):
        logger.warning(f"Config file not found: {config_path}")
        logger.info("Using default configuration")
        return {}

    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            logger.info(f"✓ Loaded configuration from {config_path}")
            return config
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse config file: {e}")
        logger.info("Using default configuration")
        return {}
    except Exception as e:
        logger.error(f"Error reading config file: {e}")
        return {}


def main():
    """Main entry point"""
    # Check if virtual environment is activated
    check_virtual_env()

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Start the gRPC monitoring collection server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                              # Start with default config
  %(prog)s --port 50052                 # Start on custom port
  %(prog)s --config my_config.json      # Use custom config file
        '''
    )
    parser.add_argument(
        '--config',
        default='../../infra.json',
        help='Path to configuration file (default: ../../infra.json)'
    )
    parser.add_argument(
        '--port',
        type=int,
        help='gRPC server port (overrides config file)'
    )
    parser.add_argument(
        '--mock-kafka',
        action='store_true',
        help='Use mock Kafka publisher (no real Kafka required)'
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)

    # Print banner
    print("=" * 80)
    print("  gRPC Monitoring Collection Server")
    print("=" * 80)
    print()

    # Load configuration
    config = load_config(args.config)

    # Import gRPC server module
    try:
        from gRPC.server import serve, GrpcServerAdapter
        import grpc
        from concurrent import futures
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'gRPC', 'generated'))
        import monitor_pb2
        import monitor_pb2_grpc
    except ImportError as e:
        logger.error(f"Failed to import gRPC modules: {e}")
        logger.error("Make sure you have generated the protobuf files:")
        logger.error("  cd gRPC && python3 -m grpc_tools.protoc ...")
        sys.exit(1)

    # Import processing and publishing modules
    try:
        from processing.processor import DataProcessor
        from publishing.kafka_publisher import KafkaPublisher, MockKafkaPublisher
    except ImportError as e:
        logger.error(f"Failed to import modules: {e}")
        logger.error("Make sure all dependencies are installed:")
        logger.error("  pip install -r requirements.txt")
        sys.exit(1)

    # Extract configuration
    grpc_config = config.get('grpc_server', {})
    kafka_config = config.get('kafka', {})
    processing_config = config.get('processing', {})

    # Override config with command line arguments
    if args.port:
        grpc_config['port'] = args.port
    if args.mock_kafka:
        kafka_config['use_mock'] = True

    # Extract gRPC settings
    address = grpc_config.get('address', 'localhost:50051')
    if ':' in address:
        host, port = address.rsplit(':', 1)
        port = int(port)
    else:
        host = '0.0.0.0'
        port = grpc_config.get('port', 50051)

    logger.info(f"Configuration:")
    logger.info(f"  gRPC: {host}:{port}")
    logger.info(f"  Kafka: {kafka_config.get('bootstrap_servers', ['localhost:9092'])}")
    logger.info(f"  Topic: {kafka_config.get('topic', 'raw_data')}")
    logger.info(f"  Mock Kafka: {kafka_config.get('use_mock', False)}")
    print()

    # Initialize components
    logger.info("[1/3] Initializing DataProcessor...")
    processor = DataProcessor(processing_config)
    logger.info("✓ DataProcessor ready")
    print()

    logger.info("[2/3] Initializing KafkaPublisher...")
    use_mock = kafka_config.get('use_mock', False)
    if use_mock:
        logger.info("Using MockKafkaPublisher (no real Kafka)")
        publisher = MockKafkaPublisher(kafka_config)
    else:
        try:
            publisher = KafkaPublisher(kafka_config)
        except Exception as e:
            logger.error(f"Failed to connect to Kafka: {e}")
            logger.info("Falling back to MockKafkaPublisher")
            publisher = MockKafkaPublisher(kafka_config)
    logger.info("✓ KafkaPublisher ready")
    print()

    logger.info("[3/3] Initializing gRPC Server...")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    monitor_pb2_grpc.add_MonitorServiceServicer_to_server(
        GrpcServerAdapter(processor, publisher), server
    )

    server.add_insecure_port(f'[::]:{port}')
    server.start()
    logger.info(f"✓ gRPC Server listening on port {port}")
    print()

    print("=" * 80)
    print("  Server ready - waiting for compute node connections...")
    print("  Press Ctrl+C to stop")
    print("=" * 80)
    print()

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("\n\nShutting down gracefully...")

        # Print statistics
        print()
        logger.info("=== Statistics ===")
        logger.info(f"Processor: {processor.get_statistics()}")
        logger.info(f"Publisher: {publisher.get_statistics()}")

        publisher.close()
        server.stop(0)
        logger.info("✓ Server stopped")


if __name__ == '__main__':
    main()
