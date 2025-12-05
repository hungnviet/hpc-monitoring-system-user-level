#!/usr/bin/env python3
"""
Unified MQTT Server Launcher

This script starts the MQTT collection server from the Collect Agent root directory.
It subscribes to MQTT topic, receives monitoring data, processes it, and publishes to Kafka.

Usage:
    python3 run_mqtt_server.py [--config CONFIG_PATH] [--broker BROKER] [--topic TOPIC]

Examples:
    python3 run_mqtt_server.py
    python3 run_mqtt_server.py --broker localhost --topic monitoring/nodes
    python3 run_mqtt_server.py --config custom_config.json --mock-kafka
"""

import sys
import os
import argparse
import json
import logging
import subprocess
import time

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
        print("  3. python3 run_mqtt_server.py")
        print()
        print("Or run everything at once:")
        print("  source venv/bin/activate && python3 run_mqtt_server.py")
        print()
        sys.exit(1)


def check_docker():
    """Check if Docker is installed and running"""
    try:
        subprocess.run(['docker', 'info'],
                      stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL,
                      check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def is_mqtt_broker_running():
    """Check if MQTT broker container is running"""
    try:
        result = subprocess.run(['docker', 'ps', '--filter', 'name=mqtt-broker', '--format', '{{.Names}}'],
                              capture_output=True, text=True, check=True)
        return 'mqtt-broker' in result.stdout
    except:
        return False


def start_mqtt_broker():
    """Start the MQTT broker using docker-compose"""
    logger = logging.getLogger(__name__)

    mqtt_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'MQTT')
    compose_file = os.path.join(mqtt_dir, 'docker-compose.yml')

    if not os.path.exists(compose_file):
        logger.error(f"Docker Compose file not found: {compose_file}")
        return False

    logger.info("Starting MQTT broker (Mosquitto)...")

    try:
        # Create directories if they don't exist
        os.makedirs(os.path.join(mqtt_dir, 'mosquitto', 'data'), exist_ok=True)
        os.makedirs(os.path.join(mqtt_dir, 'mosquitto', 'log'), exist_ok=True)

        # Start broker using docker-compose
        result = subprocess.run(['docker', 'compose', '-f', compose_file, 'up', '-d'],
                              capture_output=True, text=True, check=True)

        # Wait a moment for broker to be ready
        time.sleep(2)

        # Verify broker is running
        if is_mqtt_broker_running():
            logger.info("✓ MQTT broker started successfully")
            return True
        else:
            logger.error("MQTT broker failed to start")
            return False

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to start MQTT broker: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"Error starting MQTT broker: {e}")
        return False


def ensure_mqtt_broker():
    """Ensure MQTT broker is running, start it if needed"""
    logger = logging.getLogger(__name__)

    # Check if Docker is available
    if not check_docker():
        logger.warning("Docker is not available")
        logger.warning("MQTT broker requires Docker to be installed and running")
        logger.warning("Install Docker from: https://www.docker.com/get-started")
        logger.warning("")
        logger.warning("Or start MQTT broker manually:")
        logger.warning("  cd MQTT && ./mqtt-broker.sh start")
        return False

    # Check if broker is already running
    if is_mqtt_broker_running():
        logger.info("✓ MQTT broker is already running")
        return True

    # Try to start the broker
    logger.info("MQTT broker is not running, attempting to start...")
    return start_mqtt_broker()


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
        description='Start the MQTT monitoring collection server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                                    # Start with default config
  %(prog)s --broker localhost --port 1883     # Custom broker
  %(prog)s --topic monitoring/my-nodes        # Custom topic
  %(prog)s --mock-kafka                       # Use mock Kafka
        '''
    )
    parser.add_argument(
        '--config',
        default='../../infra.json',
        help='Path to configuration file (default: ../../infra.json)'
    )
    parser.add_argument(
        '--broker',
        help='MQTT broker address (overrides config file)'
    )
    parser.add_argument(
        '--port',
        type=int,
        help='MQTT broker port (overrides config file)'
    )
    parser.add_argument(
        '--topic',
        help='MQTT topic to subscribe to (overrides config file)'
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
    print("  MQTT Monitoring Collection Server")
    print("=" * 80)
    print()

    # Ensure MQTT broker is running
    logger.info("[0/4] Checking MQTT Broker...")
    if not ensure_mqtt_broker():
        logger.error("MQTT broker is not available and could not be started")
        logger.error("Please start it manually or check Docker installation")
        sys.exit(1)
    print()

    # Load configuration
    config = load_config(args.config)

    # Import MQTT server module
    try:
        from MQTT.server import MqttServerAdapter
        import paho.mqtt.client as mqtt
    except ImportError as e:
        logger.error(f"Failed to import MQTT modules: {e}")
        logger.error("Make sure all dependencies are installed:")
        logger.error("  pip install -r requirements.txt")
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
    mqtt_config = config.get('mqtt_broker', {})
    kafka_config = config.get('kafka', {})
    processing_config = config.get('processing', {})

    # Override config with command line arguments
    if args.broker:
        mqtt_config['address'] = args.broker
    if args.port:
        mqtt_config['port'] = args.port
    if args.topic:
        mqtt_config['topic'] = args.topic
    if args.mock_kafka:
        kafka_config['use_mock'] = True

    # Extract MQTT settings
    broker_address = mqtt_config.get('address', 'localhost')
    port = mqtt_config.get('port', 1883)
    topic = mqtt_config.get('topic', 'monitoring/compute-node')

    logger.info(f"Configuration:")
    logger.info(f"  MQTT Broker: {broker_address}:{port}")
    logger.info(f"  MQTT Topic: {topic}")
    logger.info(f"  Kafka: {kafka_config.get('bootstrap_servers', ['localhost:9092'])}")
    logger.info(f"  Kafka Topic: {kafka_config.get('topic', 'raw_data')}")
    logger.info(f"  Mock Kafka: {kafka_config.get('use_mock', False)}")
    print()

    # Initialize components
    logger.info("[1/4] Initializing DataProcessor...")
    processor = DataProcessor(processing_config)
    logger.info("✓ DataProcessor ready")
    print()

    logger.info("[2/4] Initializing KafkaPublisher...")
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

    logger.info("[3/4] Initializing MQTT Server...")
    server = MqttServerAdapter(broker_address, port, topic, processor, publisher)
    logger.info("✓ MQTT Server ready")
    print()

    logger.info("[4/4] Connecting to MQTT Broker...")
    logger.info(f"Broker: {broker_address}:{port}")
    logger.info(f"Topic: {topic}")

    print("=" * 80)
    print("  Server ready - waiting for MQTT messages...")
    print("  Press Ctrl+C to stop")
    print("=" * 80)
    print()

    # Start server
    server.start()


if __name__ == '__main__':
    main()
