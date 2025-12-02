#!/usr/bin/env python3
"""
MQTT Server for Collect Agent

Receives monitoring data from compute nodes via MQTT protocol.
Implements modular architecture:
1. Receive MQTT messages
2. Convert JSON to common schema
3. Process via DataProcessor
4. Publish to Kafka
"""

import paho.mqtt.client as mqtt
import json
import time
import sys
import os
import logging
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from common.schema import MonitoringSnapshot, ProcessMetrics, GpuState
from processing.processor import DataProcessor
from publishing.kafka_publisher import KafkaPublisher, MockKafkaPublisher


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class MqttServerAdapter:
    """
    MQTT Server Adapter - Input Layer

    Responsibilities:
    1. Connect to MQTT broker and subscribe to topic
    2. Receive MQTT messages
    3. Convert JSON to common schema (MonitoringSnapshot)
    4. Pass to processor and publisher
    """

    def __init__(self, broker_address: str, port: int, topic: str,
                 processor: DataProcessor, publisher: KafkaPublisher):
        self.broker_address = broker_address
        self.port = port
        self.topic = topic
        self.processor = processor
        self.publisher = publisher
        self.snapshot_count = 0
        self.logger = logging.getLogger(f"{__name__}.MqttServerAdapter")
        self.client = None

    def on_connect(self, client, userdata, flags, rc):
        """Callback when connected to MQTT broker"""
        if rc == 0:
            self.logger.info(f"✓ Connected to MQTT broker at {self.broker_address}:{self.port}")
            self.logger.info(f"Subscribing to topic: {self.topic}")
            client.subscribe(self.topic, qos=1)
            self.logger.info(f"✓ Subscribed successfully")
        else:
            self.logger.error(f"✗ Connection failed with code {rc}")

    def on_disconnect(self, client, userdata, rc):
        """Callback when disconnected from MQTT broker"""
        if rc != 0:
            self.logger.warning(f"Unexpected disconnection (code {rc})")

    def on_message(self, client, userdata, msg):
        """Callback when message is received"""
        self.snapshot_count += 1

        try:
            # Step 1: Parse JSON payload
            payload = msg.payload.decode('utf-8')
            data = json.loads(payload)

            # Step 2: Convert JSON to common schema
            snapshot = self._convert_from_json(data)
            snapshot.source_protocol = 'MQTT'

            self.logger.info(
                f"Received snapshot #{self.snapshot_count} from {snapshot.node_id} "
                f"({len(snapshot.processes)} processes)"
            )

            # Step 3: Process data
            processed_data = self.processor.process(snapshot)

            if processed_data is None:
                self.logger.error(f"Processing failed for snapshot from {snapshot.node_id}")
                return

            # Step 4: Publish to Kafka
            publish_success = self.publisher.publish(processed_data)

            if not publish_success:
                self.logger.error(f"Kafka publish failed for snapshot from {snapshot.node_id}")

        except json.JSONDecodeError as e:
            self.logger.error(f"✗ Failed to parse JSON: {e}")
        except Exception as e:
            self.logger.error(f"✗ Error processing message: {e}", exc_info=True)

    def _convert_from_json(self, data: dict) -> MonitoringSnapshot:
        """
        Convert JSON dict to common MonitoringSnapshot schema.

        Args:
            data: Parsed JSON dict

        Returns:
            MonitoringSnapshot object
        """
        # Convert GPU state
        gpu_data = data.get('gpu_global_state', {})
        gpu_state = GpuState(
            power_watts=gpu_data.get('power_watts', 0.0),
            temperature_celsius=gpu_data.get('temperature_celsius', 0),
            total_load_percent=gpu_data.get('total_load_percent', 0)
        )

        # Convert processes
        processes = []
        for proc_data in data.get('processes', []):
            processes.append(ProcessMetrics(
                pid=proc_data.get('pid', 0),
                uid=proc_data.get('uid', 0),
                command=proc_data.get('command', ''),
                cpu_usage_percent=proc_data.get('cpu_usage_percent', 0.0),
                memory_bytes=proc_data.get('memory_bytes', 0),
                gpu_sm_percent=proc_data.get('gpu_sm_percent', -1.0),
                gpu_mem_percent=proc_data.get('gpu_mem_percent', -1.0),
                gpu_mem_mib=proc_data.get('gpu_mem_mib', 0)
            ))

        # Create snapshot
        return MonitoringSnapshot(
            timestamp=data.get('timestamp', 0),
            node_id=data.get('node_id', 'unknown'),
            gpu_global_state=gpu_state,
            processes=processes
        )

    def start(self):
        """Start the MQTT server"""
        logger.info("="*80)
        logger.info("MQTT Monitoring Server (Modular Architecture)")
        logger.info("="*80)
        logger.info(f"Broker: {self.broker_address}:{self.port}")
        logger.info(f"Topic: {self.topic}")
        logger.info("Waiting for compute node connections...")
        logger.info("="*80 + "\n")

        # Create MQTT client
        self.client = mqtt.Client(client_id="collect_agent_mqtt_server")

        # Set callbacks
        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect
        self.client.on_message = self.on_message

        try:
            # Connect to broker
            self.client.connect(self.broker_address, self.port, keepalive=60)

            # Start loop (blocking)
            self.client.loop_forever()

        except KeyboardInterrupt:
            logger.info("\n\nShutting down gracefully...")

            # Print statistics
            logger.info("\n=== Statistics ===")
            logger.info(f"Processor: {self.processor.get_statistics()}")
            logger.info(f"Publisher: {self.publisher.get_statistics()}")

            self.publisher.close()
            self.client.disconnect()
            logger.info("✓ MQTT server stopped")

        except Exception as e:
            logger.error(f"✗ Error: {e}", exc_info=True)
            sys.exit(1)


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


def main():
    """Main entry point"""
    # Load configuration
    config = load_config()
    mqtt_config = config.get('mqtt_broker', {})
    kafka_config = config.get('kafka', {})
    processing_config = config.get('processing', {})

    # Extract MQTT configuration
    broker_address = mqtt_config.get('address', 'localhost')
    port = mqtt_config.get('port', 1883)
    topic = mqtt_config.get('topic', 'monitoring/compute-node')

    logger.info(f"MQTT Configuration: {broker_address}:{port}, topic={topic}")
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

    logger.info("\n[3/3] Initializing MQTT Server...")
    server = MqttServerAdapter(broker_address, port, topic, processor, publisher)
    logger.info("✓ MQTT Server ready\n")

    # Start server
    server.start()


if __name__ == '__main__':
    main()
