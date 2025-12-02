"""
Kafka Publisher - Output Adapter

This module handles publishing processed monitoring data to Kafka topics.
"""

import logging
import json
from typing import Dict, Any, Optional
from kafka import KafkaProducer
from kafka.errors import KafkaError
import time


class KafkaPublisher:
    """
    Publishes processed monitoring data to Kafka topics.

    Responsibilities:
    1. Maintain connection to Kafka broker
    2. Serialize data to JSON
    3. Publish to configured topics
    4. Handle errors and retries
    5. Track publishing statistics
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Kafka publisher.

        Args:
            config: Configuration dictionary with Kafka settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Kafka configuration
        self.bootstrap_servers = config.get('bootstrap_servers', ['localhost:9092'])
        self.topic = config.get('topic', 'monitoring-data')
        self.key_field = config.get('key_field', 'node_id')  # Field to use as message key

        # Statistics
        self.published_count = 0
        self.failed_count = 0
        self.total_bytes_sent = 0

        # Initialize producer
        self.producer = None
        self._connect()

    def _connect(self):
        """Establish connection to Kafka broker"""
        try:
            self.logger.info(f"Connecting to Kafka brokers: {self.bootstrap_servers}")

            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None,
                acks='all',  # Wait for all replicas to acknowledge
                retries=3,
                max_in_flight_requests_per_connection=5,
                compression_type='gzip',  # Compress messages
            )

            self.logger.info("✓ Connected to Kafka successfully")

        except KafkaError as e:
            self.logger.error(f"Failed to connect to Kafka: {e}")
            raise

    def publish(self, data: Dict[str, Any]) -> bool:
        """
        Publish processed data to Kafka topic.

        Args:
            data: Processed monitoring data

        Returns:
            True if published successfully, False otherwise
        """
        if not self.producer:
            self.logger.error("Kafka producer not initialized")
            return False

        try:
            # Extract key from data
            key = data.get(self.key_field, None)

            # Send to Kafka
            future = self.producer.send(
                topic=self.topic,
                value=data,
                key=key
            )

            # Wait for acknowledgment (with timeout)
            record_metadata = future.get(timeout=10)

            # Update statistics
            self.published_count += 1
            message_bytes = len(json.dumps(data).encode('utf-8'))
            self.total_bytes_sent += message_bytes

            self.logger.info(
                f"✓ Published to Kafka: topic={record_metadata.topic}, "
                f"partition={record_metadata.partition}, "
                f"offset={record_metadata.offset}, "
                f"size={message_bytes} bytes"
            )

            return True

        except KafkaError as e:
            self.failed_count += 1
            self.logger.error(f"✗ Failed to publish to Kafka: {e}")
            return False
        except Exception as e:
            self.failed_count += 1
            self.logger.error(f"✗ Unexpected error publishing to Kafka: {e}", exc_info=True)
            return False

    def publish_batch(self, data_list: list) -> int:
        """
        Publish multiple messages in batch.

        Args:
            data_list: List of data dictionaries to publish

        Returns:
            Number of successfully published messages
        """
        success_count = 0

        for data in data_list:
            if self.publish(data):
                success_count += 1

        # Flush to ensure all messages are sent
        self.producer.flush()

        return success_count

    def close(self):
        """Close the Kafka producer connection"""
        if self.producer:
            self.logger.info("Closing Kafka producer...")
            self.producer.flush()
            self.producer.close()
            self.logger.info("✓ Kafka producer closed")

    def get_statistics(self) -> Dict[str, Any]:
        """Get publishing statistics"""
        return {
            'published_count': self.published_count,
            'failed_count': self.failed_count,
            'total_bytes_sent': self.total_bytes_sent,
            'total_mb_sent': round(self.total_bytes_sent / (1024 * 1024), 2),
            'success_rate': (
                self.published_count / (self.published_count + self.failed_count)
                if (self.published_count + self.failed_count) > 0
                else 0
            )
        }

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


class MockKafkaPublisher(KafkaPublisher):
    """
    Mock Kafka publisher for testing without real Kafka.

    This publisher logs messages instead of sending to Kafka.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize mock publisher"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.topic = config.get('topic', 'monitoring-data')

        # Statistics
        self.published_count = 0
        self.failed_count = 0
        self.total_bytes_sent = 0

        self.logger.info("✓ MockKafkaPublisher initialized (no real Kafka connection)")

    def _connect(self):
        """No-op for mock publisher"""
        pass

    def publish(self, data: Dict[str, Any]) -> bool:
        """
        Mock publish - just logs the data.

        Args:
            data: Data to "publish"

        Returns:
            Always True
        """
        try:
            message_json = json.dumps(data, indent=2)
            message_bytes = len(message_json.encode('utf-8'))

            self.published_count += 1
            self.total_bytes_sent += message_bytes

            self.logger.info(f"[MOCK] Would publish to topic '{self.topic}':")
            self.logger.info(f"  Node: {data.get('node_id', 'unknown')}")
            self.logger.info(f"  Timestamp: {data.get('timestamp', 0)}")
            self.logger.info(f"  Processes: {len(data.get('processes', []))}")
            self.logger.info(f"  Size: {message_bytes} bytes")

            return True

        except Exception as e:
            self.failed_count += 1
            self.logger.error(f"✗ Mock publish error: {e}")
            return False

    def close(self):
        """No-op for mock publisher"""
        self.logger.info("MockKafkaPublisher closed")
