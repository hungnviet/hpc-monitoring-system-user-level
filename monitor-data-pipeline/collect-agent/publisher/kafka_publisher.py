import json
import asyncio
from typing import List
from aiokafka import AIOKafkaProducer
from publisher.base import Publisher
from models import MetricBatch
from utils import get_logger


logger = get_logger(__name__)


class KafkaPublisher(Publisher):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, brokers: List[str], topic: str):
        if not hasattr(self, '_initialized'):
            self.brokers = brokers
            self.topic = topic
            self.producer = None
            self._initialized = True

    async def start(self):
        try:
            logger.info(f"Starting Kafka producer for brokers: {self.brokers}")
            self.producer = AIOKafkaProducer(
                bootstrap_servers=self.brokers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                compression_type='gzip',
                max_batch_size=65536,
                linger_ms=10
            )
            await self.producer.start()
            logger.info("Kafka producer started successfully")
        except Exception as e:
            logger.error(f"Failed to start Kafka producer: {e}")
            raise

    async def publish(self, batches: List[MetricBatch]):
        if not self.producer:
            logger.error("Kafka producer not started")
            return

        for batch in batches:
            try:
                message = self._serialize_batch(batch)
                await self.producer.send_and_wait(
                    self.topic,
                    value=message,
                    key=batch.node_id.encode('utf-8')
                )
                logger.debug(f"Published batch from {batch.node_id} to Kafka")
            except Exception as e:
                logger.error(f"Error publishing batch to Kafka: {e}")

    def _serialize_batch(self, batch: MetricBatch) -> dict:
        result = {
            'node_id': batch.node_id,
            'timestamp': batch.timestamp,
            'collection_window_seconds': batch.collection_window_seconds,
            'collect_agent_id': batch.collect_agent_id,
            'received_timestamp': batch.received_timestamp,
            'metadata': batch.metadata,
            'processes': [
                {
                    'pid': p.pid,
                    'cpu_ontime_ns': p.cpu_ontime_ns,
                    'uid': p.uid,
                    'comm': p.comm,
                    'read_bytes': p.read_bytes,
                    'write_bytes': p.write_bytes,
                    'net_rx_bytes': p.net_rx_bytes,
                    'net_tx_bytes': p.net_tx_bytes,
                    'avg_rss_bytes': p.avg_rss_bytes,
                    'process_name': p.process_name,
                    'gpu_used_memory_mib': p.gpu_used_memory_mib,
                    'metadata': p.metadata
                }
                for p in batch.processes
            ]
        }

        # Include system metrics if present
        if batch.system_metrics:
            sm = batch.system_metrics
            result['system_metrics'] = {
                'cpu_usage_percent': sm.cpu_usage_percent,
                'memory_usage_percent': sm.memory_usage_percent,
                'memory_used_bytes': sm.memory_used_bytes,
                'memory_total_bytes': sm.memory_total_bytes,
                'gpus': [
                    {
                        'gpu_index': g.gpu_index,
                        'gpu_name': g.gpu_name,
                        'utilization_percent': g.utilization_percent,
                        'temperature_celsius': g.temperature_celsius,
                        'power_watts': g.power_watts,
                        'power_limit_watts': g.power_limit_watts,
                        'memory_used_mib': g.memory_used_mib,
                        'memory_total_mib': g.memory_total_mib
                    }
                    for g in sm.gpus
                ]
            }

        return result

    async def close(self):
        if self.producer:
            await self.producer.stop()
            logger.info("Kafka producer stopped")
