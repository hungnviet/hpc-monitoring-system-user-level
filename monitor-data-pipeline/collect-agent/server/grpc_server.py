import grpc
import asyncio
import signal
from pathlib import Path
import sys
from concurrent import futures

sys.path.insert(0, str(Path(__file__).parent.parent))
from proto import metrics_pb2_grpc
from server.metrics_servicer import MetricsCollectorServicer
from config import ConfigurationManager, CollectAgentConfig
from pipeline import MetricsPipeline
from publisher import KafkaPublisher
from alert import AlertClient
from utils import get_logger


logger = get_logger(__name__)


class CollectAgentServer:
    def __init__(self, config: CollectAgentConfig):
        self.config = config
        self.server = None
        self.publisher = None
        self.alert_client = None
        self.pipeline = None
        self.servicer = None

        self._shutdown_event = asyncio.Event()
        self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, self._signal_handler)

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, initiating shutdown...")
        asyncio.create_task(self.shutdown())

    async def start(self):
        logger.info("=" * 80)
        logger.info("Starting Collect Agent Server")
        logger.info("=" * 80)

        await self._initialize_components()
        await self._start_grpc_server()

        logger.info(f"Collect Agent '{self.config.collect_agent_id}' is running")
        logger.info(f"gRPC server listening on port {self.config.grpc_port}")
        logger.info("=" * 80)

        await self._shutdown_event.wait()

    async def _initialize_components(self):
        logger.info("Initializing components...")

        self.publisher = KafkaPublisher(
            brokers=self.config.kafka_brokers,
            topic=self.config.kafka_topic
        )
        await self.publisher.start()

        self.alert_client = AlertClient(
            server_address=self.config.main_server_address,
            collect_agent_id=self.config.collect_agent_id
        )
        await self.alert_client.connect()

        async def alert_callback(violation):
            await self.alert_client.send_alert(violation)

        self.pipeline = MetricsPipeline(
            config=self.config,
            alert_callback=alert_callback
        )

        self.servicer = MetricsCollectorServicer(
            pipeline=self.pipeline,
            publisher=self.publisher
        )

        logger.info("All components initialized successfully")

    async def _start_grpc_server(self):
        self.server = grpc.aio.server(
            futures.ThreadPoolExecutor(max_workers=self.config.grpc_max_workers),
            options=[
                ('grpc.max_send_message_length', 100 * 1024 * 1024),
                ('grpc.max_receive_message_length', 100 * 1024 * 1024),
                ('grpc.keepalive_time_ms', 30000),
                ('grpc.keepalive_timeout_ms', 10000),
                ('grpc.http2.max_pings_without_data', 0),
            ]
        )

        metrics_pb2_grpc.add_MetricsCollectorServicer_to_server(
            self.servicer,
            self.server
        )

        listen_address = f'[::]:{self.config.grpc_port}'
        self.server.add_insecure_port(listen_address)

        await self.server.start()
        logger.info(f"gRPC server started on {listen_address}")

    async def shutdown(self):
        if self._shutdown_event.is_set():
            return

        logger.info("=" * 80)
        logger.info("Shutting down Collect Agent Server")
        logger.info("=" * 80)

        self._shutdown_event.set()

        if self.server:
            logger.info("Stopping gRPC server...")
            await self.server.stop(grace=5)

        if self.publisher:
            logger.info("Closing Kafka publisher...")
            await self.publisher.close()

        if self.alert_client:
            logger.info("Closing alert client...")
            await self.alert_client.close()

        logger.info("Shutdown complete")
