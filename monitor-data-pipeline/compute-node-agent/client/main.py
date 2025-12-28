import grpc
import time
import logging
from typing import Dict, Any, Optional
from queue import Queue, Empty
from threading import Thread, Event

from grpc_proto import metrics_pb2
from grpc_proto import metrics_pb2_grpc

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MetricsStreamClient:


    def __init__(self, server_address: str, max_retries: int = 3):
        self.server_address = server_address
        self.max_retries = max_retries

        self.channel: Optional[grpc.Channel] = None
        self.stub: Optional[metrics_pb2_grpc.MetricsCollectorStub] = None
        self.stream = None

        self.message_queue: Queue = Queue(maxsize=1000)
        self.stop_event = Event()
        self.streaming_thread: Optional[Thread] = None

        self._connect()

    def _connect(self) -> bool:
        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(f"Attempting to connect to gRPC server at {self.server_address} (attempt {attempt}/{self.max_retries})")

                self.channel = grpc.insecure_channel(self.server_address)
                self.stub = metrics_pb2_grpc.MetricsCollectorStub(self.channel)

                grpc.channel_ready_future(self.channel).result(timeout=5)
                logger.info(f"Successfully connected to gRPC server at {self.server_address}")

                self._start_streaming()
                return True

            except Exception as e:
                logger.error(f"Failed to connect to gRPC server (attempt {attempt}/{self.max_retries}): {e}")
                if attempt < self.max_retries:
                    sleep_time = min(2 ** attempt, 10) 
                    logger.info(f"Retrying in {sleep_time} seconds...")
                    time.sleep(sleep_time)
                else:
                    logger.error("Max retries reached. Could not connect to gRPC server.")
                    return False

        return False

    def _start_streaming(self):
        self.streaming_thread = Thread(target=self._streaming_loop, daemon=True)
        self.streaming_thread.start()
        logger.info("Streaming thread started")

    def _streaming_loop(self):
        def message_generator():
            while not self.stop_event.is_set():
                try:
                    message = self.message_queue.get(timeout=1)
                    yield message
                except Empty:
                    continue

        try:
            self.stream = self.stub.StreamMetrics(message_generator())
            response = self.stream
            logger.info(f"Stream established, response: {response}")
        except Exception as e:
            logger.error(f"Streaming error: {e}")

    def send_metrics(self,
                    process_data: Dict[int, Dict[str, Any]],
                    system_data: Dict[str, Any],
                    node_id: str,
                    collection_window: float) -> bool:
        try:
            report = self._dict_to_protobuf(process_data, system_data, node_id, collection_window)

            if self.message_queue.full():
                logger.warning("Message queue is full, dropping oldest message")
                try:
                    self.message_queue.get_nowait()
                except Empty:
                    pass

            self.message_queue.put(report)
            logger.debug(f"Queued metrics report with {len(process_data)} processes")
            return True

        except Exception as e:
            logger.error(f"Error sending metrics: {e}")
            return False

    def _dict_to_protobuf(self,
                         process_data: Dict[int, Dict[str, Any]],
                         system_data: Dict[str, Any],
                         node_id: str,
                         collection_window: float) -> metrics_pb2.NodeMetricsReport:

        report = metrics_pb2.NodeMetricsReport()
        report.node_id = node_id
        report.timestamp = int(time.time())
        report.collection_window_seconds = collection_window

        # Per-process metrics
        for pid, metrics in process_data.items():
            process = report.processes.add()
            process.pid = pid
            process.cpu_ontime_ns = metrics.get("cpu_ontime_ns", 0)
            process.uid = metrics.get("uid", 0)
            process.comm = metrics.get("comm", "")
            process.read_bytes = metrics.get("read_bytes", 0)
            process.write_bytes = metrics.get("write_bytes", 0)
            process.net_rx_bytes = metrics.get("net_rx_bytes", 0)
            process.net_tx_bytes = metrics.get("net_tx_bytes", 0)
            process.avg_rss_bytes = metrics.get("avg_rss_bytes", 0)
            process.process_name = metrics.get("process_name", "")
            process.gpu_used_memory_mib = metrics.get("gpu_used_memory_mib", 0)

        # System-level metrics
        sys_metrics = report.system_metrics
        sys_metrics.cpu_usage_percent = system_data.get("cpu_usage_percent", 0.0)
        sys_metrics.memory_usage_percent = system_data.get("memory_usage_percent", 0.0)
        sys_metrics.memory_used_bytes = system_data.get("memory_used_bytes", 0)
        sys_metrics.memory_total_bytes = system_data.get("memory_total_bytes", 0)

        for gpu in system_data.get("gpus", []):
            gpu_msg = sys_metrics.gpus.add()
            gpu_msg.gpu_index = gpu.get("gpu_index", 0)
            gpu_msg.gpu_name = gpu.get("gpu_name", "")
            gpu_msg.utilization_percent = gpu.get("utilization_percent", 0.0)
            gpu_msg.temperature_celsius = gpu.get("temperature_celsius", 0.0)
            gpu_msg.power_watts = gpu.get("power_watts", 0.0)
            gpu_msg.power_limit_watts = gpu.get("power_limit_watts", 0.0)
            gpu_msg.memory_used_mib = gpu.get("memory_used_mib", 0)
            gpu_msg.memory_total_mib = gpu.get("memory_total_mib", 0)

        return report

    def close(self):
        logger.info("Closing gRPC client...")
        self.stop_event.set()

        if self.streaming_thread and self.streaming_thread.is_alive():
            self.streaming_thread.join(timeout=5)

        if self.channel:
            self.channel.close()

        logger.info("gRPC client closed")

    def is_connected(self) -> bool:
        if not self.channel:
            return False

        try:
            return self.channel._channel.check_connectivity_state(True) == grpc.ChannelConnectivity.READY
        except:
            return False
