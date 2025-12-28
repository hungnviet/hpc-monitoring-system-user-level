import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from proto import metrics_pb2, metrics_pb2_grpc
from models import MetricBatch, ProcessMetric, GPUMetric, NodeSystemMetric
from pipeline import MetricsPipeline
from publisher import KafkaPublisher
from utils import get_logger


logger = get_logger(__name__)


class MetricsCollectorServicer(metrics_pb2_grpc.MetricsCollectorServicer):
    def __init__(self, pipeline: MetricsPipeline, publisher: KafkaPublisher):
        self.pipeline = pipeline
        self.publisher = publisher
        self.total_reports_received = 0
        self.total_processes_received = 0
        self.active_connections = 0

    async def StreamMetrics(self, request_iterator, context):
        peer = context.peer()
        self.active_connections += 1
        logger.info(f"New stream connection from {peer} (active: {self.active_connections})")

        node_id = None
        reports_count = 0

        try:
            async for proto_report in request_iterator:
                self.total_reports_received += 1
                reports_count += 1

                node_id = proto_report.node_id

                batch = self._proto_to_batch(proto_report)
                self.total_processes_received += len(batch.processes)

                result = await self.pipeline.process(batch)

                if result.valid_batches:
                    await self.publisher.publish(result.valid_batches)

                logger.debug(
                    f"Processed batch from {node_id}: "
                    f"valid={len(result.valid_batches)}, "
                    f"filtered={result.filtered_count}, "
                    f"invalid={result.invalid_count}, "
                    f"alerts={result.alerts_triggered}"
                )

        except Exception as e:
            logger.error(f"Error processing stream from {peer}: {e}", exc_info=True)
            return metrics_pb2.StreamResponse(
                success=False,
                message=f"Error: {str(e)}"
            )

        finally:
            self.active_connections -= 1
            logger.info(
                f"Stream closed from {node_id or peer} "
                f"({reports_count} reports, active: {self.active_connections})"
            )

        return metrics_pb2.StreamResponse(
            success=True,
            message=f"Processed {reports_count} reports"
        )

    def _proto_to_batch(self, proto_report) -> MetricBatch:
        processes = [
            ProcessMetric(
                pid=p.pid,
                cpu_ontime_ns=p.cpu_ontime_ns,
                uid=p.uid,
                comm=p.comm,
                read_bytes=p.read_bytes,
                write_bytes=p.write_bytes,
                net_rx_bytes=p.net_rx_bytes,
                net_tx_bytes=p.net_tx_bytes,
                avg_rss_bytes=p.avg_rss_bytes,
                process_name=p.process_name,
                gpu_used_memory_mib=p.gpu_used_memory_mib
            )
            for p in proto_report.processes
        ]

        # Parse system metrics if present
        system_metrics = None
        if proto_report.HasField('system_metrics'):
            sm = proto_report.system_metrics
            gpus = [
                GPUMetric(
                    gpu_index=g.gpu_index,
                    gpu_name=g.gpu_name,
                    utilization_percent=g.utilization_percent,
                    temperature_celsius=g.temperature_celsius,
                    power_watts=g.power_watts,
                    power_limit_watts=g.power_limit_watts,
                    memory_used_mib=g.memory_used_mib,
                    memory_total_mib=g.memory_total_mib
                )
                for g in sm.gpus
            ]
            system_metrics = NodeSystemMetric(
                cpu_usage_percent=sm.cpu_usage_percent,
                memory_usage_percent=sm.memory_usage_percent,
                memory_used_bytes=sm.memory_used_bytes,
                memory_total_bytes=sm.memory_total_bytes,
                gpus=gpus
            )

        return MetricBatch(
            node_id=proto_report.node_id,
            timestamp=proto_report.timestamp,
            collection_window_seconds=proto_report.collection_window_seconds,
            processes=processes,
            system_metrics=system_metrics
        )
