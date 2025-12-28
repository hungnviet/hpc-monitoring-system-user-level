from pipeline.base import PipelineStage
from models import MetricBatch, ProcessResult, ProcessStatus, NodeSystemMetric
from utils import get_logger


logger = get_logger(__name__)


class SchemaValidator(PipelineStage):
    def __init__(self):
        super().__init__("schema_validator")
        self._required_fields = {
            'node_id', 'timestamp', 'collection_window_seconds', 'processes'
        }
        self._process_required_fields = {
            'pid', 'cpu_ontime_ns', 'uid', 'comm'
        }

    async def process(self, batch: MetricBatch) -> ProcessResult:
        invalid_count = 0
        valid_processes = []

        if not batch.node_id or not isinstance(batch.timestamp, int):
            logger.warning(f"Invalid batch metadata from {batch.node_id}")
            return ProcessResult(
                valid_batches=[],
                filtered_count=0,
                invalid_count=len(batch.processes),
                alerts_triggered=0
            )

        # Validate system metrics if present
        if batch.system_metrics:
            if not self._validate_system_metrics(batch.system_metrics):
                logger.warning(f"Invalid system metrics from {batch.node_id}, setting to None")
                batch.system_metrics = None

        for process in batch.processes:
            if self._validate_process(process):
                valid_processes.append(process)
            else:
                process.status = ProcessStatus.INVALID
                invalid_count += 1

        if valid_processes:
            batch.processes = valid_processes
            return ProcessResult(
                valid_batches=[batch],
                filtered_count=0,
                invalid_count=invalid_count,
                alerts_triggered=0
            )
        else:
            return ProcessResult(
                valid_batches=[],
                filtered_count=0,
                invalid_count=invalid_count,
                alerts_triggered=0
            )

    def _validate_process(self, process) -> bool:
        try:
            if process.pid <= 0:
                return False
            if process.cpu_ontime_ns < 0:
                return False
            if not process.comm or len(process.comm) == 0:
                return False
            return True
        except AttributeError:
            return False

    def _validate_system_metrics(self, sm: NodeSystemMetric) -> bool:
        """Validate system metrics ranges."""
        try:
            # CPU usage: 0-100%
            if not (0 <= sm.cpu_usage_percent <= 100):
                return False
            # Memory usage: 0-100%
            if not (0 <= sm.memory_usage_percent <= 100):
                return False
            # Memory bytes: non-negative
            if sm.memory_used_bytes < 0 or sm.memory_total_bytes < 0:
                return False

            # GPU validation
            for gpu in sm.gpus:
                if not (0 <= gpu.utilization_percent <= 100):
                    return False
                # Temperature: reasonable range (-50 to 200 Celsius)
                if gpu.temperature_celsius < -50 or gpu.temperature_celsius > 200:
                    return False
                # Power: non-negative
                if gpu.power_watts < 0:
                    return False

            return True
        except AttributeError:
            return False
