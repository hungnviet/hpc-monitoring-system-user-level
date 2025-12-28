from pipeline.base import PipelineStage
from models import MetricBatch, ProcessResult, ProcessStatus
from utils import get_logger


logger = get_logger(__name__)


class MetricsFilter(PipelineStage):
    def __init__(self):
        super().__init__("metrics_filter")
        self._bootstrap_processes = {
            'systemd', 'init', 'kthreadd', 'rcu_sched', 'migration'
        }
        self._bootstrap_time_threshold = 300
        self._min_cpu_threshold = 0
        self._min_memory_threshold = 0

    async def process(self, batch: MetricBatch) -> ProcessResult:
        filtered_count = 0
        valid_processes = []

        for process in batch.processes:
            if self._should_filter(process, batch):
                process.status = ProcessStatus.FILTERED
                filtered_count += 1
            else:
                valid_processes.append(process)

        if valid_processes:
            batch.processes = valid_processes
            return ProcessResult(
                valid_batches=[batch],
                filtered_count=filtered_count,
                invalid_count=0,
                alerts_triggered=0
            )
        else:
            return ProcessResult(
                valid_batches=[],
                filtered_count=filtered_count,
                invalid_count=0,
                alerts_triggered=0
            )

    def _should_filter(self, process, batch: MetricBatch) -> bool:
        if process.comm in self._bootstrap_processes:
            return True

        if batch.timestamp < self._bootstrap_time_threshold:
            return True

        if (process.cpu_ontime_ns == 0 and
            process.avg_rss_bytes < self._min_memory_threshold):
            return True

        return False
