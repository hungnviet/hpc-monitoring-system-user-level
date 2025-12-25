import time
from pipeline.base import PipelineStage
from models import MetricBatch, ProcessResult
from utils import get_logger


logger = get_logger(__name__)


class MetricsEnricher(PipelineStage):
    def __init__(self, collect_agent_id: str):
        super().__init__("metrics_enricher")
        self.collect_agent_id = collect_agent_id

    async def process(self, batch: MetricBatch) -> ProcessResult:
        batch.collect_agent_id = self.collect_agent_id
        batch.received_timestamp = int(time.time())

        batch.metadata['processing_stage'] = 'enriched'
        batch.metadata['collect_agent_version'] = '1.0.0'

        for process in batch.processes:
            process.metadata['enriched_at'] = batch.received_timestamp
            process.metadata['collect_agent_id'] = self.collect_agent_id

        return ProcessResult(
            valid_batches=[batch],
            filtered_count=0,
            invalid_count=0,
            alerts_triggered=0
        )
