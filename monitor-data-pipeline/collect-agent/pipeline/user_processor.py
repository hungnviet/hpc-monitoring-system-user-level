from typing import List
from pipeline.base import PipelineStage
from models import MetricBatch, ProcessResult
from config import UserProcessorConfig
from utils import get_logger


logger = get_logger(__name__)


class UserProcessor(PipelineStage):
    def __init__(self, configs: List[UserProcessorConfig]):
        super().__init__("user_processor")
        self.configs = configs
        self.processors = self._load_processors()

    def _load_processors(self) -> List:
        processors = []
        for config in self.configs:
            processor = self._create_processor(config)
            if processor:
                processors.append(processor)
        return processors

    def _create_processor(self, config: UserProcessorConfig):
        if config.type == "aggregator":
            return AggregatorProcessor(config.params)
        elif config.type == "sampler":
            return SamplerProcessor(config.params)
        else:
            logger.warning(f"Unknown user processor type: {config.type}")
            return None

    async def process(self, batch: MetricBatch) -> ProcessResult:
        for processor in self.processors:
            batch = await processor.process_batch(batch)

        return ProcessResult(
            valid_batches=[batch] if batch.processes else [],
            filtered_count=0,
            invalid_count=0,
            alerts_triggered=0
        )


class AggregatorProcessor:
    def __init__(self, params: dict):
        self.window_seconds = params.get('window_seconds', 60)

    async def process_batch(self, batch: MetricBatch) -> MetricBatch:
        batch.metadata['aggregated'] = True
        batch.metadata['aggregation_window'] = self.window_seconds
        return batch


class SamplerProcessor:
    def __init__(self, params: dict):
        self.sample_rate = params.get('sample_rate', 0.1)

    async def process_batch(self, batch: MetricBatch) -> MetricBatch:
        sample_size = int(len(batch.processes) * self.sample_rate)
        if sample_size > 0:
            batch.processes = batch.processes[:sample_size]
        batch.metadata['sampled'] = True
        batch.metadata['sample_rate'] = self.sample_rate
        return batch
