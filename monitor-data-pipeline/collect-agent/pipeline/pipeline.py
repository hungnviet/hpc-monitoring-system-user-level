from typing import List, Optional, Callable
from pipeline.base import PipelineStage
from pipeline.validator import SchemaValidator
from pipeline.filter import MetricsFilter
from pipeline.enricher import MetricsEnricher
from pipeline.threshold_checker import ThresholdChecker
from pipeline.user_processor import UserProcessor
from models import MetricBatch, ProcessResult
from config import CollectAgentConfig
from utils import get_logger


logger = get_logger(__name__)


class MetricsPipeline:
    def __init__(self, config: CollectAgentConfig, alert_callback: Optional[Callable] = None):
        self.config = config
        self.stages: List[PipelineStage] = []
        self._build_pipeline(alert_callback)

    def _build_pipeline(self, alert_callback: Optional[Callable]):
        self.stages.append(SchemaValidator())
        self.stages.append(MetricsFilter())
        self.stages.append(MetricsEnricher(self.config.collect_agent_id))
        self.stages.append(ThresholdChecker(
            self.config.threshold_rules,
            alert_callback
        ))

        if self.config.user_processors:
            self.stages.append(UserProcessor(self.config.user_processors))

        logger.info(f"Pipeline built with {len(self.stages)} stages: {[s.name for s in self.stages]}")

    async def process(self, batch: MetricBatch) -> ProcessResult:
        current_batches = [batch]
        total_result = ProcessResult(
            valid_batches=[],
            filtered_count=0,
            invalid_count=0,
            alerts_triggered=0
        )

        for stage in self.stages:
            stage_batches = []
            stage_result = ProcessResult(
                valid_batches=[],
                filtered_count=0,
                invalid_count=0,
                alerts_triggered=0
            )

            for current_batch in current_batches:
                try:
                    result = await stage.process(current_batch)
                    stage_result = stage_result + result
                except Exception as e:
                    logger.error(f"Error in stage {stage.name}: {e}", exc_info=True)
                    stage_result.invalid_count += len(current_batch.processes)

            current_batches = stage_result.valid_batches
            total_result = total_result + stage_result

            if not current_batches:
                logger.debug(f"Pipeline stopped at stage {stage.name}: no valid batches")
                break

        total_result.valid_batches = current_batches
        return total_result
