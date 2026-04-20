from typing import List, Optional, Callable, Dict

from pipeline.base import PipelineStage
from pipeline.validator import SchemaValidator
from pipeline.field_projection import FieldProjectionStage
from pipeline.prefix_aggregation import PrefixAggregationStage
from pipeline.enricher import MetricsEnricher
from pipeline.threshold_checker import ThresholdChecker
from models import MetricBatch, ProcessResult
from config import CollectAgentConfig
from utils import get_logger


logger = get_logger(__name__)

# Default order when etcd key `pipeline_stages` is absent or empty.
DEFAULT_PIPELINE_STAGES = [
    "schema_validator",
    "field_projection",
    "prefix_aggregation",
    "metrics_enricher",
    "threshold_checker",
]

# Maps normalized names (snake_case or compact) -> canonical id
_STAGE_NAME_ALIASES: Dict[str, str] = {
    "schema_validator": "schema_validator",
    "schemavalidator": "schema_validator",
    "schemapvalidator": "schema_validator",  # common typo
    "field_projection": "field_projection",
    "fieldprojection": "field_projection",
    "prefix_aggregation": "prefix_aggregation",
    "prefixaggregation": "prefix_aggregation",
    "metrics_enricher": "metrics_enricher",
    "metricsenricher": "metrics_enricher",
    "threshold_checker": "threshold_checker",
    "thresholdchecker": "threshold_checker",
    "user_processor": "user_processor",
    "userprocessor": "user_processor",
}


def _normalize_stage_name(raw: str) -> Optional[str]:
    if not raw or not str(raw).strip():
        return None
    key = str(raw).strip().lower().replace("-", "_")
    if key in _STAGE_NAME_ALIASES:
        return _STAGE_NAME_ALIASES[key]
    compact = key.replace("_", "")
    return _STAGE_NAME_ALIASES.get(compact)


def _try_user_processor_class():
    try:
        from pipeline.user_processor import UserProcessor
        return UserProcessor
    except ImportError:
        return None


class MetricsPipeline:
    def __init__(self, config: CollectAgentConfig, alert_callback: Optional[Callable] = None):
        self.config = config
        self.stages: List[PipelineStage] = []
        self._build_pipeline(alert_callback)

    def _instantiate_stage(
        self,
        canonical: str,
        alert_callback: Optional[Callable],
    ) -> Optional[PipelineStage]:
        if canonical == "schema_validator":
            return SchemaValidator()
        if canonical == "field_projection":
            return FieldProjectionStage(self.config)
        if canonical == "prefix_aggregation":
            return PrefixAggregationStage(self.config)
        if canonical == "metrics_enricher":
            return MetricsEnricher(self.config.collect_agent_id)
        if canonical == "threshold_checker":
            return ThresholdChecker(self.config.threshold_rules, alert_callback)
        return None

    def _build_pipeline(self, alert_callback: Optional[Callable]):
        configured = self.config.pipeline_stages
        if configured is None:
            names = list(DEFAULT_PIPELINE_STAGES)
        elif len(configured) == 0:
            logger.warning(
                "pipeline_stages is empty; using default pipeline order"
            )
            names = list(DEFAULT_PIPELINE_STAGES)
        else:
            names = list(configured)

        for raw in names:
            canonical = _normalize_stage_name(raw)
            if not canonical:
                logger.warning(f"Unknown pipeline stage {raw!r}; skipping")
                continue
            stage = self._instantiate_stage(canonical, alert_callback)
            if stage is not None:
                self.stages.append(stage)

        if not self.stages:
            logger.error("No valid pipeline stages; using default pipeline order")
            for canonical in DEFAULT_PIPELINE_STAGES:
                stage = self._instantiate_stage(canonical, alert_callback)
                if stage is not None:
                    self.stages.append(stage)

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
