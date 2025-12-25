from typing import List, Optional
from pipeline.base import PipelineStage
from models import MetricBatch, ProcessResult, ProcessStatus
from config import ThresholdRule
from utils import get_logger


logger = get_logger(__name__)


class ThresholdChecker(PipelineStage):
    def __init__(self, threshold_rules: List[ThresholdRule], alert_callback=None):
        super().__init__("threshold_checker")
        self.threshold_rules = threshold_rules
        self.alert_callback = alert_callback

    async def process(self, batch: MetricBatch) -> ProcessResult:
        alerts_triggered = 0

        node_metrics = self._calculate_node_metrics(batch)

        for rule in self.threshold_rules:
            violation = self._check_threshold(rule, node_metrics, batch)
            if violation and self.alert_callback:
                await self.alert_callback(violation)
                alerts_triggered += 1

        return ProcessResult(
            valid_batches=[batch],
            filtered_count=0,
            invalid_count=0,
            alerts_triggered=alerts_triggered
        )

    def _calculate_node_metrics(self, batch: MetricBatch) -> dict:
        total_cpu = sum(p.cpu_ontime_ns for p in batch.processes)
        total_memory = sum(p.avg_rss_bytes for p in batch.processes)
        total_disk_read = sum(p.read_bytes for p in batch.processes)
        total_disk_write = sum(p.write_bytes for p in batch.processes)
        total_net_rx = sum(p.net_rx_bytes for p in batch.processes)
        total_net_tx = sum(p.net_tx_bytes for p in batch.processes)

        return {
            'cpu_total_ns': total_cpu,
            'memory_total_bytes': total_memory,
            'disk_read_bytes': total_disk_read,
            'disk_write_bytes': total_disk_write,
            'network_rx_bytes': total_net_rx,
            'network_tx_bytes': total_net_tx,
            'process_count': len(batch.processes)
        }

    def _check_threshold(self, rule: ThresholdRule, metrics: dict, batch: MetricBatch) -> Optional[dict]:
        metric_value = metrics.get(rule.metric_name)
        if metric_value is None:
            return None

        violated = False
        violation_type = None

        if rule.max_value is not None and metric_value > rule.max_value:
            violated = True
            violation_type = 'exceeded_max'

        if rule.min_value is not None and metric_value < rule.min_value:
            violated = True
            violation_type = 'below_min'

        if violated:
            return {
                'node_id': batch.node_id,
                'metric_name': rule.metric_name,
                'metric_value': metric_value,
                'threshold_max': rule.max_value,
                'threshold_min': rule.min_value,
                'violation_type': violation_type,
                'timestamp': batch.timestamp
            }

        return None
