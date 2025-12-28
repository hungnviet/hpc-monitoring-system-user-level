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
        """Calculate metrics from both processes and system-level data."""
        # Existing per-process aggregations
        total_cpu = sum(p.cpu_ontime_ns for p in batch.processes)
        total_memory = sum(p.avg_rss_bytes for p in batch.processes)
        total_disk_read = sum(p.read_bytes for p in batch.processes)
        total_disk_write = sum(p.write_bytes for p in batch.processes)
        total_net_rx = sum(p.net_rx_bytes for p in batch.processes)
        total_net_tx = sum(p.net_tx_bytes for p in batch.processes)

        metrics = {
            # Existing metrics (per-process aggregations)
            'cpu_total_ns': total_cpu,
            'memory_total_bytes': total_memory,
            'disk_read_bytes': total_disk_read,
            'disk_write_bytes': total_disk_write,
            'network_rx_bytes': total_net_rx,
            'network_tx_bytes': total_net_tx,
            'process_count': len(batch.processes),
        }

        # System-level metrics for threshold checking
        if batch.system_metrics:
            sm = batch.system_metrics
            metrics['cpu_usage_percent'] = sm.cpu_usage_percent
            metrics['memory_usage_percent'] = sm.memory_usage_percent
            metrics['system_memory_used_bytes'] = sm.memory_used_bytes
            metrics['system_memory_total_bytes'] = sm.memory_total_bytes

            # Per-GPU metrics (for multi-GPU support)
            for gpu in sm.gpus:
                idx = gpu.gpu_index
                metrics[f'gpu_{idx}_utilization_percent'] = gpu.utilization_percent
                metrics[f'gpu_{idx}_temperature_celsius'] = gpu.temperature_celsius
                metrics[f'gpu_{idx}_power_watts'] = gpu.power_watts
                metrics[f'gpu_{idx}_memory_used_mib'] = gpu.memory_used_mib
                metrics[f'gpu_{idx}_memory_total_mib'] = gpu.memory_total_mib

            # Aggregate GPU metrics (max values across all GPUs)
            if sm.gpus:
                metrics['gpu_max_utilization_percent'] = max(g.utilization_percent for g in sm.gpus)
                metrics['gpu_max_temperature_celsius'] = max(g.temperature_celsius for g in sm.gpus)
                metrics['gpu_max_power_watts'] = max(g.power_watts for g in sm.gpus)
                metrics['gpu_total_memory_used_mib'] = sum(g.memory_used_mib for g in sm.gpus)
                metrics['gpu_count'] = len(sm.gpus)

        return metrics

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
