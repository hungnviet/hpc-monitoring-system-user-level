from typing import Set, List, Optional

from pipeline.base import PipelineStage
from models import MetricBatch, ProcessResult, ProcessMetric
from config import CollectAgentConfig
from utils import get_logger


logger = get_logger(__name__)

# Matches ProcessMetric / metrics.proto ProcessMetrics field names
ALLOWED_PROCESS_FIELDS: Set[str] = {
    "pid",
    "cpu_ontime_ns",
    "uid",
    "comm",
    "read_bytes",
    "write_bytes",
    "net_rx_bytes",
    "net_tx_bytes",
    "avg_rss_bytes",
    "process_name",
    "gpu_used_memory_mib",
}


class FieldProjectionStage(PipelineStage):
    def __init__(self, config: CollectAgentConfig):
        super().__init__("field_projection")
        self._config = config

    def _normalize_fields(self, names: Optional[List[str]]) -> Optional[List[str]]:
        if not names:
            return None
        out: List[str] = []
        for n in names:
            if n in ALLOWED_PROCESS_FIELDS:
                out.append(n)
            else:
                logger.warning(f"Ignoring unknown process field name: {n!r}")
        return out if out else None

    def _project_process(self, p: ProcessMetric, keep: Set[str]) -> ProcessMetric:
        return ProcessMetric(
            pid=p.pid if "pid" in keep else 0,
            cpu_ontime_ns=p.cpu_ontime_ns if "cpu_ontime_ns" in keep else 0,
            uid=p.uid if "uid" in keep else 0,
            comm=p.comm if "comm" in keep else "",
            read_bytes=p.read_bytes if "read_bytes" in keep else 0,
            write_bytes=p.write_bytes if "write_bytes" in keep else 0,
            net_rx_bytes=p.net_rx_bytes if "net_rx_bytes" in keep else 0,
            net_tx_bytes=p.net_tx_bytes if "net_tx_bytes" in keep else 0,
            avg_rss_bytes=p.avg_rss_bytes if "avg_rss_bytes" in keep else 0,
            process_name=p.process_name if "process_name" in keep else "",
            gpu_used_memory_mib=p.gpu_used_memory_mib if "gpu_used_memory_mib" in keep else 0,
            metadata=dict(p.metadata),
            status=p.status,
        )

    async def process(self, batch: MetricBatch) -> ProcessResult:
        normalized = self._normalize_fields(self._config.process_fields)
        if not normalized:
            batch.metadata.pop("exported_process_fields", None)
            return ProcessResult(
                valid_batches=[batch],
                filtered_count=0,
                invalid_count=0,
                alerts_triggered=0,
            )

        keep = set(normalized)
        batch.processes = [self._project_process(p, keep) for p in batch.processes]
        batch.metadata["exported_process_fields"] = list(normalized)

        return ProcessResult(
            valid_batches=[batch],
            filtered_count=0,
            invalid_count=0,
            alerts_triggered=0,
        )
