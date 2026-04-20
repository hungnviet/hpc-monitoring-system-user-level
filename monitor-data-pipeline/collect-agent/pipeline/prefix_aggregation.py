from typing import Dict, List, Optional, Tuple

from pipeline.base import PipelineStage
from models import MetricBatch, ProcessResult, ProcessMetric
from config import CollectAgentConfig
from utils import get_logger


logger = get_logger(__name__)


def _longest_matching_prefix(comm: str, prefixes: List[str]) -> Optional[str]:
    best: Optional[str] = None
    best_len = -1
    for p in prefixes:
        if comm.startswith(p) and len(p) > best_len:
            best = p
            best_len = len(p)
    return best


def _merge_group(rows: List[ProcessMetric], prefix: str) -> ProcessMetric:
    first = rows[0]
    cpu = sum(p.cpu_ontime_ns for p in rows)
    rb = sum(p.read_bytes for p in rows)
    wb = sum(p.write_bytes for p in rows)
    nr = sum(p.net_rx_bytes for p in rows)
    nt = sum(p.net_tx_bytes for p in rows)
    rss = sum(p.avg_rss_bytes for p in rows)
    gpu = sum(p.gpu_used_memory_mib for p in rows)

    return ProcessMetric(
        pid=0,
        cpu_ontime_ns=cpu,
        uid=first.uid,
        comm=prefix,
        read_bytes=rb,
        write_bytes=wb,
        net_rx_bytes=nr,
        net_tx_bytes=nt,
        avg_rss_bytes=rss,
        process_name="",
        gpu_used_memory_mib=gpu,
        metadata=dict(first.metadata),
        status=first.status,
    )


class PrefixAggregationStage(PipelineStage):
    def __init__(self, config: CollectAgentConfig):
        super().__init__("prefix_aggregation")
        self._config = config

    async def process(self, batch: MetricBatch) -> ProcessResult:
        prefixes = self._config.comm_prefixes or []
        if not prefixes:
            return ProcessResult(
                valid_batches=[batch],
                filtered_count=0,
                invalid_count=0,
                alerts_triggered=0,
            )

        groups: Dict[Tuple[int, str], List[ProcessMetric]] = {}
        order: List[Tuple[int, str]] = []
        passthrough: List[ProcessMetric] = []

        for p in batch.processes:
            match = _longest_matching_prefix(p.comm, prefixes)
            if match is None:
                passthrough.append(p)
                continue
            key = (p.uid, match)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(p)

        merged: List[ProcessMetric] = []
        for key in order:
            merged.append(_merge_group(groups[key], key[1]))
        merged.extend(passthrough)
        batch.processes = merged

        return ProcessResult(
            valid_batches=[batch],
            filtered_count=0,
            invalid_count=0,
            alerts_triggered=0,
        )
