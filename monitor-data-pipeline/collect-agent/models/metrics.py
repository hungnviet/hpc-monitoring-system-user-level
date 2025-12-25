from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class ProcessStatus(Enum):
    VALID = "valid"
    FILTERED = "filtered"
    INVALID = "invalid"
    ALERT_TRIGGERED = "alert_triggered"


@dataclass
class ProcessMetric:
    pid: int
    cpu_ontime_ns: int
    uid: int
    comm: str
    read_bytes: int
    write_bytes: int
    net_rx_bytes: int
    net_tx_bytes: int
    avg_rss_bytes: int
    process_name: str
    gpu_used_memory_mib: int

    metadata: Dict[str, Any] = field(default_factory=dict)
    status: ProcessStatus = ProcessStatus.VALID


@dataclass
class MetricBatch:
    node_id: str
    timestamp: int
    collection_window_seconds: float
    processes: List[ProcessMetric]

    collect_agent_id: Optional[str] = None
    received_timestamp: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProcessResult:
    valid_batches: List[MetricBatch]
    filtered_count: int
    invalid_count: int
    alerts_triggered: int

    def __add__(self, other: 'ProcessResult') -> 'ProcessResult':
        return ProcessResult(
            valid_batches=self.valid_batches + other.valid_batches,
            filtered_count=self.filtered_count + other.filtered_count,
            invalid_count=self.invalid_count + other.invalid_count,
            alerts_triggered=self.alerts_triggered + other.alerts_triggered
        )
