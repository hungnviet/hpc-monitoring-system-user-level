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
class GPUMetric:
    """Per-GPU metrics for multi-GPU support."""
    gpu_index: int
    gpu_name: str
    utilization_percent: float
    temperature_celsius: float
    power_watts: float
    power_limit_watts: float
    memory_used_mib: int
    memory_total_mib: int


@dataclass
class NodeSystemMetric:
    """Node-level system metrics (not per-process)."""
    cpu_usage_percent: float
    memory_usage_percent: float
    memory_used_bytes: int
    memory_total_bytes: int
    gpus: List[GPUMetric] = field(default_factory=list)


@dataclass
class MetricBatch:
    node_id: str
    timestamp: int
    collection_window_seconds: float
    processes: List[ProcessMetric]

    system_metrics: Optional[NodeSystemMetric] = None
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
