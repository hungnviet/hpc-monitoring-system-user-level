"""
Common Data Schema for Collect Agent

This module defines the unified data model that all input servers
(gRPC, MQTT, Telegraf, REST) must convert their data into.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime
import json


@dataclass
class GpuState:
    """GPU global state metrics"""
    power_watts: float = 0.0
    temperature_celsius: int = 0
    total_load_percent: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProcessMetrics:
    """Per-process resource usage metrics"""
    pid: int
    uid: int
    command: str
    cpu_usage_percent: float = 0.0
    memory_bytes: int = 0
    gpu_sm_percent: float = -1.0  # -1 indicates not using GPU
    gpu_mem_percent: float = -1.0
    gpu_mem_mib: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MonitoringSnapshot:
    """
    Unified monitoring data snapshot from compute nodes.

    This is the canonical data format used internally by the Collect Agent.
    All input servers must convert their received data into this format.
    """
    timestamp: int  # Unix timestamp in seconds
    node_id: str
    gpu_global_state: GpuState
    processes: List[ProcessMetrics] = field(default_factory=list)

    # Metadata added by Collect Agent
    received_at: Optional[float] = None  # When received by server
    source_protocol: Optional[str] = None  # gRPC, MQTT, Telegraf, REST

    def __post_init__(self):
        """Set received timestamp if not provided"""
        if self.received_at is None:
            self.received_at = datetime.now().timestamp()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp,
            'node_id': self.node_id,
            'gpu_global_state': self.gpu_global_state.to_dict(),
            'processes': [p.to_dict() for p in self.processes],
            'received_at': self.received_at,
            'source_protocol': self.source_protocol
        }

    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MonitoringSnapshot':
        """Create instance from dictionary"""
        gpu_state = GpuState(**data.get('gpu_global_state', {}))
        processes = [ProcessMetrics(**p) for p in data.get('processes', [])]

        return cls(
            timestamp=data['timestamp'],
            node_id=data['node_id'],
            gpu_global_state=gpu_state,
            processes=processes,
            received_at=data.get('received_at'),
            source_protocol=data.get('source_protocol')
        )

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics"""
        return {
            'node_id': self.node_id,
            'timestamp': self.timestamp,
            'received_at': self.received_at,
            'source_protocol': self.source_protocol,
            'num_processes': len(self.processes),
            'total_cpu_percent': sum(p.cpu_usage_percent for p in self.processes),
            'total_memory_bytes': sum(p.memory_bytes for p in self.processes),
            'gpu_utilization': self.gpu_global_state.total_load_percent,
            'gpu_temperature': self.gpu_global_state.temperature_celsius,
            'gpu_power': self.gpu_global_state.power_watts
        }
