"""
Data Processor - Central Computing Logic

This module contains the core preprocessing and transformation logic
for monitoring data received from compute nodes.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from common.schema import MonitoringSnapshot, ProcessMetrics


class DataProcessor:
    """
    Central processing unit for monitoring data.

    Responsibilities:
    1. Validate incoming data
    2. Apply preprocessing/enrichment
    3. Filter and aggregate data
    4. Prepare data for downstream systems (Kafka)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the data processor.

        Args:
            config: Configuration dictionary with processing rules
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.processed_count = 0
        self.validation_errors = 0
        self.processing_errors = 0

        # Processing configuration
        self.min_cpu_threshold = self.config.get('min_cpu_threshold', 0.0)
        self.min_memory_threshold = self.config.get('min_memory_threshold', 0)
        self.enable_aggregation = self.config.get('enable_aggregation', True)
        self.enable_enrichment = self.config.get('enable_enrichment', True)

        self.logger.info("DataProcessor initialized with config: %s", self.config)

    def process(self, snapshot: MonitoringSnapshot) -> Optional[Dict[str, Any]]:
        """
        Main processing method - orchestrates the entire processing pipeline.

        Args:
            snapshot: MonitoringSnapshot object to process

        Returns:
            Processed data as dictionary ready for Kafka, or None if processing fails
        """
        try:
            # Step 1: Validate
            if not self._validate(snapshot):
                self.validation_errors += 1
                self.logger.warning(f"Validation failed for snapshot from {snapshot.node_id}")
                return None

            # Step 2: Filter processes
            filtered_snapshot = self._filter_processes(snapshot)

            # Step 3: Enrich data
            if self.enable_enrichment:
                enriched_snapshot = self._enrich(filtered_snapshot)
            else:
                enriched_snapshot = filtered_snapshot

            # Step 4: Aggregate metrics
            if self.enable_aggregation:
                aggregated_data = self._aggregate(enriched_snapshot)
            else:
                aggregated_data = enriched_snapshot.to_dict()

            # Step 5: Add processing metadata
            processed_data = self._add_metadata(aggregated_data)

            self.processed_count += 1
            self.logger.info(f"Successfully processed snapshot from {snapshot.node_id}")

            return processed_data

        except Exception as e:
            self.processing_errors += 1
            self.logger.error(f"Error processing snapshot: {e}", exc_info=True)
            return None

    def _validate(self, snapshot: MonitoringSnapshot) -> bool:
        """
        Validate the monitoring snapshot.

        Args:
            snapshot: Snapshot to validate

        Returns:
            True if valid, False otherwise
        """
        # Check required fields
        if not snapshot.node_id:
            self.logger.error("Missing node_id")
            return False

        if not snapshot.timestamp or snapshot.timestamp <= 0:
            self.logger.error("Invalid timestamp")
            return False

        # Check data freshness (not older than 1 hour)
        current_time = datetime.now().timestamp()
        age_seconds = current_time - snapshot.timestamp
        if age_seconds > 3600:
            self.logger.warning(f"Data is stale: {age_seconds} seconds old")
            # Don't reject, just warn
        elif age_seconds < -300:
            self.logger.warning(f"Data is from the future: {age_seconds} seconds")

        # Validate processes
        for proc in snapshot.processes:
            if proc.cpu_usage_percent < 0 or proc.cpu_usage_percent > 1000:
                self.logger.warning(f"Suspicious CPU usage: {proc.cpu_usage_percent}%")

        return True

    def _filter_processes(self, snapshot: MonitoringSnapshot) -> MonitoringSnapshot:
        """
        Filter processes based on thresholds.

        Args:
            snapshot: Original snapshot

        Returns:
            Filtered snapshot with only relevant processes
        """
        filtered_processes = []

        for proc in snapshot.processes:
            # Filter by CPU threshold
            if proc.cpu_usage_percent >= self.min_cpu_threshold:
                filtered_processes.append(proc)
            # Or by memory threshold
            elif proc.memory_bytes >= self.min_memory_threshold:
                filtered_processes.append(proc)
            # Keep processes using GPU
            elif proc.gpu_sm_percent > 0:
                filtered_processes.append(proc)

        self.logger.debug(f"Filtered {len(snapshot.processes)} → {len(filtered_processes)} processes")

        # Create new snapshot with filtered processes
        snapshot.processes = filtered_processes
        return snapshot

    def _enrich(self, snapshot: MonitoringSnapshot) -> MonitoringSnapshot:
        """
        Enrich snapshot with additional computed metrics.

        Args:
            snapshot: Snapshot to enrich

        Returns:
            Enriched snapshot
        """
        # Add process ranking based on resource usage
        processes_with_score = []

        for proc in snapshot.processes:
            # Compute resource usage score
            cpu_score = proc.cpu_usage_percent
            mem_score = proc.memory_bytes / (1024 * 1024 * 1024)  # GB
            gpu_score = proc.gpu_sm_percent if proc.gpu_sm_percent > 0 else 0

            # Weighted score
            resource_score = (cpu_score * 0.4) + (mem_score * 0.3) + (gpu_score * 0.3)

            # Could add more enrichment here
            # - Process classification (cpu-bound, memory-bound, gpu-bound)
            # - Anomaly detection
            # - Historical comparison

            processes_with_score.append((proc, resource_score))

        # Sort by score
        processes_with_score.sort(key=lambda x: x[1], reverse=True)
        snapshot.processes = [p for p, _ in processes_with_score]

        self.logger.debug(f"Enriched snapshot with {len(snapshot.processes)} ranked processes")
        return snapshot

    def _aggregate(self, snapshot: MonitoringSnapshot) -> Dict[str, Any]:
        """
        Aggregate and summarize metrics.

        Args:
            snapshot: Snapshot to aggregate

        Returns:
            Aggregated data dictionary
        """
        # Start with base snapshot data
        data = snapshot.to_dict()

        # Add aggregated metrics
        total_cpu = sum(p.cpu_usage_percent for p in snapshot.processes)
        total_memory = sum(p.memory_bytes for p in snapshot.processes)
        gpu_processes = [p for p in snapshot.processes if p.gpu_sm_percent > 0]

        data['aggregated_metrics'] = {
            'total_cpu_percent': round(total_cpu, 2),
            'total_memory_bytes': total_memory,
            'total_memory_gb': round(total_memory / (1024**3), 2),
            'num_processes': len(snapshot.processes),
            'num_gpu_processes': len(gpu_processes),
            'avg_cpu_per_process': round(total_cpu / len(snapshot.processes), 2) if snapshot.processes else 0,
            'avg_memory_per_process': total_memory // len(snapshot.processes) if snapshot.processes else 0,
        }

        # Top resource consumers
        data['top_processes'] = {
            'by_cpu': [p.to_dict() for p in sorted(snapshot.processes, key=lambda x: x.cpu_usage_percent, reverse=True)[:5]],
            'by_memory': [p.to_dict() for p in sorted(snapshot.processes, key=lambda x: x.memory_bytes, reverse=True)[:5]],
        }

        if gpu_processes:
            data['top_processes']['by_gpu'] = [
                p.to_dict() for p in sorted(gpu_processes, key=lambda x: x.gpu_sm_percent, reverse=True)[:5]
            ]

        return data

    def _add_metadata(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add processing metadata to the data.

        Args:
            data: Processed data

        Returns:
            Data with metadata
        """
        data['processing_metadata'] = {
            'processed_at': datetime.now().isoformat(),
            'processor_version': '1.0.0',
            'total_processed': self.processed_count,
        }

        return data

    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics"""
        return {
            'processed_count': self.processed_count,
            'validation_errors': self.validation_errors,
            'processing_errors': self.processing_errors,
            'success_rate': (
                self.processed_count / (self.processed_count + self.processing_errors)
                if (self.processed_count + self.processing_errors) > 0
                else 0
            )
        }
