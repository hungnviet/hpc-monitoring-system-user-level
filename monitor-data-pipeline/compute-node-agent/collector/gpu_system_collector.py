"""
System-level GPU metrics collector using nvidia-smi.
Supports multiple GPUs with per-GPU metrics.
"""
import subprocess
from typing import Dict, Any, List


def _run_nvidia_smi(query: str) -> str:
    """Run nvidia-smi with given query and return stdout."""
    try:
        result = subprocess.run(
            ["nvidia-smi", f"--query-gpu={query}", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=5.0
        )
        if result.returncode != 0:
            return ""
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return ""


class GPUSystemCollector:
    def collect(self) -> Dict[str, Any]:
        """
        Collect per-GPU system metrics.

        nvidia-smi query fields:
        - index: GPU index
        - name: GPU name
        - utilization.gpu: GPU utilization %
        - temperature.gpu: GPU temperature in Celsius
        - power.draw: Current power draw in watts
        - power.limit: Power limit in watts
        - memory.used: Memory used in MiB
        - memory.total: Total memory in MiB

        Returns:
            Dict with 'gpus' key containing list of GPU metrics
        """
        query = "index,name,utilization.gpu,temperature.gpu,power.draw,power.limit,memory.used,memory.total"
        output = _run_nvidia_smi(query)

        if not output:
            return {"gpus": []}

        gpus: List[Dict[str, Any]] = []
        for line in output.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 8:
                continue

            try:
                gpu_data = {
                    "gpu_index": int(parts[0]),
                    "gpu_name": parts[1],
                    "utilization_percent": self._parse_float(parts[2]),
                    "temperature_celsius": self._parse_float(parts[3]),
                    "power_watts": self._parse_float(parts[4]),
                    "power_limit_watts": self._parse_float(parts[5]),
                    "memory_used_mib": self._parse_int(parts[6]),
                    "memory_total_mib": self._parse_int(parts[7])
                }
                gpus.append(gpu_data)
            except (ValueError, IndexError):
                continue

        return {"gpus": gpus}

    @staticmethod
    def _parse_float(value: str) -> float:
        """Parse float, handling 'N/A' or '[Not Supported]'."""
        try:
            return float(value)
        except ValueError:
            return 0.0

    @staticmethod
    def _parse_int(value: str) -> int:
        """Parse int, handling 'N/A' or '[Not Supported]'."""
        try:
            return int(float(value))
        except ValueError:
            return 0
