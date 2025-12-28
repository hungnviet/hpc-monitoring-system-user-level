"""
System-level CPU usage collector using /proc/stat.
Calculates overall CPU usage percentage across all cores.
"""
from typing import Dict, Any, Tuple


class SystemCPUCollector:
    def __init__(self):
        self._prev_idle: int = 0
        self._prev_total: int = 0

    def _read_proc_stat(self) -> Tuple[int, int]:
        """
        Read /proc/stat and return (idle_time, total_time).

        /proc/stat format (first line):
        cpu user nice system idle iowait irq softirq steal guest guest_nice
        """
        with open("/proc/stat", "r") as f:
            line = f.readline()

        parts = line.split()
        # parts[0] is 'cpu', parts[1:] are the time values
        times = [int(x) for x in parts[1:]]

        # idle = idle + iowait (positions 3 and 4, 0-indexed)
        idle = times[3] + times[4] if len(times) > 4 else times[3]
        total = sum(times)

        return idle, total

    def collect(self) -> Dict[str, Any]:
        """
        Calculate CPU usage percentage since last call.
        First call returns 0.0 (no previous baseline).
        """
        idle, total = self._read_proc_stat()

        if self._prev_total == 0:
            # First call - save baseline and return 0
            self._prev_idle = idle
            self._prev_total = total
            return {"cpu_usage_percent": 0.0}

        idle_delta = idle - self._prev_idle
        total_delta = total - self._prev_total

        # Update for next call
        self._prev_idle = idle
        self._prev_total = total

        if total_delta == 0:
            return {"cpu_usage_percent": 0.0}

        # CPU usage = 100 - idle percentage
        cpu_usage = 100.0 * (1.0 - idle_delta / total_delta)
        return {"cpu_usage_percent": round(cpu_usage, 2)}

    def reset(self) -> None:
        """Reset the baseline for fresh calculation."""
        self._prev_idle = 0
        self._prev_total = 0
