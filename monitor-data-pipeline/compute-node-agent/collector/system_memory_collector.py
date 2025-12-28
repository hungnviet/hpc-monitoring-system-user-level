"""
System-level memory usage collector using /proc/meminfo.
"""
from typing import Dict, Any


class SystemMemoryCollector:
    def collect(self) -> Dict[str, Any]:
        """
        Read memory usage from /proc/meminfo.

        Returns:
            Dict with memory_usage_percent, memory_used_bytes, memory_total_bytes
        """
        mem_info = {}

        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0].rstrip(":")
                    # Values are in kB
                    value_kb = int(parts[1])
                    mem_info[key] = value_kb * 1024  # Convert to bytes

        total = mem_info.get("MemTotal", 0)
        available = mem_info.get("MemAvailable", 0)

        if total == 0:
            return {
                "memory_usage_percent": 0.0,
                "memory_used_bytes": 0,
                "memory_total_bytes": 0
            }

        used = total - available
        usage_percent = 100.0 * used / total

        return {
            "memory_usage_percent": round(usage_percent, 2),
            "memory_used_bytes": used,
            "memory_total_bytes": total
        }
