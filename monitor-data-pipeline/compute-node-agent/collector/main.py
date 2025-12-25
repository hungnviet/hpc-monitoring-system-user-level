import time
from typing import Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor

from cpu_collector import CPUCollector
from disk_collector import DiskCollector
from network_collector import NetCollector
from ram_collector import RamCollector
from gpu_process_collector import GPUComputeMemCollector


def merge(
    cpu: Dict[int, Dict[str, Any]],
    disk: Dict[int, Dict[str, Any]],
    net: Dict[int, Dict[str, Any]],
    ram: Dict[int, Dict[str, Any]],
    gpu: Dict[int, Dict[str, Any]],
) -> Dict[int, Dict[str, Any]]:
    merged: Dict[int, Dict[str, Any]] = {}

    for pid, c in cpu.items():
        obj = {
            "pid": pid,
            "cpu_ontime_ns": c.get("cpu_ontime_ns", 0),
            "uid": c.get("uid"),
            "comm": c.get("comm", ""),
            "read_bytes": 0,
            "write_bytes": 0,
            "net_rx_bytes": 0,
            "net_tx_bytes": 0,
            "avg_rss_bytes": 0,
            "process_name": "",
            "gpu_used_memory_mib": 0,
        }

        d = disk.get(pid)
        if d:
            obj["read_bytes"] = d.get("read_bytes", 0)
            obj["write_bytes"] = d.get("write_bytes", 0)

        n = net.get(pid)
        if n:
            obj["net_rx_bytes"] = n.get("net_rx_bytes", 0)
            obj["net_tx_bytes"] = n.get("net_tx_bytes", 0)

        r = ram.get(pid)
        if r:
            obj["avg_rss_bytes"] = r.get("avg_rss_bytes", 0)

        g = gpu.get(pid)
        if g:
            obj["process_name"] = g.get("process_name", "")
            obj["gpu_used_memory_mib"] = g.get("used_memory_mib", 0)

        merged[pid] = obj

    return merged


class VirtualSensor:
    def __init__( self,ram_sample_interval_s: float = 1.0, max_workers: int = 2):
        self.cpu_col = CPUCollector()
        self.disk_col = DiskCollector()
        self.net_col = NetCollector()
        self.ram_col = RamCollector(sample_interval_s=ram_sample_interval_s)
        self.gpu_col = GPUComputeMemCollector()

        self._executor = ThreadPoolExecutor(max_workers=max_workers)

    def close(self) -> None:
        self._executor.shutdown(wait=False)

    def collect(self, window: float) -> Dict[int, Dict[str, Any]]:
        self.cpu_col.clear()
        self.disk_col.clear()
        self.net_col.clear()

        ram_future = self._executor.submit(self.ram_col.collect_window, window)

        time.sleep(window)

        cpu_data = self.cpu_col.collect()
        disk_data = self.disk_col.collect()
        net_data = self.net_col.collect()
        ram_data = ram_future.result()
        gpu_data = self.gpu_col.collect()  

        return merge(cpu_data, disk_data, net_data, ram_data, gpu_data)
