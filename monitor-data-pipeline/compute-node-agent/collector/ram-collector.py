import os
import time
import argparse
from typing import Dict, Any

def read_rss_bytes(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    kb = int(line.split()[1])
                    return kb * 1024
    except Exception:
        pass
    return 0

def list_pids():
    for name in os.listdir("/proc"):
        if name.isdigit():
            yield int(name)

class RamCollector:
    def __init__(self, sample_interval_s: float = 1.0):
        self.sample_interval_s = max(0.2, sample_interval_s)

    def collect_window(self, window_s: float) -> Dict[int, Dict[str, Any]]:
        end = time.time() + window_s
        acc: Dict[int, Dict[str, int]] = {}

        while time.time() < end:
            for pid in list_pids():
                rss = read_rss_bytes(pid)
                if pid not in acc:
                    acc[pid] = {"sum": rss, "count": 1}
                else:
                    acc[pid]["sum"] += rss
                    acc[pid]["count"] += 1

            time.sleep(self.sample_interval_s)

        out: Dict[int, Dict[str, Any]] = {}
        for pid, v in acc.items():
            if v["count"] > 0 and v["sum"] > 0:
                out[pid] = {
                    "avg_rss_bytes": v["sum"] // v["count"]
                }
        return out

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("window", type=float, help="Window time (seconds)")
    args = parser.parse_args()

    collector = RamCollector(sample_interval_s=1.0)

    try:
        while True:
            data = collector.collect_window(args.window)
            for pid, info in data.items():
                print(f"{pid} - avg={info['avg_rss_bytes']} bytes")
            print("-" * 48)
    except KeyboardInterrupt:
        pass
