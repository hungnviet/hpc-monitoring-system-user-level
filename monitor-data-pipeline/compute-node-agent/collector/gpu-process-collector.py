import subprocess
import time
import argparse
from typing import Dict, Any, List

def _run(cmd: List[str]) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1.0)
    if r.returncode != 0:
        return ""
    return r.stdout.strip()

def sample_compute_apps() -> Dict[int, Dict[str, Any]]:
    out = _run([
        "nvidia-smi",
        "--query-compute-apps=pid,process_name,used_memory",
        "--format=csv"
    ])
    if not out:
        return {}

    lines = out.splitlines()
    if len(lines) < 2:
        return {}

    header = [h.strip() for h in lines[0].split(",")]
    def idx_of(names):
        for n in names:
            if n in header:
                return header.index(n)
        return -1

    pid_i = idx_of(["pid"])
    name_i = idx_of(["process_name"])
    mem_i = idx_of(["used_memory", "used_gpu_memory [MiB]", "used_gpu_memory", "used_memory [MiB]", "used_gpu_memory [MiB]"])

    if pid_i < 0 or name_i < 0 or mem_i < 0:
        pid_i, name_i, mem_i = 0, 1, 2

    data: Dict[int, Dict[str, Any]] = {}
    for line in lines[1:]:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) <= max(pid_i, name_i, mem_i):
            continue
        try:
            pid = int(parts[pid_i])
        except ValueError:
            continue
        process_name = parts[name_i]
        mem_str = parts[mem_i].replace("MiB", "").replace("Mib", "").strip()
        try:
            used_mib = int(float(mem_str))
        except ValueError:
            continue

        data[pid] = {"process_name": process_name, "used_memory_mib": used_mib}

    return data

class GPUComputeMemCollector:
    def collect(self) -> Dict[int, Dict[str, Any]]:
        return sample_compute_apps()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("window", type=float, help="Window time (seconds)")
    args = parser.parse_args()

    collector = GPUComputeMemCollector()

    try:
        while True:
            time.sleep(args.window)
            data = collector.collect()
            for pid, info in data.items():
                print(f"{pid} - {info['process_name']} - {info['used_memory_mib']} MiB")
            print("-" * 48)
    except KeyboardInterrupt:
        pass
