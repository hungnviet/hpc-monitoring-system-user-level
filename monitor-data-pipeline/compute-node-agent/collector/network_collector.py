from bcc import BPF
import time
import argparse
from typing import Dict

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct net_io_t {
    u64 rx_bytes;
    u64 tx_bytes;
};

BPF_HASH(net_io, u32, struct net_io_t);

static __always_inline int add_net_bytes(u32 pid, u64 bytes, int is_tx) {
    if (bytes == 0) return 0;

    struct net_io_t zero = {};
    struct net_io_t *v = net_io.lookup_or_init(&pid, &zero);
    if (!v) return 0;

    if (is_tx) v->tx_bytes += bytes;
    else       v->rx_bytes += bytes;

    return 1;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendto) {
    long ret = args->ret;
    if (ret <= 0) return 0;
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    add_net_bytes(pid, (u64)ret, 1);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendmsg) {
    long ret = args->ret;
    if (ret <= 0) return 0;
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    add_net_bytes(pid, (u64)ret, 1);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
    long ret = args->ret;
    if (ret <= 0) return 0;
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    add_net_bytes(pid, (u64)ret, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvmsg) {
    long ret = args->ret;
    if (ret <= 0) return 0;
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    add_net_bytes(pid, (u64)ret, 0);
    return 0;
}
"""

class NetCollector:
    def __init__(self):
        self.bpf = BPF(text=BPF_PROGRAM)
        self.net_io = self.bpf.get_table("net_io")

    def collect(self) -> Dict[int, Dict[str, int]]:
        out: Dict[int, Dict[str, int]] = {}
        for k, v in self.net_io.items():
            pid = int(k.value)
            out[pid] = {
                "net_rx_bytes": int(v.rx_bytes),
                "net_tx_bytes": int(v.tx_bytes),
            }
        return out

    def clear(self) -> None:
        self.net_io.clear()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("window", type=float, help="Window time (seconds)")
    args = parser.parse_args()

    collector = NetCollector()

    try:
        while True:
            collector.clear()
            time.sleep(args.window)
            data = collector.collect()
            for pid, info in data.items():
                print(f"{pid} - rx={info['net_rx_bytes']} bytes | tx={info['net_tx_bytes']} bytes")
            print("-" * 48)
    except KeyboardInterrupt:
        pass


#sudo python3 cpu-collector.py 5
### Sample output:
# 2309 - rx=208 bytes | tx=600 bytes
# 3838 - rx=8704 bytes | tx=0 bytes
# 4013 - rx=0 bytes | tx=8704 bytes
# 7631 - rx=956 bytes | tx=58028 bytes
# 7411 - rx=96 bytes | tx=184 bytes
# 7859 - rx=96 bytes | tx=264 bytes
# 7308 - rx=96 bytes | tx=640 bytes
# 7287 - rx=636 bytes | tx=3044 bytes
# 783 - rx=11055 bytes | tx=0 bytes
# 3433 - rx=640 bytes | tx=208 bytes
