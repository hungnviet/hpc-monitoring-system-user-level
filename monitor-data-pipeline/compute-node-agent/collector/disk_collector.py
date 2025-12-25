from bcc import BPF
import time
import argparse
from typing import Dict

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

struct io_t {
    u64 read_bytes;
    u64 write_bytes;
};

BPF_HASH(io_by_pid, u32, struct io_t);

static __always_inline int add_io(u32 pid, u64 bytes, int is_write) {
    if (bytes == 0) return 0;

    struct io_t zero = {};
    struct io_t *v = io_by_pid.lookup_or_init(&pid, &zero);
    if (!v) return 0;

    if (is_write) v->write_bytes += bytes;
    else          v->read_bytes  += bytes;

    return 1;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    long ret = args->ret;
    if (ret <= 0) return 0;
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    add_io(pid, (u64)ret, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pread64) {
    long ret = args->ret;
    if (ret <= 0) return 0;
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    add_io(pid, (u64)ret, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_write) {
    long ret = args->ret;
    if (ret <= 0) return 0;
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    add_io(pid, (u64)ret, 1);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pwrite64) {
    long ret = args->ret;
    if (ret <= 0) return 0;
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    add_io(pid, (u64)ret, 1);
    return 0;
}
"""

class DiskCollector:
    def __init__(self):
        self.bpf = BPF(text=BPF_PROGRAM)
        self.io_by_pid = self.bpf.get_table("io_by_pid")

    def collect(self) -> Dict[int, Dict[str, int]]:
        out: Dict[int, Dict[str, int]] = {}
        for k, v in self.io_by_pid.items():
            pid = int(k.value)
            out[pid] = {
                "read_bytes": int(v.read_bytes),
                "write_bytes": int(v.write_bytes),
            }
        return out

    def clear(self) -> None:
        self.io_by_pid.clear()



