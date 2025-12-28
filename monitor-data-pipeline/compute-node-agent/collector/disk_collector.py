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

// Struct for syscall exit tracepoints
struct syscall_exit_args {
    u64 __unused__;
    long __syscall_nr;
    long ret;
};

int trace_read_exit(struct syscall_exit_args *args) {
    long ret = args->ret;
    if (ret <= 0) return 0;
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    add_io(pid, (u64)ret, 0);
    return 0;
}

int trace_pread64_exit(struct syscall_exit_args *args) {
    long ret = args->ret;
    if (ret <= 0) return 0;
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    add_io(pid, (u64)ret, 0);
    return 0;
}

int trace_write_exit(struct syscall_exit_args *args) {
    long ret = args->ret;
    if (ret <= 0) return 0;
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    add_io(pid, (u64)ret, 1);
    return 0;
}

int trace_pwrite64_exit(struct syscall_exit_args *args) {
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
        self.bpf.attach_tracepoint(tp="syscalls:sys_exit_read", fn_name="trace_read_exit")
        self.bpf.attach_tracepoint(tp="syscalls:sys_exit_pread64", fn_name="trace_pread64_exit")
        self.bpf.attach_tracepoint(tp="syscalls:sys_exit_write", fn_name="trace_write_exit")
        self.bpf.attach_tracepoint(tp="syscalls:sys_exit_pwrite64", fn_name="trace_pwrite64_exit")
        self.io_by_pid = self.bpf.get_table("io_by_pid")

    def collect(self) -> Dict[int, Dict[str, int]]:
        out: Dict[int, Dict[str, int]] = {}
        for k, v in self.io_by_pid.items():
            pid = k.value
            if pid == 0:
                continue
            out[pid] = {
                "read_bytes": int(v.read_bytes),
                "write_bytes": int(v.write_bytes),
            }
        return out

    def clear(self) -> None:
        self.io_by_pid.clear()



