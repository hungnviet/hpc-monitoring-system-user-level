from bcc import BPF
import time
import argparse
from typing import Dict, Any

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_CPUS 128
#define TASK_COMM_LEN 16

BPF_ARRAY(last_ts, u64, MAX_CPUS);
BPF_ARRAY(cur_pid, u32, MAX_CPUS);

struct pid_info_t {
    u64 cpu_ontime_ns;
    u32 uid;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(pid_info, u32, struct pid_info_t);

// Return int (NOT void) to be compatible with BCC's lookup_or_init macro.
static __always_inline int add_cpu_ontime(u32 pid, u64 delta) {
    struct pid_info_t zero = {};
    struct pid_info_t *info = pid_info.lookup_or_init(&pid, &zero);
    if (!info) return 0;

    info->cpu_ontime_ns += delta;

    u64 uid_gid = bpf_get_current_uid_gid();
    info->uid = (u32)uid_gid;

    bpf_get_current_comm(&info->comm, sizeof(info->comm));
    return 1;
}

// Use TRACEPOINT_PROBE macro for better compatibility
// This is called on context switch - the "prev" task is being switched out
TRACEPOINT_PROBE(sched, sched_switch) {
    u32 cpu = bpf_get_smp_processor_id();
    u64 curTime = bpf_ktime_get_ns();

    // Get PID using bpf_get_current_pid_tgid() - this is the PREV task
    // Upper 32 bits = PID (tgid), Lower 32 bits = TID
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);

    u64 *tsp = last_ts.lookup(&cpu);
    if (!tsp) return 0;

    u64 prevTime = *tsp;
    last_ts.update(&cpu, &curTime);

    if (prevTime == 0) {
        cur_pid.update(&cpu, &pid);
        return 0;
    }

    u64 delta = curTime - prevTime;

    // Account CPU time to the process that was previously running
    u32 *prev_p = cur_pid.lookup(&cpu);
    if (prev_p && *prev_p > 0) {
        add_cpu_ontime(*prev_p, delta);
    }

    cur_pid.update(&cpu, &pid);
    return 0;
}
"""


class CPUCollector:
    def __init__(self):
        self.bpf = BPF(text=BPF_PROGRAM)
        # TRACEPOINT_PROBE auto-attaches, no need for manual attach
        self.pid_info = self.bpf.get_table("pid_info")  

    def collect(self) -> Dict[int, Dict[str, Any]]:
        out: Dict[int, Dict[str, Any]] = {}
        for k, v in self.pid_info.items():
            pid = k.value
            # Skip PID 0 (swapper/idle) as it's not a user process
            if pid == 0:
                continue
            out[pid] = {
                "cpu_ontime_ns": int(v.cpu_ontime_ns),
                "uid": int(v.uid),
                "comm": v.comm.decode("utf-8", "replace").rstrip("\x00"),
            }
        return out

    def clear(self) -> None:
        self.pid_info.clear() 




#sudo python3 cpu-collector.py 5
# Example output:
# 2527 - 50559 | 1054800026 | gmain
# 15 - 894598 | 0 | rcu_preempt
# 1990 - 1860654 | 1054800026 | Xorg
# 757 - 853492 | 0 | containerd
# 783 - 368815 | 0 | systemd-logind
# 7216 - 2055393 | 1054800026 | firefox-esr
# 773 - 37430 | 0 | sssd_sudo
# 7229 - 182781 | 1054800026 | Socket Thread
# 3962 - 364852 | 1054800026 | code
# 4029 - 1118673 | 1054800026 | code
# 2028 - 82501 | 1054800026 | goa-daemon
