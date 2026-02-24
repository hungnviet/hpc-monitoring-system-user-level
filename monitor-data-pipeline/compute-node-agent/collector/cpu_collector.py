from bcc import BPF
import time
import argparse
from typing import Dict, Any

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_CPUS 128
#define TASK_COMM_LEN 16
#define MAX_CMDLINE_LEN 128

BPF_ARRAY(last_ts, u64, MAX_CPUS);
BPF_ARRAY(cur_pid, u32, MAX_CPUS);

struct pid_info_t {
    u64 cpu_ontime_ns;
    u32 uid;
    u32 ppid;           // Parent PID for process hierarchy
    u8 exited;          // Flag: 1 if process has exited
    char comm[TASK_COMM_LEN];
};

// Active processes
BPF_HASH(pid_info, u32, struct pid_info_t);

// Exited processes - preserved until collected
BPF_HASH(exited_pid_info, u32, struct pid_info_t);

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

// Track process creation - catch new processes immediately
TRACEPOINT_PROBE(sched, sched_process_fork) {
    // Get parent info
    u32 parent_pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    u32 child_pid = args->child_pid;
    
    // Initialize tracking for the new process
    struct pid_info_t zero = {};
    zero.ppid = parent_pid;
    zero.exited = 0;
    
    u64 uid_gid = bpf_get_current_uid_gid();
    zero.uid = (u32)uid_gid;
    
    bpf_get_current_comm(&zero.comm, sizeof(zero.comm));
    
    pid_info.update(&child_pid, &zero);
    return 0;
}

// Track process exit - CRITICAL for short-lived processes
// Preserves CPU time data before the process disappears
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    
    struct pid_info_t *info = pid_info.lookup(&pid);
    if (info) {
        // Mark as exited and copy to exited map
        struct pid_info_t exited_info = *info;
        exited_info.exited = 1;
        exited_pid_info.update(&pid, &exited_info);
        
        // Remove from active map
        pid_info.delete(&pid);
    }
    return 0;
}

// Track process exec - updates command name when process executes new binary
TRACEPOINT_PROBE(sched, sched_process_exec) {
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    
    struct pid_info_t *info = pid_info.lookup(&pid);
    if (info) {
        // Update comm to reflect the new executable
        bpf_get_current_comm(&info->comm, sizeof(info->comm));
    }
    return 0;
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
        self.exited_pid_info = self.bpf.get_table("exited_pid_info")

    def collect(self) -> Dict[int, Dict[str, Any]]:
        """Collect CPU metrics from both active and exited processes."""
        out: Dict[int, Dict[str, Any]] = {}
        
        # Collect from active processes
        for k, v in self.pid_info.items():
            pid = k.value
            # Skip PID 0 (swapper/idle) as it's not a user process
            if pid == 0:
                continue
            out[pid] = {
                "cpu_ontime_ns": int(v.cpu_ontime_ns),
                "uid": int(v.uid),
                "ppid": int(v.ppid),
                "comm": v.comm.decode("utf-8", "replace").rstrip("\x00"),
                "exited": False,
            }
        
        # Collect from exited processes (short-lived processes captured here)
        for k, v in self.exited_pid_info.items():
            pid = k.value
            if pid == 0:
                continue
            # If already in out (unlikely but possible), merge the data
            if pid in out:
                out[pid]["cpu_ontime_ns"] += int(v.cpu_ontime_ns)
            else:
                out[pid] = {
                    "cpu_ontime_ns": int(v.cpu_ontime_ns),
                    "uid": int(v.uid),
                    "ppid": int(v.ppid),
                    "comm": v.comm.decode("utf-8", "replace").rstrip("\x00"),
                    "exited": True,
                }
        
        return out

    def clear(self) -> None:
        """Clear both active and exited process maps."""
        self.pid_info.clear()
        self.exited_pid_info.clear()
    
    def snapshot(self) -> Dict[int, Dict[str, Any]]:
        """Take a snapshot without clearing - for delta calculation."""
        return self.collect() 




