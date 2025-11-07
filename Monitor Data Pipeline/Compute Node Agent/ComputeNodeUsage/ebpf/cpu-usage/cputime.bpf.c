#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, u64);
} cpu_total_ns SEC(".maps");

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    pid_t prev_tid = prev->pid;
    u64 ts = bpf_ktime_get_ns();
    u64 *prev_ts;
    
    // Update time for the thread being switched out
    prev_ts = bpf_map_lookup_elem(&cpu_total_ns, &prev_tid);
    if (prev_ts) {
        u64 delta = ts - *prev_ts;
        u64 *total = bpf_map_lookup_elem(&cpu_total_ns, &prev_tid);
        if (total) {
            __sync_fetch_and_add(total, delta);
        }
    } else {
        bpf_map_update_elem(&cpu_total_ns, &prev_tid, &ts, BPF_ANY);
    }
    
    // Record start time for thread being switched in
    pid_t next_tid = next->pid;
    bpf_map_update_elem(&cpu_total_ns, &next_tid, &ts, BPF_ANY);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";