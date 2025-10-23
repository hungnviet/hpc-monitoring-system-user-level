#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Per-TID last schedule-in timestamp (ns)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, pid_t); // TID
  __type(value, u64); // ns
} start_ns SEC(".maps");

// Per-TID accumulated on-CPU time (ns)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, pid_t); // TID
  __type(value, u64); // ns
} cpu_total_ns SEC(".maps");

// Per-TID UID tracking
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, pid_t); // TID
  __type(value, u32); // UID
} tid_uid SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
  pid_t prev_tid = ctx->prev_pid; // scheduled out
  pid_t next_tid = ctx->next_pid; // scheduled in
  u64 now = bpf_ktime_get_ns();

  // Account time for the task being scheduled out
  if (prev_tid != 0) {
    u64 *pstart = bpf_map_lookup_elem(&start_ns, &prev_tid);
    if (pstart) {
      u64 delta = now - *pstart;
      bpf_map_delete_elem(&start_ns, &prev_tid);

      u64 *ptotal = bpf_map_lookup_elem(&cpu_total_ns, &prev_tid);
      u64 total = ptotal ? (*ptotal + delta) : delta;
      bpf_map_update_elem(&cpu_total_ns, &prev_tid, &total, BPF_ANY);
    }
  }

  // Record start for the task being scheduled in
  if (next_tid != 0) {
    bpf_map_update_elem(&start_ns, &next_tid, &now, BPF_ANY);
    
    // Store UID for this TID
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_map_update_elem(&tid_uid, &next_tid, &uid, BPF_ANY);
  }

  return 0;
}