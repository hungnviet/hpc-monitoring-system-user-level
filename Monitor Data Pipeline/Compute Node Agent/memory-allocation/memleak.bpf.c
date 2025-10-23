#define __BPF__
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "memleak.shared.h"

char LICENSE[] SEC("license") = "GPL";

// --- BPF Maps ---

// Temporary storage for allocation size, keyed by thread ID
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t);     // TID
  __type(value, size_t);  // alloc size
} sizes SEC(".maps");

// Main map of outstanding allocations, keyed by allocated address
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1000000);
  __type(key, u64);             // address
  __type(value, struct alloc_info);
} allocs_info SEC(".maps");

// Total accumulated allocations per process
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t); // TGID
  __type(value, u64); // total bytes
} total_allocs SEC(".maps");

// Perf event buffer for exit events
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} exit_events SEC(".maps");

// --- Allocation/Free Handlers ---

static __always_inline int gen_alloc_enter(size_t size) {
  pid_t tid = (pid_t)bpf_get_current_pid_tgid();
  bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);
  return 0;
}

static __always_inline int gen_alloc_exit(struct pt_regs *ctx) {
  pid_t tid = (pid_t)bpf_get_current_pid_tgid();
  pid_t tgid = (pid_t)(bpf_get_current_pid_tgid() >> 32);

  u64 address = PT_REGS_RC(ctx);
  if (address == 0)
    return 0;

  size_t *size_p = bpf_map_lookup_elem(&sizes, &tid);
  if (!size_p)
    return 0;

  struct alloc_info info = {.size = *size_p, .tgid = tgid};
  bpf_map_update_elem(&allocs_info, &address, &info, BPF_ANY);
  bpf_map_delete_elem(&sizes, &tid);

  u64 *ptotal = bpf_map_lookup_elem(&total_allocs, &tgid);
  u64 new_total = info.size;
  if (ptotal)
    new_total += *ptotal;
  bpf_map_update_elem(&total_allocs, &tgid, &new_total, BPF_ANY);

  return 0;
}

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size) {
  return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit) {
  return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(calloc_enter, size_t nmemb, size_t size) {
  return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe")
int BPF_KRETPROBE(calloc_exit) {
  return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(realloc_enter, void *ptr, size_t size) {
  u64 address = (u64)ptr;
  if (address != 0) {
    bpf_map_delete_elem(&allocs_info, &address);
  }
  return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(realloc_exit) {
  return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void *ptr) {
  u64 address = (u64)ptr;
  if (address == 0)
    return 0;
  bpf_map_delete_elem(&allocs_info, &address);
  return 0;
}

// Sends the final report for a process (once, when main thread exits)
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  pid_t tid = (pid_t)pid_tgid;
  pid_t tgid = (pid_t)(pid_tgid >> 32);

  // Only report when the main thread (process leader) exits
  if (tid != tgid)
    return 0;

  u64 *ptotal = bpf_map_lookup_elem(&total_allocs, &tgid);
  if (!ptotal)
    return 0;

  struct exit_event_t event = {
      .tgid = tgid,
      .total_allocs_bytes = *ptotal,
      .uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF),
  };
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  bpf_perf_event_output(ctx, &exit_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

  bpf_map_delete_elem(&total_allocs, &tgid);
  return 0;
}