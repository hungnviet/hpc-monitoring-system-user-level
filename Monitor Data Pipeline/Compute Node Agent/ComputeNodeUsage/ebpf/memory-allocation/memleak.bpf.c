#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "memleak.shared.h"

const volatile int target_pid = -1;

// Map: address -> alloc_info
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, u64);
    __type(value, struct alloc_info);
} allocs SEC(".maps");

// Temporary storage: tid -> size
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, u64);
} sizes SEC(".maps");

// Map: tgid -> total_bytes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, u64);
} current_allocs SEC(".maps");

static __always_inline int gen_alloc_enter(u64 size)
{
    pid_t tgid = bpf_get_current_pid_tgid() >> 32;
    
    if (target_pid != -1 && tgid != target_pid)
        return 0;
    
    // Store size for this thread temporarily
    u64 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);
    
    return 0;
}

static __always_inline int gen_alloc_exit(u64 address)
{
    u64 tid = bpf_get_current_pid_tgid();
    pid_t tgid = tid >> 32;
    
    u64 *size_ptr = bpf_map_lookup_elem(&sizes, &tid);
    if (!size_ptr)
        return 0;
    
    u64 size = *size_ptr;
    bpf_map_delete_elem(&sizes, &tid);
    
    if (address == 0)
        return 0;
    
    // Store allocation info
    struct alloc_info info = {
        .size = size,
        .tgid = tgid,
    };
    bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);
    
    // Update process total
    u64 *total = bpf_map_lookup_elem(&current_allocs, &tgid);
    if (total) {
        __sync_fetch_and_add(total, size);
    } else {
        bpf_map_update_elem(&current_allocs, &tgid, &size, BPF_ANY);
    }
    
    return 0;
}

static __always_inline int gen_free_enter(u64 address)
{
    struct alloc_info *info = bpf_map_lookup_elem(&allocs, &address);
    if (!info)
        return 0;
    
    pid_t tgid = info->tgid;
    u64 size = info->size;
    
    bpf_map_delete_elem(&allocs, &address);
    
    // Update process total
    u64 *total = bpf_map_lookup_elem(&current_allocs, &tgid);
    if (total && *total >= size) {
        __sync_fetch_and_add(total, -size);
    }
    
    return 0;
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:malloc")
int BPF_KPROBE(malloc_enter, u64 size)
{
    return gen_alloc_enter(size);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:malloc")
int BPF_KRETPROBE(malloc_exit)
{
    u64 ret = PT_REGS_RC(ctx);
    return gen_alloc_exit(ret);
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:free")
int BPF_KPROBE(free_enter, u64 address)
{
    return gen_free_enter(address);
}

char LICENSE[] SEC("license") = "GPL";