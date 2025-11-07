#ifndef __MEMLEAK_SHARED_H
#define __MEMLEAK_SHARED_H

#ifdef __BPF__
// Kernel-space types
typedef unsigned long long u64;
typedef unsigned int u32;
typedef int pid_t;
typedef unsigned long size_t;
#else
// User-space types
#include <stdint.h>
#include <sys/types.h>
typedef uint64_t u64;
typedef uint32_t u32;
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// Information about an outstanding allocation
struct alloc_info {
  size_t size;
  pid_t tgid;
};

// Event payload sent to user-space on process exit
struct exit_event_t {
  pid_t tgid;
  u64 total_allocs_bytes;
  u32 uid;                 // owner of the process
  char comm[TASK_COMM_LEN]; // command name at exit
};

#endif /* __MEMLEAK_SHARED_H */