#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <csignal>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <map>
#include <pwd.h>
#include <cstdint>
#include <cstring>
#include <ctime>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "memleak.shared.h"
#include "memleak.skel.h"

// Structure to hold process exit info for interval reporting
struct ProcessExitInfo {
  pid_t tgid;
  uint32_t uid;
  std::string comm;
  std::string username;
  uint64_t total_allocs_bytes;
  uint64_t leak_bytes;
};

static struct memleak_bpf* g_skel = nullptr;
static volatile bool exiting = false;
static std::vector<ProcessExitInfo> g_interval_exits;
static time_t g_interval_start = 0;

static void sig_handler(int) { exiting = true; }

// Raise memlock rlimit to allow BPF maps/programs
static int bump_memlock_rlimit() {
  struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
  return setrlimit(RLIMIT_MEMLOCK, &rl);
}

// Resolve username from UID
static std::string username_from_uid(uint32_t uid) {
  struct passwd* pw = getpwuid(uid);
  if (pw && pw->pw_name) return pw->pw_name;
  return std::to_string(uid);
}

// Helper to find the path to libc for a running process
static std::string find_libc_path_for_pid(int pid) {
  std::string line;
  std::ifstream maps_file("/proc/" + std::to_string(pid) + "/maps");
  if (!maps_file.is_open()) {
    std::cerr << "Failed to open maps file for PID " << pid << std::endl;
    return "";
  }
  while (std::getline(maps_file, line)) {
    if (line.find(" r-xp ") != std::string::npos &&
        line.find("libc.so.6") != std::string::npos) {
      size_t path_start = line.find('/');
      if (path_start != std::string::npos) {
        return line.substr(path_start);
      }
    }
  }
  return "";
}

// Try common libc locations by distro/arch
static std::string find_system_libc_path() {
  const char* candidates[] = {
      "/lib64/libc.so.6",
      "/usr/lib64/libc.so.6",
      "/lib/x86_64-linux-gnu/libc.so.6",
      "/lib/aarch64-linux-gnu/libc.so.6",
      "/lib/arm64-linux-gnu/libc.so.6",
      "/lib/libc.so.6",
  };
  struct stat st{};
  for (auto p : candidates) {
    if (stat(p, &st) == 0) return std::string(p);
  }
  return "";
}

// Attach uprobe by function name using libbpf opts API
static bpf_link* attach_uprobe_fn(bpf_program* prog, bool retprobe, pid_t pid,
                                  const char* binary_path, const char* func_name) {
  LIBBPF_OPTS(bpf_uprobe_opts, opts);
  opts.retprobe = retprobe;
  opts.func_name = func_name;
  return bpf_program__attach_uprobe_opts(prog, pid, binary_path, 0, &opts);
}

// Perf Buffer Callback: kernel -> user-space exit event
static void handle_event(void* /*ctx*/, int /*cpu*/, void* data, __u32 /*data_sz*/) {
  const struct exit_event_t* event = (const struct exit_event_t*)data;

  // 1) Calculate final outstanding leaks for this TGID
  uint64_t total_leak_bytes = 0;
  int leaks_map_fd = bpf_map__fd(g_skel->maps.allocs_info);
  uint64_t leak_key = (uint64_t)-1, next_leak_key = 0;
  struct alloc_info info{};
  std::vector<uint64_t> keys_to_delete;

  while (bpf_map_get_next_key(leaks_map_fd, &leak_key, &next_leak_key) == 0) {
    if (bpf_map_lookup_elem(leaks_map_fd, &next_leak_key, &info) == 0) {
      if (info.tgid == event->tgid) {
        total_leak_bytes += info.size;
        keys_to_delete.push_back(next_leak_key);
      }
    }
    leak_key = next_leak_key;
  }

  // 2) Store process exit info for interval reporting (use COMM from event)
  ProcessExitInfo exit_info;
  exit_info.tgid = event->tgid;
  exit_info.uid = event->uid;
  exit_info.comm = std::string(event->comm);
  exit_info.username = username_from_uid(event->uid);
  exit_info.total_allocs_bytes = event->total_allocs_bytes;
  exit_info.leak_bytes = total_leak_bytes;
  g_interval_exits.push_back(exit_info);

  // 3) Clean up allocs_info for this TGID
  for (const auto& key : keys_to_delete) {
    bpf_map_delete_elem(leaks_map_fd, &key);
  }
}

static void handle_lost_events(void* /*ctx*/, int cpu, __u64 lost_cnt) {
  std::cerr << "Lost " << lost_cnt << " events on CPU " << cpu << std::endl;
}

// Print interval report (dedupe by PID just in case)
static void print_interval_report(time_t start_time, time_t end_time) {
  if (g_interval_exits.empty())
    return;

  // Deduplicate by TGID (keep the last one seen in the interval)
  std::map<pid_t, ProcessExitInfo> uniq;
  for (const auto& e : g_interval_exits) {
    uniq[e.tgid] = e;
  }
  std::vector<ProcessExitInfo> rows;
  rows.reserve(uniq.size());
  for (auto& kv : uniq) rows.push_back(kv.second);

  // Sort by total allocations (descending)
  std::sort(rows.begin(), rows.end(),
            [](const ProcessExitInfo& a, const ProcessExitInfo& b) {
              return a.total_allocs_bytes > b.total_allocs_bytes;
            });

  // Title and table header
  std::cout << "\n[" << start_time << " - " << end_time
            << "] Report Of Memory Allocation Of Process Finished In The Time Window\n";
  printf("%-8s %-12s %-6s %-16s %-12s %s\n",
         "UID", "USER", "PID", "COMM", "TOTAL_ALLOCS", "MEM_LEAK");

  // Values (MB)
  for (const auto& proc : rows) {
    printf("%-8u %-12s %-6d %-16s %-12.3f %.3f\n",
           proc.uid,
           proc.username.c_str(),
           proc.tgid,
           proc.comm.c_str(),
           proc.total_allocs_bytes / (1024.0 * 1024.0),
           proc.leak_bytes / (1024.0 * 1024.0));
  }
  fflush(stdout);

  g_interval_exits.clear();
}

int main(int argc, char** argv) {
  struct memleak_bpf* skel = nullptr;
  struct perf_buffer* pb = nullptr;
  int err = 0;
  pid_t pid = -1;
  std::string libc_path;
  int interval = 5; // Default 5 second interval

  // --- Argument Parsing ---
  if (argc < 2) {
    std::cerr << "Usage:\n"
              << "  " << argv[0] << " -p <PID> [interval]\n"
              << "  " << argv[0] << " -a [interval]\n";
    return 1;
  }

  if (std::string(argv[1]) == "-p") {
    if (argc < 3) { std::cerr << "Usage: " << argv[0] << " -p <PID> [interval]\n"; return 1; }
    try { pid = std::stoi(argv[2]); } catch (...) { std::cerr << "Invalid PID.\n"; return 1; }
    if (argc > 3) {
      try { interval = std::stoi(argv[3]); } catch (...) { std::cerr << "Invalid interval.\n"; return 1; }
    }
    libc_path = find_libc_path_for_pid(pid);
    if (libc_path.empty()) {
      std::cerr << "Failed to find libc.so.6 for PID " << pid << std::endl;
      return 1;
    }
    std::cout << "Tracing PID " << pid << " using libc: " << libc_path
              << " (interval: " << interval << "s)" << std::endl;
  } else if (std::string(argv[1]) == "-a") {
    pid = -1;
    if (argc > 2) {
      try { interval = std::stoi(argv[2]); } catch (...) { std::cerr << "Invalid interval.\n"; return 1; }
    }
    libc_path = find_system_libc_path();
    if (libc_path.empty()) {
      std::cerr << "Failed to locate system libc.so.6 (try -p <PID>)\n";
      return 1;
    }
    std::cout << "Tracing all processes using libc: " << libc_path
              << " (interval: " << interval << "s)" << std::endl;
  } else {
    std::cerr << "Invalid arguments.\n"; return 1;
  }

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  if (bump_memlock_rlimit()) {
    std::cerr << "Warning: failed to increase RLIMIT_MEMLOCK, load may fail.\n";
  }

  skel = memleak_bpf__open();
  if (!skel) {
    std::cerr << "Failed to open BPF skeleton\n";
    return 1;
  }
  g_skel = skel;

  err = memleak_bpf__load(skel);
  if (err) {
    std::cerr << "Failed to load BPF skeleton: " << err << std::endl;
    err = 1;
    goto cleanup;
  }

  // --- Attach uprobes by function name ---
  std::cout << "Attaching probes..." << std::endl;
  skel->links.malloc_enter  = attach_uprobe_fn(skel->progs.malloc_enter,  false, pid, libc_path.c_str(), "malloc");
  skel->links.malloc_exit   = attach_uprobe_fn(skel->progs.malloc_exit,   true,  pid, libc_path.c_str(), "malloc");
  skel->links.calloc_enter  = attach_uprobe_fn(skel->progs.calloc_enter,  false, pid, libc_path.c_str(), "calloc");
  skel->links.calloc_exit   = attach_uprobe_fn(skel->progs.calloc_exit,   true,  pid, libc_path.c_str(), "calloc");
  skel->links.realloc_enter = attach_uprobe_fn(skel->progs.realloc_enter, false, pid, libc_path.c_str(), "realloc");
  skel->links.realloc_exit  = attach_uprobe_fn(skel->progs.realloc_exit,  true,  pid, libc_path.c_str(), "realloc");
  skel->links.free_enter    = attach_uprobe_fn(skel->progs.free_enter,    false, pid, libc_path.c_str(), "free");

  // Attach tracepoint for process exit
  skel->links.handle_exit = bpf_program__attach(skel->progs.handle_exit);

  if (!skel->links.malloc_enter || !skel->links.malloc_exit ||
      !skel->links.calloc_enter || !skel->links.calloc_exit ||
      !skel->links.realloc_enter || !skel->links.realloc_exit ||
      !skel->links.free_enter || !skel->links.handle_exit) {
    std::cerr << "Failed to attach one or more probes.\n";
    err = 1;
    goto cleanup;
  }

  // Set up perf buffer
  {
    int map_fd = bpf_map__fd(skel->maps.exit_events);
    pb = perf_buffer__new(map_fd, 8, handle_event, handle_lost_events, nullptr, nullptr);
    if (!pb) {
      std::cerr << "Failed to open perf buffer: " << strerror(errno) << std::endl;
      err = 1;
      goto cleanup;
    }
  }

  std::cout << "Monitoring memory allocations... Hit Ctrl-C to end." << std::endl;

  // Initialize interval start time
  g_interval_start = time(nullptr);

  // --- Main Loop with Interval Reporting ---
  while (!exiting) {
    // Poll for events with timeout
    int rc = perf_buffer__poll(pb, 100); // 100ms timeout
    if (rc < 0 && rc != -EINTR) {
      std::cerr << "Error polling perf buffer: " << strerror(-rc) << std::endl;
      break;
    }

    // Check if interval has elapsed
    time_t now = time(nullptr);
    if (now - g_interval_start >= interval) {
      time_t interval_end = now;
      print_interval_report(g_interval_start, interval_end);
      g_interval_start = interval_end;
    }

    // If tracing a single PID, exit when it’s gone after printing its report
    if (pid != -1) {
      if (kill(pid, 0) == -1 && errno == ESRCH) {
        // Poll a bit more to catch the exit event
        for (int i = 0; i < 10; i++) {
          perf_buffer__poll(pb, 100);
        }
        time_t final_time = time(nullptr);
        print_interval_report(g_interval_start, final_time);
        break;
      }
    }
  }

  // Print any remaining data
  if (!g_interval_exits.empty()) {
    time_t final_time = time(nullptr);
    print_interval_report(g_interval_start, final_time);
  }

cleanup:
  std::cout << "\nDetaching and cleaning up..." << std::endl;
  perf_buffer__free(pb);
  memleak_bpf__destroy(skel);
  return err;
}