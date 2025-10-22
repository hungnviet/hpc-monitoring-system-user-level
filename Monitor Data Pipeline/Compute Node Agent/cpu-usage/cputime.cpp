#include "cputime.skel.h"
#include <bpf/bpf.h>  // Add this for bpf_map_* functions
#include <algorithm>
#include <csignal>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <unistd.h>
#include <vector>

static volatile bool exiting = false;

static void sig_handler(int) { exiting = true; }

// Helper to read the command name for a given PID/TGID
std::string get_comm_for_pid(int pid) {
  std::string comm = "[exited]";
  std::ifstream comm_file("/proc/" + std::to_string(pid) + "/comm");
  if (comm_file.is_open()) {
    std::getline(comm_file, comm);
  }
  return comm;
}

// Helper to get the TGID (Process ID) for a given TID (Thread ID)
int get_tgid_for_tid(int tid) {
  std::string line;
  std::ifstream status_file("/proc/" + std::to_string(tid) + "/status");
  if (status_file.is_open()) {
    while (std::getline(status_file, line)) {
      if (line.rfind("Tgid:", 0) == 0) {
        try {
          return std::stoi(line.substr(5));
        } catch (...) {
          return -1;
        }
      }
    }
  }
  return -1;
}

int main(int argc, char **argv) {
  struct cputime_bpf *skel;
  int err;
  int interval = 1;

  if (argc > 1) {
    interval = std::stoi(argv[1]);
  }

  // Set up signal handler for clean exit
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  // Open, load, and verify the BPF skeleton
  skel = cputime_bpf__open();
  if (!skel) {
    std::cerr << "Failed to open BPF skeleton" << std::endl;
    return 1;
  }

  err = cputime_bpf__load(skel);
  if (err) {
    std::cerr << "Failed to load and verify BPF skeleton" << std::endl;
    cputime_bpf__destroy(skel);
    return 1;
  }

  // Attach the eBPF program to the tracepoint
  err = cputime_bpf__attach(skel);
  if (err) {
    std::cerr << "Failed to attach BPF skeleton" << std::endl;
    cputime_bpf__destroy(skel);
    return 1;
  }

  std::cout << "Tracing CPU time... Hit Ctrl-C to end." << std::endl;

  // --- Main Loop ---
  while (!exiting) {
    sleep(interval);

    std::cout << "\n[" << time(nullptr) << "] Total On-CPU Time:" << std::endl;
    printf("%-6s %-16s %s\n", "PID", "COMM", "CPU_TIME_MS");

    // Read per-thread times from the kernel map
    int map_fd = bpf_map__fd(skel->maps.cpu_total_ns);
    pid_t lookup_key = -1, next_key;
    uint64_t time_ns;
    std::vector<std::pair<pid_t, uint64_t>> thread_times;

    while (bpf_map_get_next_key(map_fd, &lookup_key, &next_key) == 0) {
      if (bpf_map_lookup_elem(map_fd, &next_key, &time_ns) == 0) {
        thread_times.push_back({next_key, time_ns});
      }
      lookup_key = next_key;
    }

    // Aggregate thread times by process ID (TGID) in user-space
    std::map<pid_t, uint64_t> process_times;
    for (const auto &entry : thread_times) {
      int tid = entry.first;
      uint64_t thread_ns = entry.second;
      int tgid = get_tgid_for_tid(tid);
      if (tgid > 0) {
        process_times[tgid] += thread_ns;
      }
    }

    // Convert map to vector for sorting
    std::vector<std::pair<pid_t, uint64_t>> sorted_procs(process_times.begin(),
                                                         process_times.end());
    // Fix lambda - use explicit types instead of auto
    std::sort(sorted_procs.begin(), sorted_procs.end(),
              [](const std::pair<pid_t, uint64_t> &a, const std::pair<pid_t, uint64_t> &b) {
                return a.second > b.second;
              });

    for (const auto &entry : sorted_procs) {
      printf("%-6d %-16s %.3f\n", entry.first,
             get_comm_for_pid(entry.first).c_str(), entry.second / 1000000.0);
    }

    // Clear entries for next interval
    for (const auto &entry : thread_times) {
      bpf_map_delete_elem(map_fd, &entry.first);
    }
  }

  std::cout << "\nDetaching and cleaning up..." << std::endl;
  cputime_bpf__destroy(skel);

  return 0;
}