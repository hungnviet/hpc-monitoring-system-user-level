#include "cputime.skel.h"
#include <bpf/bpf.h>
#include <algorithm>
#include <csignal>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <unistd.h>
#include <vector>
#include <pwd.h>

static volatile bool exiting = false;

static void sig_handler(int) { exiting = true; }

// Helper to get username from UID
std::string get_username_for_uid(uint32_t uid) {
  struct passwd *pw = getpwuid(uid);
  if (pw) {
    return std::string(pw->pw_name);
  }
  return std::to_string(uid); // Fallback to numeric UID
}

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

// Structure to hold process info
struct ProcessInfo {
  pid_t pid;
  uint32_t uid;
  uint64_t cpu_time_ns;
  std::string comm;
  std::string username;
};

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
    printf("%-8s %-12s %-6s %-16s %s\n", "UID", "USER", "PID", "COMM", "CPU_TIME_MS");

    // Read per-thread times from the kernel map
    int cpu_map_fd = bpf_map__fd(skel->maps.cpu_total_ns);
    int uid_map_fd = bpf_map__fd(skel->maps.tid_uid);
    pid_t lookup_key = -1, next_key;
    uint64_t time_ns;
    uint32_t uid;
    std::vector<std::tuple<pid_t, uint64_t, uint32_t>> thread_data; // TID, CPU time, UID

    while (bpf_map_get_next_key(cpu_map_fd, &lookup_key, &next_key) == 0) {
      if (bpf_map_lookup_elem(cpu_map_fd, &next_key, &time_ns) == 0) {
        // Try to get UID for this TID
        if (bpf_map_lookup_elem(uid_map_fd, &next_key, &uid) != 0) {
          uid = 0; // Default to root if UID not found
        }
        thread_data.push_back({next_key, time_ns, uid});
      }
      lookup_key = next_key;
    }

    // Aggregate thread times by process ID (TGID) and UID
    std::map<std::pair<pid_t, uint32_t>, uint64_t> process_times; // Key: (TGID, UID), Value: CPU time
    for (const auto &entry : thread_data) {
      int tid = std::get<0>(entry);
      uint64_t thread_ns = std::get<1>(entry);
      uint32_t thread_uid = std::get<2>(entry);
      
      int tgid = get_tgid_for_tid(tid);
      if (tgid > 0) {
        auto key = std::make_pair(tgid, thread_uid);
        process_times[key] += thread_ns;
      }
    }

    // Convert to vector for sorting
    std::vector<ProcessInfo> processes;
    for (const auto &entry : process_times) {
      ProcessInfo info;
      info.pid = entry.first.first;
      info.uid = entry.first.second;
      info.cpu_time_ns = entry.second;
      info.comm = get_comm_for_pid(info.pid);
      info.username = get_username_for_uid(info.uid);
      processes.push_back(info);
    }

    // Sort by CPU time (descending)
    std::sort(processes.begin(), processes.end(),
              [](const ProcessInfo &a, const ProcessInfo &b) {
                return a.cpu_time_ns > b.cpu_time_ns;
              });

    // Display results
    for (const auto &proc : processes) {
      printf("%-8u %-12s %-6d %-16s %.3f\n",
             proc.uid,
             proc.username.c_str(),
             proc.pid,
             proc.comm.c_str(),
             proc.cpu_time_ns / 1000000.0);
    }

    // Clear entries for next interval
    for (const auto &entry : thread_data) {
      pid_t tid = std::get<0>(entry);
      bpf_map_delete_elem(cpu_map_fd, &tid);
      bpf_map_delete_elem(uid_map_fd, &tid);
    }
  }

  std::cout << "\nDetaching and cleaning up..." << std::endl;
  cputime_bpf__destroy(skel);

  return 0;
}