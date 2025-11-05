# CPU Time Monitor - eBPF-based Process CPU Usage Tracker

## Overview

This tool monitors per-process CPU time usage in real-time using eBPF (extended Berkeley Packet Filter) technology. It tracks thread-level CPU consumption in the kernel and aggregates the data by process ID (TGID) in user space.

## How It Works

### Architecture

1. **Kernel-space (eBPF)**:
   - Attaches to the `sched/sched_switch` tracepoint
   - Tracks when threads are scheduled on/off CPU
   - Maintains two BPF hash maps:
     - `start_ns`: Records when each thread (TID) was scheduled onto CPU
     - `cpu_total_ns`: Accumulates total on-CPU time per thread

2. **User-space (C++)**:
   - Reads per-thread CPU time from eBPF maps
   - Resolves thread IDs (TID) to process IDs (TGID) via `/proc/<tid>/status`
   - Aggregates thread times by process
   - Displays sorted results (highest CPU usage first)
   - Clears map entries each interval for delta measurements

### Key Features

- **Low overhead**: eBPF runs in kernel, minimal performance impact
- **Real-time tracking**: Reports CPU time at configurable intervals
- **Process-level aggregation**: Sums all thread times for multi-threaded processes
- **Automatic cleanup**: Properly detaches on Ctrl+C

## Sample Output

```
[1761153775] Total On-CPU Time:
UID      USER         PID    COMM             CPU_TIME_MS
1000     nvhung       2704   gnome-shell      18.742
1000     nvhung       33396  code             2.804
1000     nvhung       34519  gnome-terminal-  2.656
0        root         944    containerd       0.378
0        root         1046   rsyslogd         0.258
...
```

**Columns**:
- `UID`: User ID of the process owner
- `USER`: Username (resolved from UID, falls back to numeric UID if user not found)
- `PID`: Process ID (TGID)
- `COMM`: Command name from `/proc/<pid>/comm`
- `CPU_TIME_MS`: **On-CPU time in milliseconds during THIS INTERVAL ONLY** (sum of all threads)

## Requirements

### System Requirements
- **Linux kernel**: 5.8+ with BTF (BPF Type Format) support
- **Architecture**: x86_64 or ARM64 (aarch64)
- **OS**: Rocky Linux 9 / RHEL 9 / CentOS Stream 9 (or Ubuntu/Debian with different packages)

### Software Dependencies
- `clang` / `llvm` (LLVM/Clang compiler)
- `libbpf` (BPF library and headers)
- `elfutils-libelf-devel` (ELF library development files)
- `kernel-devel` (Kernel headers matching your running kernel)
- `bpftool` (BPF inspection tool)
- `gcc` / `g++` (GNU C/C++ compiler)

## Installation Guide

### For Rocky Linux / RHEL / CentOS Stream

#### 1. Verify Kernel BTF Support

```bash
# Check if BTF is available
ls /sys/kernel/btf/vmlinux
```

If the file doesn't exist, you need a newer kernel with CONFIG_DEBUG_INFO_BTF=y.

#### 2. Install System Dependencies

```bash
# Install build tools and kernel headers
sudo dnf install -y clang llvm elfutils-libelf-devel kernel-devel perf elfutils-devel gcc gcc-c++
```

#### 3. Install libbpf from Source

Rocky Linux 9 doesn't include `libbpf-devel` in default repos, so install from source:

```bash
# Clone libbpf repository
cd /tmp
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src

# Build and install
make
sudo make install
sudo make install_headers
sudo ldconfig
```

Verify installation:
```bash
ls -la /usr/lib64/libbpf.so*
# Should show: libbpf.so -> libbpf.so.1 -> libbpf.so.1.x.x
```

#### 4. Build the Program

```bash
cd /path/to/cpu-usage/
make clean
make
```

#### 5. Run the Program

```bash
# Run with 1-second intervals (requires root for eBPF)
sudo ./cputime 1

# Stop with Ctrl+C
```

### For Ubuntu / Debian

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev libelf-dev linux-tools-generic gcc-multilib

# Build and run
make clean
make
sudo ./cputime 1
```

## Usage

```bash
# Default 1-second interval
sudo ./cputime

# Custom interval (5 seconds)
sudo ./cputime 5

# Stop the program
Press Ctrl+C
```

## Troubleshooting

### Common Build Errors

#### 1. `fatal error: 'bpf/bpf_helpers.h' file not found`

**Cause**: libbpf headers not installed

**Fix**:
```bash
cd /tmp/libbpf/src
sudo make install_headers
```

#### 2. `/usr/bin/ld: cannot find -lbpf`

**Cause**: libbpf library not installed or not in library path

**Fix**:
```bash
cd /tmp/libbpf/src
sudo make install
sudo ldconfig

# Verify
ldconfig -p | grep libbpf
```

#### 3. `Error: /sys/kernel/btf/vmlinux not found`

**Cause**: Kernel doesn't have BTF support

**Fix**: Upgrade to kernel 5.8+ with CONFIG_DEBUG_INFO_BTF=y enabled

#### 4. `Failed to load and verify BPF skeleton`

**Cause**: Insufficient permissions or verifier error

**Fix**:
- Run with `sudo`
- Check kernel logs: `sudo dmesg | tail -50`
- Verify kernel version: `uname -r`

#### 5. Makefile spacing errors (`*** multiple target patterns`)

**Cause**: Makefiles require TAB characters, not spaces for recipe indentation

**Fix**:
```bash
sed -i 's/^    /\t/g' Makefile
```

### Runtime Issues

#### High CPU overhead from `/proc` reads

The program reads `/proc/<tid>/status` for each thread to get TGID. For systems with thousands of threads, this can be slow.

**Optimization**: Cache TID→TGID mappings in user space or move aggregation to kernel space.

#### Missing processes in output

**Cause**: Thread exited between map read and `/proc` lookup

**Expected behavior**: This is a race condition inherent to the design. Short-lived threads may be missed.

#### Incorrect CPU times

**Cause**: Currently running threads aren't accounted for until they're scheduled out

**Note**: CPU times show completed timeslices. For currently-running threads, also read `start_ns` and calculate `now - start_ns`.

## Files

- `cputime.bpf.c` - eBPF kernel program
- `cputime.cpp` - User-space C++ program
- `Makefile` - Build configuration
- `vmlinux.h` - Generated kernel type definitions (auto-created)
- `cputime.bpf.o` - Compiled eBPF object (auto-created)
- `cputime.skel.h` - eBPF skeleton header (auto-created)
- `cputime` - Final executable (auto-created)

## Makefile Targets

```bash
make              # Build the program
make check-tools  # Verify all required tools are installed
make install-deps # Install dependencies (Rocky Linux)
make clean        # Remove all generated files
make run          # Build and run with sudo
make help         # Show available targets
```

## Technical Details

### BPF Maps

- **start_ns**: `BPF_MAP_TYPE_HASH`, max 65536 entries
  - Key: Thread ID (pid_t)
  - Value: Timestamp in nanoseconds (u64)

- **cpu_total_ns**: `BPF_MAP_TYPE_HASH`, max 65536 entries
  - Key: Thread ID (pid_t)
  - Value: Accumulated CPU time in nanoseconds (u64)

### Performance Characteristics

- **Overhead**: < 1% CPU on typical workloads
- **Memory**: ~1MB kernel memory for BPF maps (65K entries × 2 maps × 8 bytes)
- **Latency**: Negligible impact on scheduler (inline BPF execution)

## Limitations

1. **Per-interval data**: Map is cleared after each read, showing delta time, not cumulative
2. **Thread overhead**: High thread-count systems may experience `/proc` read overhead
3. **Race conditions**: Threads exiting between map read and TGID lookup are dropped
4. **Kernel dependency**: Requires modern kernel with BTF support

## Future Enhancements
- [ ] Support filtering by process name/PID
- [ ] JSON output format

## License
GPL (required for eBPF programs)

## References

- [libbpf Documentation](https://github.com/libbpf/libbpf)
- [BPF & XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)
- [Linux Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)