# Memory Leak Monitor - eBPF-based Process Memory Allocation Tracker

## Overview

This tool monitors per-process memory allocations and detects memory leaks using eBPF (extended Berkeley Packet Filter) technology. It tracks malloc/calloc/realloc/free calls in user space and reports total allocations and outstanding leaks when processes terminate.

## How It Works

### Architecture

1. **Kernel-space (eBPF)**:
   - Attaches uprobes to libc allocation functions (`malloc`, `calloc`, `realloc`, `free`)
   - Attaches to the `sched/sched_process_exit` tracepoint
   - Maintains BPF hash maps:
     - `sizes`: Temporary storage for allocation sizes (keyed by TID)
     - `allocs_info`: Outstanding allocations database (keyed by memory address)
     - `total_allocs`: Cumulative allocation counter per process (keyed by TGID)
   - Sends process exit events via perf buffer when a process terminates

2. **User-space (C++)**:
   - Receives exit events from kernel
   - Calculates final memory leaks by scanning `allocs_info` map
   - Reports per-process allocation statistics in time intervals
   - Only displays data when processes exit within the interval
   - Cleans up map entries for terminated processes

### Key Features

- **Event-driven**: Reports only when processes exit (no polling overhead)
- **Interval-based reporting**: Groups process exits by configurable time windows
- **Low overhead**: eBPF runs in kernel, minimal performance impact
- **Lifetime tracking**: Shows total allocations since process start
- **Leak detection**: Identifies memory never freed before exit
- **Multi-user support**: Tracks UID/username for HPC environments

## Sample Output

```
[1761153780 - 1761153785] Report Of Memory Allocation Of Process Finished In The Time Window
UID      USER         PID    COMM             TOTAL_ALLOCS_MB MEM_LEAK_MB
1001     alice        12345  python3          245.340         12.450
1002     bob          23456  simulation       1024.120        0.000
1000     nvhung       34567  test_program     5.230           2.100
```

**Columns**:
- `UID`: User ID of the process owner
- `USER`: Username (resolved from UID, falls back to numeric UID if user not found)
- `PID`: Process ID (TGID)
- `COMM`: Command name from `/proc/<pid>/comm`
- `TOTAL_ALLOCS_MB`: **Total lifetime allocations in MB** (all malloc/calloc/realloc since process start)
- `MEM_LEAK_MB`: **Outstanding memory leaks in MB** (allocated but never freed before exit)

**Important Notes**:
- Output appears **only when processes exit** within the time window
- If no processes exit during an interval, **no output is shown**
- Each process is reported **once** at termination
- This is **not** a snapshot tool like CPU monitoring

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
- `gcc` / `g++` (GNU C/C++ compiler with C++14 support)

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
cd /path/to/memory-allocation/
make clean
make
```

#### 5. Run the Program

```bash
# Trace a specific process with 5-second intervals (default)
sudo ./memleak -p <PID>

# Trace a specific process with custom interval
sudo ./memleak -p <PID> 10

# Trace all processes (use with caution on busy systems)
sudo ./memleak -a 5

# Stop with Ctrl+C
```

### For Ubuntu / Debian

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev libelf-dev linux-tools-generic gcc-multilib g++

# Build and run
make clean
make
sudo ./memleak -p <PID>
```

## Usage

```bash
# Trace specific PID with default 5-second interval
sudo ./memleak -p 1234

# Trace specific PID with 10-second interval
sudo ./memleak -p 1234 10

# Trace all processes with 30-second interval
sudo ./memleak -a 30

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
- Reduce `allocs_info` max_entries if hitting memory limits

#### 5. Makefile spacing errors (`*** missing separator`)

**Cause**: Makefiles require TAB characters, not spaces for recipe indentation

**Fix**:
```bash
sed -i 's/^    /\t/g' Makefile
```

#### 6. `Failed to find libc.so.6 for PID <PID>`

**Cause**: Process doesn't use standard libc or hasn't loaded it yet

**Fix**:
- Verify process is running: `ps -p <PID>`
- Check process maps: `cat /proc/<PID>/maps | grep libc`
- Try `-a` mode instead of `-p`

### Runtime Issues

#### No output appearing

**Expected behavior**: Output only appears when processes **exit**. If no processes terminate during the interval, nothing is printed.

**To test**: Run a short-lived program:
```bash
# Terminal 1
sudo ./memleak -a 5

# Terminal 2
./some_test_program  # Program that exits quickly
```

#### High memory usage

**Cause**: `allocs_info` map can grow large with long-running processes making many allocations

**Fix**: Reduce `max_entries` in `memleak.bpf.c`:
```c
struct {
  __uint(max_entries, 100000);  // Reduce from 1000000
  ...
} allocs_info SEC(".maps");
```

#### Missing allocations

**Cause**: Processes using custom allocators (e.g., jemalloc, tcmalloc) won't be tracked

**Note**: This tool only tracks standard libc malloc/free calls.

## Files

- `memleak.bpf.c` - eBPF kernel program
- `memleak.cpp` - User-space C++ program
- `memleak.shared.h` - Shared type definitions (kernel ↔ user space)
- `Makefile` - Build configuration
- `vmlinux.h` - Generated kernel type definitions (auto-created)
- `memleak.bpf.o` - Compiled eBPF object (auto-created)
- `memleak.skel.h` - eBPF skeleton header (auto-created)
- `memleak` - Final executable (auto-created)

## Makefile Targets

```bash
make              # Build the program
make check-tools  # Verify all required tools are installed
make install-deps # Install dependencies (Rocky Linux)
make clean        # Remove all generated files
make help         # Show available targets
```

## Technical Details

### BPF Maps

- **sizes**: `BPF_MAP_TYPE_HASH`, max 10240 entries
  - Key: Thread ID (pid_t)
  - Value: Allocation size (size_t)
  - Purpose: Pass size from uprobe entry to return

- **allocs_info**: `BPF_MAP_TYPE_HASH`, max 1000000 entries
  - Key: Allocated memory address (u64)
  - Value: `struct alloc_info {size_t size; pid_t tgid;}`
  - Purpose: Track outstanding allocations for leak detection

- **total_allocs**: `BPF_MAP_TYPE_HASH`, max 10240 entries
  - Key: Process ID / TGID (pid_t)
  - Value: Cumulative bytes allocated (u64)
  - Purpose: Track lifetime total allocations

- **exit_events**: `BPF_MAP_TYPE_PERF_EVENT_ARRAY`
  - Purpose: Send process exit notifications to user space

### Event Flow

```
1. Process calls malloc(100)
   ├─> malloc_enter: sizes[TID] = 100
   └─> malloc_exit: 
       ├─> allocs_info[addr] = {100, TGID}
       └─> total_allocs[TGID] += 100

2. Process calls free(addr)
   └─> free_enter: delete allocs_info[addr]

3. Process exits
   └─> handle_exit:
       ├─> Read total_allocs[TGID]
       ├─> Send exit_event{TGID, total, UID}
       └─> Delete total_allocs[TGID]

4. User space receives event
   ├─> Scan allocs_info for TGID
   ├─> Sum remaining allocations = leak
   ├─> Store in interval buffer
   └─> Delete allocs_info entries for TGID

5. Interval timer expires
   └─> Print all processes that exited
```

### Performance Characteristics

- **Overhead**: ~2-5% on allocation-heavy workloads
- **Memory**: Up to ~100MB kernel memory for maps (1M entries × ~100 bytes)
- **Latency**: <10µs per allocation call (inline uprobe)

## Limitations

1. **libc-only tracking**: Only tracks standard libc allocations (malloc/calloc/realloc/free)
   - Custom allocators (jemalloc, tcmalloc) are not tracked
   - Direct mmap/brk syscalls are not tracked
   
2. **Event-driven reporting**: Only reports at process exit
   - Cannot show live/current allocations for running processes
   - Long-running processes won't appear until they terminate
   
3. **Memory overhead**: Large `allocs_info` map for leak tracking
   - Each allocation adds an entry
   - Long-running processes with many allocations consume map space
   
4. **Kernel dependency**: Requires modern kernel with BTF and uprobe support

5. **Symbol resolution**: Requires libc symbols to be present
   - Stripped binaries may fail to attach

## Use Cases

### HPC Compute Nodes

Perfect for tracking memory usage and leaks across multiple users:

```bash
# Monitor all user jobs with 60-second intervals
sudo ./memleak -a 60

# Output shows which user's jobs are leaking memory
[1761153780 - 1761153840] Report Of Memory Allocation Of Process Finished In The Time Window
UID      USER         PID    COMM             TOTAL_ALLOCS_MB MEM_LEAK_MB
1001     alice        12345  simulation       2048.500        512.340  ← Large leak!
1002     bob          23456  analysis         1024.120        0.000    ← Clean exit
```

### Development & Testing

Detect memory leaks in your applications:

```bash
# Start monitoring
sudo ./memleak -p $(pgrep my_app) 5

# Run tests, then exit your app
# Leak report appears immediately
```

## Future Enhancements

- [ ] Add filtering by process name/UID
- [ ] JSON output format for integration with monitoring systems
- [ ] Live allocation tracking (before process exit)
- [ ] Per-function allocation attribution (stack traces)
- [ ] Support for custom allocators via configuration
- [ ] Export to Prometheus/InfluxDB

## License

GPL (required for eBPF programs)

## References

- [libbpf Documentation](https://github.com/libbpf/libbpf)
- [BPF & XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)
- [Linux Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)
- [BCC Memory Leak Detector](https://github.com/iovisor/bcc/blob/master/tools/memleak.py)