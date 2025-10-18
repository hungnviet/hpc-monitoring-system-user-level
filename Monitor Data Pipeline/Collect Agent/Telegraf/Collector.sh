#!/bin/bash
SNAPSHOT_TIME=$(date +%s%N)
echo "SNAPSHOT_START: $SNAPSHOT_TIME"

# 1. Process Metrics (PID, UID, Command, CPU Jiffies, RSS in KB, VmSize in KB)
# We use /proc/self/task/* for threads, but /proc/[pid] for processes.
# Columns: PID | UID | COMM | UTILITY_JIFFIES | RSS_KB | VMSIZE_KB
# Jiffies = utime + stime from /proc/[pid]/stat
echo "PROCESS_METRICS"
ps -eo pid,uid,comm,utime,stime,rss,vsz --no-headers | while read PID UID COMM UTIME STIME RSS VSZ; do
    # Calculate Total Jiffies (UTIME + STIME)
    TOTAL_JIFFIES=$((UTIME + STIME))
    echo "$PID|$UID|$COMM|$TOTAL_JIFFIES|$RSS|$VSZ"
done

# 2. Disk I/O Counters (Accumulative, since boot)
# We use /proc/diskstats for system-wide, but /proc/[pid]/io for per-process.
# Columns: PID | READ_BYTES | WRITE_BYTES
echo "DISK_IO_METRICS"
for pid in /proc/[0-9]*; do
    PID=$(basename $pid)
    # Check if process still exists and has an I/O file
    if [ -f "$pid/io" ]; then
        READ_BYTES=$(awk '/read_bytes/ {print $2}' "$pid/io")
        WRITE_BYTES=$(awk '/write_bytes/ {print $2}' "$pid/io")
        echo "$PID|$READ_BYTES|$WRITE_BYTES"
    fi
done

# 3. Network I/O Counters (Accumulative, since boot)
# Columns: PID | TX_BYTES | RX_BYTES
echo "NET_IO_METRICS"
for pid in /proc/[0-9]*; do
    PID=$(basename $pid)
    # Check if process still exists and has an I/O file
    if [ -f "$pid/net/dev" ]; then
        # Sum all bytes across all interfaces (except loopback 'lo')
        RX_BYTES=$(awk 'NR > 2 { sum_rx += $2; sum_tx += $10 } END { print sum_rx }' "$pid/net/dev")
        TX_BYTES=$(awk 'NR > 2 { sum_rx += $2; sum_tx += $10 } END { print sum_tx }' "$pid/net/dev")
        echo "$PID|$TX_BYTES|$RX_BYTES"
    fi
done

# Footer (optional)
echo "SNAPSHOT_END: $SNAPSHOT_TIME"