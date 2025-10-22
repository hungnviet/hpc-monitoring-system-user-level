#!/bin/bash

SNAPSHOT_TIME=$(date +%s%N)

echo "SNAPSHOT_START: $SNAPSHOT_TIME"

echo "PROCESS_METRICS"
# Fix: Renamed UID to P_UID to avoid conflict.
# Fix: Added check for UTIME/STIME to prevent syntax error in $(( ))
ps -eo pid,uid,comm,utime,stime,rss,vsz --no-headers | while read PID P_UID COMM UTIME STIME RSS VSZ; do
    # Check if CPU time fields are numeric before calculating JIFFIES
    if [[ "$UTIME" =~ ^[0-9]+$ ]] && [[ "$STIME" =~ ^[0-9]+$ ]]; then
        TOTAL_JIFFIES=$((UTIME + STIME))
    else
        TOTAL_JIFFIES=0 # Assign 0 if data is non-numeric
    fi
    echo "$PID|$P_UID|$COMM|$TOTAL_JIFFIES|$RSS|$VSZ"
done


# This section REQUIRES root permission (sudo) to read all /proc files
echo "DISK_IO_METRICS"
for pid in /proc/[0-9]*; do
    PID=$(basename $pid)
    if [ -f "$pid/io" ]; then
        IO_DATA=$(awk '
            /read_bytes/ {READ = $2} 
            /write_bytes/ {WRITE = $2} 
            END { print READ "|" WRITE }
        ' "$pid/io" 2>/dev/null) 
        if [ ! -z "$IO_DATA" ]; then
            echo "$PID|$IO_DATA"
        fi
    fi
done

echo "NET_IO_METRICS"
# This section also REQUIRES root permission (sudo)
for pid in /proc/[0-9]*; do
    PID=$(basename $pid)
    if [ -f "$pid/net/dev" ]; then
        RX_BYTES=$(awk 'NR > 2 { sum_rx += $2; sum_tx += $10 } END { print sum_rx }' "$pid/net/dev")
        TX_BYTES=$(awk 'NR > 2 { sum_rx += $2; sum_tx += $10 } END { print sum_tx }' "$pid/net/dev")
        echo "$PID|$TX_BYTES|$RX_BYTES"
    fi
done

echo "SNAPSHOT_END: $SNAPSHOT_TIME"