import subprocess
import time
import json
from collections import defaultdict, deque
import os

# --- Configuration ---
SNAPSHOT_INTERVAL = 2    # seconds
COLLECTION_WINDOW = 20   # seconds
NUM_SNAPSHOTS = int(COLLECTION_WINDOW / SNAPSHOT_INTERVAL)
OUTPUT_FILE = "node_metrics_package.txt"
NODE_ID = "cn-001" 
JIFPY_TO_SECONDS = 0.01 # Standard Linux value for Jiffies to seconds. (May vary)


process_cache = defaultdict(lambda: {
    'uid': 0, 'comm': 'N/A', 'cpu_jiffies_history': deque(maxlen=NUM_SNAPSHOTS),
    'rss_history': deque(maxlen=NUM_SNAPSHOTS), 
    'read_bytes_history': deque(maxlen=NUM_SNAPSHOTS), 
    'write_bytes_history': deque(maxlen=NUM_SNAPSHOTS), 
    'tx_bytes_history': deque(maxlen=NUM_SNAPSHOTS), 
    'rx_bytes_history': deque(maxlen=NUM_SNAPSHOTS),
    'last_jiffies': 0, 'last_time': 0,
})

start_counters = defaultdict(lambda: {
    'cpu_jiffies': 0, 'read_bytes': 0, 'write_bytes': 0, 'tx_bytes': 0, 'rx_bytes': 0
})

def parse_collector_output(output):
    """Parses the shell script output into structured process data."""
    lines = output.strip().split('\n')
    data = defaultdict(dict)
    current_section = None
    
    for line in lines:
        if line.startswith("SNAPSHOT_START"):
            data['timestamp'] = line.split(': ')[1]
        elif line.startswith("PROCESS_METRICS"):
            current_section = "PROCESS"
        elif line.startswith("DISK_IO_METRICS"):
            current_section = "DISK_IO"
        elif line.startswith("NET_IO_METRICS"):
            current_section = "NET_IO"
        elif line.startswith("SNAPSHOT_END"):
            break
        elif current_section:
            parts = line.split('|')
            if current_section == "PROCESS" and len(parts) >= 6:
                pid, uid, comm, jiffies, rss, vsz = map(str.strip, parts)
                data[int(pid)].update({
                    'pid': int(pid), 'uid': int(uid), 'comm': comm, 
                    'jiffies': int(jiffies), 'rss_kb': int(rss)
                })
            elif current_section == "DISK_IO" and len(parts) == 3:
                pid, read, write = map(str.strip, parts)
                data[int(pid)].update({
                    'read_bytes': int(read), 'write_bytes': int(write)
                })
            elif current_section == "NET_IO" and len(parts) == 3:
                pid, tx, rx = map(str.strip, parts)
                data[int(pid)].update({
                    'tx_bytes': int(tx), 'rx_bytes': int(rx)
                })
    return data

def update_cache(snapshot_data, snapshot_time_sec):
    """Updates the process cache with new snapshot data and handles startup/cleanup."""
    global start_counters
    
    current_pids = set(p for p in snapshot_data if isinstance(p, int))

    for pid in current_pids:
        p_data = snapshot_data[pid]
        
        if pid not in start_counters:
            start_counters[pid] = {
                'cpu_jiffies': p_data['jiffies'],
                'read_bytes': p_data.get('read_bytes', 0),
                'write_bytes': p_data.get('write_bytes', 0),
                'tx_bytes': p_data.get('tx_bytes', 0),
                'rx_bytes': p_data.get('rx_bytes', 0)
            }
            process_cache[pid]['last_jiffies'] = p_data['jiffies']
            process_cache[pid]['last_time'] = snapshot_time_sec

        cache = process_cache[pid]
        cache['uid'] = p_data['uid']
        cache['comm'] = p_data['comm']


        time_delta = snapshot_time_sec - cache['last_time']
        if time_delta > 0:
            jiffy_delta = (p_data['jiffies'] - cache['last_jiffies']) * JIFPY_TO_SECONDS
            cpu_percent = (jiffy_delta / time_delta) * 100
            cache['cpu_jiffies_history'].append(cpu_percent)

        cache['rss_history'].append(p_data['rss_kb'] * 1024) # KB to Bytes
        
        cache['read_bytes_history'].append(p_data.get('read_bytes', 0))
        cache['write_bytes_history'].append(p_data.get('write_bytes', 0))
        cache['tx_bytes_history'].append(p_data.get('tx_bytes', 0))
        cache['rx_bytes_history'].append(p_data.get('rx_bytes', 0))

        cache['last_jiffies'] = p_data['jiffies']
        cache['last_time'] = snapshot_time_sec


def aggregate_and_package(window_end_time):
    """Aggregates all data in the cache into the DTO1 format."""
    
    final_process_metrics = []

    final_snapshot_output = subprocess.run(['bash', './collector.sh'], capture_output=True, text=True, check=True).stdout
    final_snapshot_data = parse_collector_output(final_snapshot_output)
    
    for pid, cache in process_cache.items():
        if not cache['cpu_jiffies_history']:
            continue
            
        cpu_avg = sum(cache['cpu_jiffies_history']) / len(cache['cpu_jiffies_history'])
        rss_avg = sum(cache['rss_history']) / len(cache['rss_history'])
        

        start = start_counters[pid]
        final_data = final_snapshot_data.get(pid, {})
        
        read_delta = final_data.get('read_bytes', start['read_bytes']) - start['read_bytes']
        write_delta = final_data.get('write_bytes', start['write_bytes']) - start['write_bytes']
        tx_delta = final_data.get('tx_bytes', start['tx_bytes']) - start['tx_bytes']
        rx_delta = final_data.get('rx_bytes', start['rx_bytes']) - start['rx_bytes']
        
        process_metric = {
            "pid": pid,
            "uid": cache['uid'],
            "command": cache['comm'],
            "application_name": cache['comm'], 
            "cpu_percent_avg": round(cpu_avg, 2),
            "mem_rss_bytes_avg": int(rss_avg),
            "disk_read_bytes_delta": read_delta if read_delta >= 0 else 0,
            "disk_write_bytes_delta": write_delta if write_delta >= 0 else 0,
            "net_bytes_sent_delta": tx_delta if tx_delta >= 0 else 0,
            "net_bytes_recv_delta": rx_delta if rx_delta >= 0 else 0,
            "gpu_metrics": [] 
        }
        final_process_metrics.append(process_metric)

    node_metrics_dto = {
        "node_id": NODE_ID,
        "timestamp_utc": window_end_time,
        "interval_seconds": COLLECTION_WINDOW,
        "process_metrics": final_process_metrics
    }
    
    return node_metrics_dto

def main():
    global process_cache, start_counters
    print(f"Agent starting. Collecting {NUM_SNAPSHOTS} snapshots over {COLLECTION_WINDOW}s.")
    
    for i in range(NUM_SNAPSHOTS + 1): 
        start_time = time.time()
        if i == NUM_SNAPSHOTS:
            print("\n--- Packaging DTO ---")
            break

        print(f"Snapshot {i+1}/{NUM_SNAPSHOTS}...")
        
        try:
            result = subprocess.run(
                ['bash', './collector.sh'], 
                capture_output=True, text=True, check=True
            )
            raw_data = result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error running collector.sh: {e}")
            return
            
        snapshot_data = parse_collector_output(raw_data)
        current_time_sec = int(time.time())
        update_cache(snapshot_data, current_time_sec)
        
        time_to_wait = SNAPSHOT_INTERVAL - (time.time() - start_time)
        if time_to_wait > 0:
            time.sleep(time_to_wait)
            
    window_end_time = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    final_package = aggregate_and_package(window_end_time)
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(final_package, f, indent=4)
        
    print(f"✅ Aggregation complete. DTO written to {OUTPUT_FILE}")
    print(f"Total processes aggregated: {len(final_package['process_metrics'])}")

if __name__ == "__main__":
    main()