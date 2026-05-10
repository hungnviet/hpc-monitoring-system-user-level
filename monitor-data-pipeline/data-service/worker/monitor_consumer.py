import json
import os
from kafka import KafkaConsumer
import time
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# Configuration - read from environment variables
KAFKA_BOOTSTRAP_SERVERS = os.getenv('KAFKA_BOOTSTRAP_SERVERS', '172.28.10.129:9092').split(',')
KAFKA_TOPIC = os.getenv('KAFKA_TOPIC', 'monitoring_metrics')
KAFKA_CONSUMER_GROUP = os.getenv('KAFKA_CONSUMER_GROUP', 'monitor3-a5_group')

INFLUX_URL = os.getenv('INFLUX_URL', 'http://172.28.10.130:8086')
INFLUX_TOKEN = os.getenv('INFLUX_TOKEN')
INFLUX_ORG = os.getenv('INFLUX_ORG', 'hpcc-org')
INFLUX_BUCKET = os.getenv('INFLUX_BUCKET', 'metrics')

# Fail fast if critical secrets are missing
if not INFLUX_TOKEN:
    raise RuntimeError("INFLUX_TOKEN environment variable is required")

COMM_PREFIXES = ["StreamT", "IPC", "FSBroker", "gvfsd", "gsd", "kworker", "glfs", "gnome", "ibus", "ksoftirqd", "swapper"]

def safe_int(val, default=0):
    if val is None: return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default

def safe_float(val, default=0.0):
    if val is None: return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default

def map_uid(uid):
    uid_val = safe_int(uid, -1)
    if uid_val == 0: return 0
    elif 0 < uid_val < 1000: return 1
    return uid_val

def normalize_comm(comm):
    if not comm: return "unknown"
    for prefix in COMM_PREFIXES:
        if comm.startswith(prefix): return prefix
    return comm

# Setup InfluxDB client
client = InfluxDBClient(url=INFLUX_URL,
                        token=INFLUX_TOKEN,
                        org=INFLUX_ORG)
write_api = client.write_api(write_options=SYNCHRONOUS)

# Setup Kafka consumer
consumer = KafkaConsumer(
    KAFKA_TOPIC,
    bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
    group_id=KAFKA_CONSUMER_GROUP,
    auto_offset_reset='earliest',
    value_deserializer=lambda x: json.loads(x.decode('utf-8')),
    api_version=(3, 6, 0)
)

print("Listening from Kafka and writing to InfluxDB...")

for message in consumer:
    try:
        data = message.value
        node_id = data.get('node_id', 'unknown_node')

        current_timestamp_seconds = int(time.time())
        points = []

        # In case system_metrics is null
        sys_metrics = data.get('system_metrics') or {}

        # 1. Create point: NODE_STATUS
        p_node = Point("node_status") \
            .tag("node_id", node_id) \
            .tag("collect_agent_id", str(data.get('collect_agent_id') or 'unknown')) \
            .tag("metadata.collect_agent_version", str(data.get('metadata', {}).get('collect_agent_version') or 'unknown')) \
            .field("collection_window_seconds", safe_float(data.get('collection_window_seconds'))) \
            .field("received_timestamp", safe_int(data.get('received_timestamp'))) \
            .field("cpu_usage_percent", safe_float(sys_metrics.get('cpu_usage_percent'))) \
            .field("memory_usage_percent", safe_float(sys_metrics.get('memory_usage_percent'))) \
            .field("memory_used_bytes", safe_int(sys_metrics.get('memory_used_bytes'))) \
            .field("memory_total_bytes", safe_int(sys_metrics.get('memory_total_bytes'))) \
            .time(current_timestamp_seconds, WritePrecision.S)
        points.append(p_node)

        # 2. Create points: GPU_STATUS
        gpus = sys_metrics.get('gpus') or []
        for gpu in gpus:
            p_gpu = Point("gpu_status") \
                .tag("node_id", node_id) \
                .tag("gpu_index", str(gpu.get('gpu_index', '0'))) \
                .tag("gpu_name", str(gpu.get('gpu_name') or 'unknown')) \
                .field("utilization_percent", safe_float(gpu.get('utilization_percent'))) \
                .field("temperature_celsius", safe_float(gpu.get('temperature_celsius'))) \
                .field("power_watts", safe_float(gpu.get('power_watts'))) \
                .field("power_limit_watts", safe_float(gpu.get('power_limit_watts'))) \
                .field("memory_used_mib", safe_int(gpu.get('memory_used_mib'))) \
                .field("memory_total_mib", safe_int(gpu.get('memory_total_mib'))) \
                .time(current_timestamp_seconds, WritePrecision.S)
            points.append(p_gpu)

        # 3. Create points: PROCESS_STATUS
        processes = data.get('processes') or []
        grouped_procs = {}

        for proc in processes:
            uid_mapped = str(map_uid(proc.get('uid')))
            comm_norm = normalize_comm(proc.get('comm', 'unknown'))

            key = (uid_mapped, comm_norm)
            if key not in grouped_procs:
                grouped_procs[key] = {
                    'cpu_ontime_ns': 0, 'read_bytes': 0, 'write_bytes': 0,
                    'net_rx_bytes': 0, 'net_tx_bytes': 0, 'gpu_used_memory_mib': 0,
                    'avg_rss_bytes': 0, 'process_count': 0
                }

            g = grouped_procs[key]
            g['cpu_ontime_ns'] += safe_int(proc.get('cpu_ontime_ns'))
            g['read_bytes'] += safe_int(proc.get('read_bytes'))
            g['write_bytes'] += safe_int(proc.get('write_bytes'))
            g['net_rx_bytes'] += safe_int(proc.get('net_rx_bytes'))
            g['net_tx_bytes'] += safe_int(proc.get('net_tx_bytes'))
            g['gpu_used_memory_mib'] += safe_int(proc.get('gpu_used_memory_mib'))
            g['avg_rss_bytes'] += safe_int(proc.get('avg_rss_bytes'))
            g['process_count'] += 1
        
        for (uid, comm), metrics in grouped_procs.items():
            p_proc = Point("process_status") \
                .tag("node_id", node_id) \
                .tag("comm", comm) \
                .tag("uid", uid) \
                .field("cpu_ontime_ns", metrics['cpu_ontime_ns']) \
                .field("read_bytes", metrics['read_bytes']) \
                .field("write_bytes", metrics['write_bytes']) \
                .field("net_rx_bytes", metrics['net_rx_bytes']) \
                .field("net_tx_bytes", metrics['net_tx_bytes']) \
                .field("gpu_used_memory_mib", metrics['gpu_used_memory_mib']) \
                .field("avg_rss_bytes", metrics['avg_rss_bytes']) \
                .field("process_count", metrics['process_count']) \
                .time(current_timestamp_seconds, WritePrecision.S)
            points.append(p_proc)

        # Batch write to InfluxDB
        if points:
            write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=points)
            print(f"Wrote {len(points)} points for node_id={node_id} to InfluxDB")

    except Exception as e:
        print(f"Error processing message: {e}")
