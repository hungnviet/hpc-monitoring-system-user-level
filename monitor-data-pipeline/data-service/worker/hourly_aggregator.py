import os
import psycopg2
import schedule
import time
from datetime import datetime
from influxdb_client import InfluxDBClient
from zoneinfo import ZoneInfo

VN_TZ = ZoneInfo("Asia/Ho_Chi_Minh")

# Configuration - read from environment variables
INFLUX_URL = os.getenv('INFLUX_URL', 'http://172.28.10.130:8086')
INFLUX_TOKEN = os.getenv('INFLUX_TOKEN')
INFLUX_ORG = os.getenv('INFLUX_ORG', 'hpcc-org')
INFLUX_BUCKET = os.getenv('INFLUX_BUCKET', 'metrics')

PG_HOST = os.getenv('PG_HOST', '172.28.10.130')
PG_PORT = os.getenv('PG_PORT', '5432')
PG_DB = os.getenv('PG_DB', 'hpc_monitoring')
PG_USER = os.getenv('PG_USER', 'admin')
PG_PASS = os.getenv('PG_PASS')

# Fail fast if critical secrets are missing
_required = {'INFLUX_TOKEN': INFLUX_TOKEN, 'PG_PASS': PG_PASS}
_missing = [k for k, v in _required.items() if not v]
if _missing:
    raise RuntimeError(f"Missing required environment variables: {', '.join(_missing)}")

def get_postgres_connection():
    return psycopg2.connect(host=PG_HOST,
                            port=PG_PORT,
                            database=PG_DB,
                            user=PG_USER,
                            password=PG_PASS)

def run_hourly_etl():
    print(f"[{datetime.now(VN_TZ)}] Starting Hourly Aggregation Pipeline...")
    start_time = "-1h"

    client = InfluxDBClient(url=INFLUX_URL,
                            token=INFLUX_TOKEN,
                            org=INFLUX_ORG,
                            timeout=300000)
    query_api = client.query_api()
    pg_conn = get_postgres_connection()
    cursor = pg_conn.cursor()

    try:
        # 1. Node Status Aggregation
        nodes = {}
        def get_node_obj(nid, btime):
            local_btime = btime.astimezone(VN_TZ)

            if nid not in nodes:
                nodes[nid] = {
                    "bucket_time": local_btime, "node_id": nid, "avg_cpu": 0.0, "max_cpu": 0.0,
                    "avg_mem": 0.0, "max_mem_b": 0, "gpu_util": 0.0, "gpu_temp": 0,
                    "gpu_pow": 0.0, "gpu_cnt": 0, "read": 0, "write": 0, "rx": 0, "tx": 0
                }
            return nodes[nid]
        
        print("Fetching Node metrics...")
        res_n_avg = query_api.query(f"""import "timezone"
                                    option location = timezone.location(name: "Asia/Ho_Chi_Minh")
                                    from(bucket: "{INFLUX_BUCKET}") \
                                    |> range(start: {start_time}) \
                                    |> filter(fn: (r) => r["_measurement"] == "node_status") \
                                    |> filter(fn: (r) => r["_field"] == "cpu_usage_percent" or r["_field"] == "memory_usage_percent") \
                                    |> aggregateWindow(every: 1h, fn: mean, createEmpty: false) \
                                    |> truncateTimeColumn(unit: 1h)
                                    |> pivot(rowKey:["_time", "node_id"], columnKey: ["_field"], valueColumn: "_value")
        """)
        for t in res_n_avg:
            for r in t.records:
                n = get_node_obj(r.values.get("node_id"), r.get_time())
                n["avg_cpu"] = r.values.get("cpu_usage_percent") or 0.0
                n["avg_mem"] = r.values.get("memory_usage_percent") or 0.0

        res_n_max = query_api.query(f"""import "timezone"
                                    option location = timezone.location(name: "Asia/Ho_Chi_Minh")
                                    from(bucket: "{INFLUX_BUCKET}") \
                                    |> range(start: {start_time}) \
                                    |> filter(fn: (r) => r["_measurement"] == "node_status") \
                                    |> filter(fn: (r) => r["_field"] == "cpu_usage_percent" or r["_field"] == "memory_used_bytes") \
                                    |> aggregateWindow(every: 1h, fn: max, createEmpty: false) \
                                    |> truncateTimeColumn(unit: 1h)
                                    |> pivot(rowKey:["_time", "node_id"], columnKey: ["_field"], valueColumn: "_value")
        """)
        for t in res_n_max:
            for r in t.records:
                n = get_node_obj(r.values.get("node_id"), r.get_time())
                n["max_cpu"] = r.values.get("cpu_usage_percent") or 0.0
                n["max_mem_b"] = r.values.get("memory_used_bytes") or 0

        # GPU metrics
        res_gpu = query_api.query(f"""import "timezone"
                                    option location = timezone.location(name: "Asia/Ho_Chi_Minh")
                                    from(bucket: "{INFLUX_BUCKET}") \
                                    |> range(start: {start_time}) \
                                    |> filter(fn: (r) => r["_measurement"] == "gpu_status") \
                                    |> filter(fn: (r) => r["_field"] == "utilization_percent" or r["_field"] == "power_watts" or r["_field"] == "temperature_celsius") \
                                    |> aggregateWindow(every: 1h, fn: mean, createEmpty: false) \
                                    |> truncateTimeColumn(unit: 1h)
                                    |> pivot(rowKey:["_time", "node_id", "gpu_index"], columnKey: ["_field"], valueColumn: "_value")
        """)
        for t in res_gpu:
            for r in t.records:
                n = get_node_obj(r.values.get("node_id"), r.get_time())
                n["gpu_util"] += r.values.get("utilization_percent") or 0.0
                n["gpu_pow"] += r.values.get("power_watts") or 0.0
                n["gpu_cnt"] += 1
                temp = r.values.get("temperature_celsius") or 0
                if temp > n["gpu_temp"]: n["gpu_temp"] = temp

        # Node IO
        res_n_io = query_api.query(f"""import "timezone"
                                    option location = timezone.location(name: "Asia/Ho_Chi_Minh")
                                    from(bucket: "{INFLUX_BUCKET}") \
                                    |> range(start: {start_time}) \
                                    |> filter(fn: (r) => r["_measurement"] == "process_status") \
                                    |> filter(fn: (r) => r["_field"] == "read_bytes" or r["_field"] == "write_bytes" or r["_field"] == "net_rx_bytes" or r["_field"] == "net_tx_bytes") \
                                    |> group(columns: ["node_id", "uid", "comm", "_field"]) \
                                    |> spread() \
                                    |> group(columns: ["node_id", "_field"]) \
                                    |> sum() \
                                    |> pivot(rowKey:["node_id"], columnKey: ["_field"], valueColumn: "_value")
        """)
        for t in res_n_io:
            for r in t.records:
                nid = r.values.get("node_id")
                if nid in nodes:
                    nodes[nid].update({"read": r.values.get("read_bytes", 0),
                                       "write": r.values.get("write_bytes", 0),
                                       "rx": r.values.get("net_rx_bytes", 0),
                                       "tx": r.values.get("net_tx_bytes", 0)})

        # 2. User App Aggregation
        apps_dict = {}
        def get_app_obj(btime, nid, muid, ncomm):
            local_btime = btime.astimezone(VN_TZ)

            key = (local_btime, nid, muid, ncomm)
            if key not in apps_dict:
                apps_dict[key] = {"avg_rss": [], "max_rss": 0, "read": 0, "write": 0, "rx": 0, "tx": 0, "cpu_s": 0.0, "proc_count": 0}
            return apps_dict[key]
        
        print("Fetching User App metrics...")
        # App Spread (CPU Time & IO)
        q_app_spread = query_api.query(f"""import "timezone"
                        option location = timezone.location(name: "Asia/Ho_Chi_Minh")
                        from(bucket: "{INFLUX_BUCKET}") \
                        |> range(start: {start_time}) \
                        |> filter(fn: (r) => r["_measurement"] == "process_status") \
                        |> filter(fn: (r) => r["_field"] == "cpu_ontime_ns" or r["_field"] == "read_bytes" or r["_field"] == "write_bytes" or r["_field"] == "net_rx_bytes" or r["_field"] == "net_tx_bytes") \
                        |> group(columns: ["node_id", "uid", "comm", "_field"]) \
                        |> spread() \
                        |> duplicate(column: "_stop", as: "_time")
                        |> truncateTimeColumn(unit: 1h)
                        |> pivot(rowKey:["_time", "node_id", "uid", "comm"], columnKey: ["_field"], valueColumn: "_value")
        """)
        for t in q_app_spread:
            for r in t.records:
                cpu_s = (r.values.get("cpu_ontime_ns") or 0) / 1e9
                if cpu_s <= 0: continue
                app = get_app_obj(r.get_time(), r.values.get("node_id"), r.values.get("uid", "-1"), r.values.get("comm", "unknown"))
                app["cpu_s"] += cpu_s
                app["read"] += r.values.get("read_bytes") or 0
                app["write"] += r.values.get("write_bytes") or 0
                app["rx"] += r.values.get("net_rx_bytes") or 0
                app["tx"] += r.values.get("net_tx_bytes") or 0

        # App Max/Mean (RAM)
        q_app_ram = query_api.query(f"""import "timezone"
                                    option location = timezone.location(name: "Asia/Ho_Chi_Minh")
                                    from(bucket: "{INFLUX_BUCKET}") \
                                    |> range(start: {start_time}) \
                                    |> filter(fn: (r) => r["_measurement"] == "process_status") \
                                    |> filter(fn: (r) => r["_field"] == "avg_rss_bytes" or r["_field"] == "process_count") \
                                    |> group(columns: ["node_id", "uid", "comm", "_field"]) \
                                    |> aggregateWindow(every: 1h, fn: max, createEmpty: false) \
                                    |> truncateTimeColumn(unit: 1h)
                                    |> pivot(rowKey:["_time", "node_id", "uid", "comm"], columnKey: ["_field"], valueColumn: "_value")
        """)
        for t in q_app_ram:
            for r in t.records:
                app = get_app_obj(r.get_time(), r.values.get("node_id"), r.values.get("uid", "-1"), r.values.get("comm", "unknown"))
                rss = r.values.get("avg_rss_bytes") or 0
                app["avg_rss"].append(rss)
                if rss > app["max_rss"]: app["max_rss"] = rss
                app["proc_count"] = int(r.values.get("process_count") or 0)

        # 3. Database Writing
        print("Committing to TimescaleDB...")
        for nid, d in nodes.items():
            avg_util = d["gpu_util"] / d["gpu_cnt"] if d["gpu_cnt"] > 0 else 0.0
            avg_pow = d["gpu_pow"] / d["gpu_cnt"] if d["gpu_cnt"] > 0 else 0.0
            cursor.execute("""INSERT INTO node_status_hourly \
                           (bucket_time, node_id, avg_cpu_usage_percent, max_cpu_usage_percent, \
                           avg_mem_usage_percent, max_mem_used_bytes, avg_gpu_utilization, \
                           max_gpu_temperature, total_gpu_power_watts, total_disk_read_bytes, \
                           total_disk_write_bytes, total_net_rx_bytes, total_net_tx_bytes, is_active) \
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE) \
                           ON CONFLICT DO NOTHING""", (d["bucket_time"], d["node_id"], d["avg_cpu"], d["max_cpu"], d["avg_mem"], d["max_mem_b"], avg_util, d["gpu_temp"], avg_pow, d["read"], d["write"], d["rx"], d["tx"]))
        
        for key, d in apps_dict.items():
            b_time, nid, uid, comm = key
            avg_rss = sum(d["avg_rss"])/len(d["avg_rss"]) if d["avg_rss"] else 0
            cursor.execute("""INSERT INTO user_app_hourly \
                           (bucket_time, node_id, uid, comm, total_cpu_time_seconds, avg_rss_memory_bytes, \
                           max_rss_memory_bytes, total_read_bytes, total_write_bytes, total_net_rx_bytes, \
                           total_net_tx_bytes, process_count) \
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) \
                           ON CONFLICT DO NOTHING""", (b_time, nid, int(uid), comm, d["cpu_s"], avg_rss, d["max_rss"], d["read"], d["write"], d["rx"], d["tx"], d["proc_count"]))

        pg_conn.commit()
        print(f"Successfully aggregated {len(nodes)} nodes and {len(apps_dict)} user apps.")
    except Exception as e:
        print(f"Error during pipeline: {e}")
        pg_conn.rollback()
    finally:
        cursor.close()
        pg_conn.close()

schedule.every().hour.at(":05").do(run_hourly_etl)

if __name__ == "__main__":
    print("Full Aggregator Service Started...")
    run_hourly_etl()
    while True:
        schedule.run_pending()
        time.sleep(1)