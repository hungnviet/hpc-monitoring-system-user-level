CREATE TABLE IF NOT EXISTS node_status_hourly (
    bucket_time TIMESTAMPTZ NOT NULL,
    node_id TEXT NOT NULL,
    avg_cpu_usage_percent DOUBLE PRECISION,
    max_cpu_usage_percent DOUBLE PRECISION,
    avg_mem_usage_percent DOUBLE PRECISION,
    max_mem_used_bytes BIGINT,
    avg_gpu_utilization DOUBLE PRECISION,
    max_gpu_temperature INT,
    total_gpu_power_watts DOUBLE PRECISION,
    total_disk_read_bytes BIGINT,
    total_disk_write_bytes BIGINT,
    total_net_rx_bytes BIGINT,
    total_net_tx_bytes BIGINT,
    is_active BOOLEAN DEFAULT TRUE
);
SELECT create_hypertable('node_status_hourly', 'bucket_time', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS user_app_hourly (
    bucket_time TIMESTAMPTZ NOT NULL,
    node_id TEXT NOT NULL,
    uid INT NOT NULL,
    comm TEXT NOT NULL,
    total_cpu_time_seconds DOUBLE PRECISION,
    avg_rss_memory_bytes BIGINT,
    max_rss_memory_bytes BIGINT,
    max_gpu_memory_mib INT,
    total_read_bytes BIGINT,
    total_write_bytes BIGINT,
    total_net_rx_bytes BIGINT,
    total_net_tx_bytes BIGINT,
    process_count INT
);
SELECT create_hypertable('user_app_hourly', 'bucket_time', if_not_exists => TRUE);
root@hpcc:/opt/timescale# cat 
create_agg_tables.sql  docker-compose.yml     schema.sql             
root@hpcc:/opt/timescale# cat schema.sql 
CREATE TABLE IF NOT EXISTS nodes (
  id		TEXT PRIMARY KEY,
  name		TEXT NOT NULL,
  ip		TEXT NOT NULL,
  group_name	TEXT NOT NULL,
  collect_agent TEXT NOT NULL,
  created_at	TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS hpc_users (
  uid		INT PRIMARY KEY,
  username	TEXT NOT NULL UNIQUE,
  email		TEXT,
  group_name	TEXT
);

CREATE TABLE IF NOT EXISTS collection_settings (
  node_id		TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
  interval_seconds	INT NOT NULL DEFAULT 10,
  window_seconds	INT NOT NULL DEFAULT 60,
  collect_agent		TEXT NOT NULL,
  updated_at		TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pipeline_rules (
  id		TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name		TEXT NOT NULL,
  type		TEXT NOT NULL CHECK (type IN ('filter', 'aggregate', 'derive')),
  resource	TEXT NOT NULL CHECK (resource IN ('cpu', 'gpu', 'mem', 'disk', 'net')),
  condition	TEXT NOT NULL,
  enabled	BOOLEAN NOT NULL DEFAULT TRUE,
  created_at	TIMESTAMPTZ DEFAULT NOW(),
  updated_at	TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alert_rules (
  id		TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name		TEXT NOT NULL,
  node_group	TEXT NOT NULL,
  resource	TEXT NOT NULL CHECK (resource IN ('cpu', 'gpu', 'mem', 'disk', 'net')),
  operator	TEXT NOT NULL CHECK (operator IN ('>', '<', '>=', '<=')),
  threshold	DOUBLE PRECISION NOT NULL,
  severity	TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
  enabled	BOOLEAN NOT NULL DEFAULT TRUE,
  created_at	TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notifications (
  id		TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  rule_id	TEXT REFERENCES alert_rules(id) ON DELETE SET NULL,
  severity	TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
  message	TEXT NOT NULL,
  node_id	TEXT REFERENCES nodes(id) ON DELETE SET NULL,
  acknowledged	BOOLEAN NOT NULL DEFAULT FALSE,
  created_at	TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS config_versions (
  id			TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  version		TEXT NOT NULL,
  author		TEXT NOT NULL DEFAULT 'admin',
  description		TEXT,
  config_snapshot	JSONB,
  active		BOOLEAN NOT NULL DEFAULT FALSE,
  created_at		TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id 		TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  actor		TEXT NOT NULL DEFAULT 'admin',
  action	TEXT NOT NULL CHECK (action IN ('CREATE', 'UPDATE', 'DELETE', 'ROLLOUT', 'LOGIN')),
  target	TEXT NOT NULL,
  detail	TEXT,
  created_at	TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS custom_dashboards (
  id		TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  title		TEXT NOT NULL,
  user_uids	INT[],
  resource	TEXT NOT NULL CHECK (resource IN ('cpu', 'gpu', 'mem', 'disk', 'net')),
  chart_type	TEXT NOT NULL CHECK (chart_type IN ('line', 'bar', 'stacked')),
  pinned	BOOLEAN NOT NULL DEFAULT FALSE,
  created_at	TIMESTAMPTZ DEFAULT NOW()
);