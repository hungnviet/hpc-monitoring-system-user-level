CREATE TABLE IF NOT EXISTS node_status_hourly (
    bucket_time TIMESTAMPTZ NOT NULL,
    node_id VARCHAR(255) NOT NULL,
    avg_cpu_usage_percent DOUBLE PRECISION,
    max_cpu_usage_percent DOUBLE PRECISION,
    avg_mem_usage_percent DOUBLE PRECISION,
    max_mem_used_bytes BIGINT,
    avg_gpu_utilization DOUBLE PRECISION,
    max_gpu_temperature DOUBLE PRECISION,
    total_gpu_power_watts DOUBLE PRECISION,
    total_disk_read_bytes BIGINT,
    total_disk_write_bytes BIGINT,
    total_net_rx_bytes BIGINT,
    total_net_tx_bytes BIGINT,
    is_active BOOLEAN,
    UNIQUE (bucket_time, node_id)
);
SELECT create_hypertable('node_status_hourly', 'bucket_time', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS user_app_hourly (
    bucket_time TIMESTAMPTZ NOT NULL,
    node_id VARCHAR(255) NOT NULL,
    uid INT NOT NULL,
    comm VARCHAR(255) NOT NULL,
    total_cpu_time_seconds DOUBLE PRECISION,
    avg_rss_memory_bytes BIGINT,
    max_rss_memory_bytes BIGINT,
    total_read_bytes BIGINT,
    total_write_bytes BIGINT,
    total_net_rx_bytes BIGINT,
    total_net_tx_bytes BIGINT,
    process_count INT,
    UNIQUE (bucket_time, node_id, uid, comm)
);
SELECT create_hypertable('user_app_hourly', 'bucket_time', if_not_exists => TRUE);