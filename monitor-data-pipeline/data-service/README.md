# Data Service

This directory contains the storage and processing layer that sits downstream of Kafka. It is composed of three sub-services, each with its own `docker-compose.yml` and `.env`.

## Sub-services

| Directory | Container name | Description |
|---|---|---|
| `timescale/` | `hpc_timescaledb` | TimescaleDB — hourly-aggregated metrics and admin tables |
| `influx/` | `hpc_influxdb` | InfluxDB 2.7 — raw real-time metric time series |
| `worker/` | `hpc_metrics_consumer`, `hpc_hourly_aggregator` | Python workers: consume Kafka → write InfluxDB, aggregate InfluxDB → TimescaleDB |

## Data Flow

```
Kafka (topic: monitoring_metrics)
         │
         ▼
  [hpc_metrics_consumer]          monitor_consumer.py
         │  writes raw points
         ▼
     InfluxDB                     measurement: node_status, process_metrics
         │
         │  hourly Flux queries
         ▼
  [hpc_hourly_aggregator]         hourly_aggregator.py
         │  UPSERT
         ▼
   TimescaleDB                    tables: node_status_hourly, user_app_hourly
```

## Deployment Order

1. Start **TimescaleDB** (`timescale/`) — schema is applied automatically on first start.
2. Start **InfluxDB** (`influx/`) — initialised from env vars on first start.
3. Start **Worker services** (`worker/`) — both databases must be ready before workers start.

Each sub-service has its own README with detailed configuration and run commands:

- [timescale/README.md](timescale/README.md)
- [influx/README.md](influx/README.md)
- [worker/README.md](worker/README.md)

All three `docker-compose.yml` files attach to the same Docker network named `hpc_network`. If your databases and workers run on different machines, set `network_mode: host` or update the service hostnames in each `.env`.
