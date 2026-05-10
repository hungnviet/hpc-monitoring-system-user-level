# HPC Cluster Monitoring System

A distributed system for collecting, processing, storing, and visualising real-time hardware and process-level metrics from HPC compute nodes.

## Repository Layout

```
.
├── monitor-data-pipeline/          # Data collection and storage pipeline
│   ├── coordinator/                # etcd — central config & service discovery
│   ├── kafka/                      # Kafka message broker (KRaft mode)
│   ├── collect-agent/              # gRPC server + processing pipeline + Kafka publisher
│   ├── compute-node-agent/         # Per-node agent: eBPF + nvidia-smi collectors
│   ├── data-service/
│   │   ├── timescale/              # TimescaleDB — historical aggregated metrics
│   │   ├── influx/                 # InfluxDB — raw real-time metrics
│   │   └── worker/                 # Python workers: Kafka consumer + hourly ETL
│   └── grafana/                    # Grafana dashboards
└── Application/
    └── hpc-admin/                  # Next.js 16 admin web application
```

## System Overview

```
Compute Node Agents  ──gRPC──▶  Collect Agent  ──Kafka──▶  Worker Services
  (eBPF + nvidia-smi)                                    ├──▶ InfluxDB (raw)
         │                                               └──▶ TimescaleDB (hourly)
         │  heartbeat / config
         └──────────────▶  etcd (Coordinator)
                                    │
                             hpc-admin (Next.js)
                                    │
                             Grafana (dashboards)
```

**Data flow summary:**

1. Each **Compute Node Agent** collects per-process CPU, memory, disk, network, and GPU metrics using eBPF and `nvidia-smi`.
2. Metrics are streamed via gRPC to the **Collect Agent**, which validates, enriches, and checks thresholds before publishing JSON messages to **Kafka** (topic: `monitoring_metrics`).
3. **Worker services** consume those messages: `monitor_consumer` writes raw data to **InfluxDB**; `hourly_aggregator` runs hourly ETL from InfluxDB into **TimescaleDB**.
4. **Grafana** visualises the data from InfluxDB in real time.
5. The **hpc-admin** web application provides a full management interface over TimescaleDB and etcd, and embeds Grafana panels.
6. **etcd** acts as the central nervous system: all agents read their configuration from it on startup and watch for live changes without needing a restart.

## Quick Links

| Component | Folder | README |
|---|---|---|
| Full pipeline overview | `monitor-data-pipeline/` | [README](monitor-data-pipeline/README.md) |
| Coordinator (etcd) | `monitor-data-pipeline/coordinator/` | [README](monitor-data-pipeline/coordinator/README.md) |
| Kafka | `monitor-data-pipeline/kafka/` | [README](monitor-data-pipeline/kafka/README.md) |
| Collect Agent | `monitor-data-pipeline/collect-agent/` | [README](monitor-data-pipeline/collect-agent/README.md) |
| Compute Node Agent | `monitor-data-pipeline/compute-node-agent/` | [README](monitor-data-pipeline/compute-node-agent/README.md) |
| Data Services | `monitor-data-pipeline/data-service/` | [README](monitor-data-pipeline/data-service/README.md) |
| hpc-admin | `Application/hpc-admin/` | [README](Application/hpc-admin/README.md) |
| Installation guide | — | [INSTALLATION.md](INSTALLATION.md) |

## Getting Started

See **[INSTALLATION.md](INSTALLATION.md)** for the full step-by-step deployment guide covering prerequisites, deployment order, per-host configuration, and validation checks.
