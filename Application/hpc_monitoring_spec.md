# HPC Monitoring System Specification

## I. Usage Monitoring Module

### 1. Real-Time Monitoring Dashboards

**Refresh Interval:** 5--10 seconds\
**Data Source:** InfluxDB\
**Visualization:** Embedded Grafana Panels

#### Cluster-Level Dashboard

Displays overall system status with: - CPU usage - GPU usage - Memory
consumption - Disk utilization - Network throughput - Node status
(active / idle / down) - Cluster health indicator

Modes: - Current snapshot - Time-range view

Purpose: Provide administrators with a fast overview of cluster workload
and health.

------------------------------------------------------------------------

#### Node-Level Dashboard

Detailed metrics per compute node:

-   CPU utilization + load
-   GPU usage, temperature, power
-   Memory usage + bandwidth
-   Disk throughput + latency

Modes: - Current snapshot - Time-range view

Purpose: Detect node-specific performance issues.

------------------------------------------------------------------------

### 2. Historical Usage Analytics

**Data Source:** TimescaleDB

Purpose: Support auditing, fairness analysis, and capacity planning.

#### User Usage History

Admin selects: - User(s) - Resource type (CPU/GPU/MEM/DISK/NET) - Time
range

System returns: Charts showing historical usage patterns.

------------------------------------------------------------------------

#### Custom Dashboard Builder

Admins can: - Add/remove panels dynamically - Combine multiple users -
Select chart types (line, bar, stacked)

Dashboards can be: - Saved - Loaded - Pinned

------------------------------------------------------------------------

#### Prompt-Based Chart Generator

User enters natural language request.

System: 1. Parses intent 2. Generates query 3. Fetches data 4. Returns
chart config + dataset

------------------------------------------------------------------------

### 3. Chatbot Assistant

Provides: - Dashboard usage guidance - Metric explanations -
Troubleshooting help

------------------------------------------------------------------------

## II. System Configuration Module

### 1. Data Collection Settings

Admins configure: - Collection interval/window per node or group - Node
assignment to collect agents

------------------------------------------------------------------------

### 2. Processing Pipeline Management

Configure preprocessing logic executed at collect agents.

Examples: - Filtering - Aggregation - Derived metrics

------------------------------------------------------------------------

### 3. Threshold & Alert Management

Admins define: - Resource thresholds per node group - Alert severity
levels - Notification rules

------------------------------------------------------------------------

### 4. System Governance

Includes: - Configuration versioning - Audit logs - Live configuration
rollout to nodes

------------------------------------------------------------------------

## System Architecture Context

Pipeline: Compute Node Agents → Collect Agents → Kafka → Storage

Storage Layers: - InfluxDB → real-time metrics - TimescaleDB →
historical analytics

Frontend: - Dashboard UI - Embedded Grafana panels

------------------------------------------------------------------------

## Design Principles

-   Modular architecture
-   Real-time + historical separation
-   Configurable pipelines
-   Extensible visualization
-   Admin-first observability

------------------------------------------------------------------------

## Future Extension Hooks

-   Plugin metric processors
-   Custom virtual sensors
-   Predictive anomaly detection
-   Role-based dashboard views

------------------------------------------------------------------------

**End of Specification**
