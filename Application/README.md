# Application

This directory contains the user-facing web application for the HPC cluster monitoring system.

## Contents

| Directory | Description |
|---|---|
| `hpc-admin/` | Next.js 16 admin web application — cluster dashboard, analytics, configuration management |

## hpc-admin

The **hpc-admin** application is built for HPC cluster administrators. It provides:

- **Dashboard** — live cluster overview with Grafana panel embeds and per-node detail views
- **Analytics** — historical resource usage charts per user and application, custom dashboards
- **Configuration** — manage collection settings, pipeline rules, and alert thresholds written back to etcd
- **Governance** — configuration version history, audit logs, and rollout controls
- **Chat** — AI-assisted admin chatbot

See [`hpc-admin/README.md`](hpc-admin/README.md) for setup and run instructions.

## Dependencies (external services)

The application connects to the following services deployed by `monitor-data-pipeline/`:

| Service | Default address | Used for |
|---|---|---|
| TimescaleDB | `localhost:5432` | Historical metrics + admin tables |
| etcd | `localhost:2379` | Node config, heartbeats, live status |
| Grafana | `localhost:3000` | Iframe-embedded panel visualisations |

All connection strings are configured in `hpc-admin/.env.local`. See [INSTALLATION.md](../INSTALLATION.md) for details.
