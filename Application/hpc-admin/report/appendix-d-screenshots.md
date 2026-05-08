# Appendix D — Screenshots

> Placeholders. Capture each page at 1440×900 in dark mode after logging in with seeded data, export as PNG, and replace the placeholder path below. File names are suggested so that a build script could inline them automatically.

The required minimum set is one screenshot per page listed in [Chapter 2 §2.5](02-analysis.md#25-use-case-catalogue).

## Authentication

| Page | File | Notes |
|---|---|---|
| Login | `screenshots/login.png` | Empty form + inline error state on wrong credentials. |

## Dashboard

| Page | File | Notes |
|---|---|---|
| Cluster dashboard | `screenshots/dashboard.png` | Show node counts, Grafana CPU / memory / GPU panels, time-range selector. |
| Node list | `screenshots/nodes.png` | Sortable table with merged DB + etcd + latest-metrics data. |
| Node detail | `screenshots/node-detail.png` | Per-node Grafana panels, Recharts time-series, start/stop button. |

## Analytics

| Page | File | Notes |
|---|---|---|
| Analytics (summary) | `screenshots/analytics-summary.png` | Users table sorted by CPU seconds. |
| Analytics (timeseries) | `screenshots/analytics-timeseries.png` | Single-user line chart. |
| Analytics (apps breakdown) | `screenshots/analytics-apps.png` | Per-user per-app table. |
| AI Chart Generator | `screenshots/ai-chart.png` | Prompt + returned Grafana panel embed. |
| Custom dashboards (current mock) | `screenshots/analytics-custom.png` | Flagged in Chapter 6 as still mock-driven. |

## Configuration

| Page | File | Notes |
|---|---|---|
| Collection | `screenshots/config-collection.png` | Per-node interval, window, collect-agent. |
| Pipeline | `screenshots/config-pipeline.png` | Rule list + Push to etcd button. |
| Alerts | `screenshots/config-alerts.png` | Alert rule list + Push to etcd button. |
| Governance | `screenshots/config-governance.png` | Version history + audit log. |

## Auxiliary

| Page | File | Notes |
|---|---|---|
| Chat | `screenshots/chat.png` | Stub page; flagged in Chapter 6. |
| Notifications panel | `screenshots/notifications.png` | Invoked from the header. |

## Error states

Include at least one screenshot of each degraded path (used in Chapter 6 §6.1 limitations discussion):

| Condition | File |
|---|---|
| etcd unreachable — `/dashboard` with warning banner | `screenshots/error-etcd-down.png` |
| AI microservice unreachable — `/analytics/ai-chart` inline error | `screenshots/error-ai-down.png` |
| Grafana iframe fails to load — empty panel | `screenshots/error-grafana-blocked.png` |
