# Appendix A — API endpoint catalogue

Every route handler under [src/app/api](../src/app/api) as of the submission of this report.

## Authentication

| Method | Path | Source | Purpose |
|---|---|---|---|
| `GET`, `POST` | `/api/auth/[...nextauth]` | [route.ts](../src/app/api/auth/[...nextauth]/route.ts) | Auth.js v5 handlers. |

## Nodes (TimescaleDB-backed registry)

| Method | Path | Source | Purpose |
|---|---|---|---|
| `GET` | `/api/nodes` | [route.ts](../src/app/api/nodes/route.ts) | List nodes ordered by name. |
| `POST` | `/api/nodes` | same | Insert `{id, name, ip, group_name, collect_agent}`. |
| `GET` | `/api/nodes/[nodeId]` | [route.ts](../src/app/api/nodes/[nodeId]/route.ts) | Single node by id. |
| `PUT` | `/api/nodes/[nodeId]` | same | Update node row. |
| `DELETE` | `/api/nodes/[nodeId]` | same | Delete node row. |
| `GET` | `/api/nodes/[nodeId]/hourly?range=24h\|48h\|7d\|30d` | [route.ts](../src/app/api/nodes/[nodeId]/hourly/route.ts) | Time-series from `node_status_hourly`. |
| `GET` | `/api/nodes/metrics/latest` | [route.ts](../src/app/api/nodes/metrics/latest/route.ts) | Latest hourly bucket per node. |

## etcd — compute-node configuration + live status

| Method | Path | Source | Purpose |
|---|---|---|---|
| `GET` | `/api/etcd/nodes` | [route.ts](../src/app/api/etcd/nodes/route.ts) | List compute-node configs with derived `running`/`stopped`. |
| `POST` | `/api/etcd/nodes` | same | Create `{nodeId, target_collect_agent, window?, heartbeat_interval?}` keys. |
| `GET` | `/api/etcd/nodes/[nodeId]` | [route.ts](../src/app/api/etcd/nodes/[nodeId]/route.ts) | Read all fields for one node. |
| `PUT` | `/api/etcd/nodes/[nodeId]` | same | Update `target_collect_agent`, `window`, `heartbeat_interval`. |
| `DELETE` | `/api/etcd/nodes/[nodeId]` | same | Remove all keys under the node prefix. |
| `GET` | `/api/etcd/nodes/[nodeId]/status` | [route.ts](../src/app/api/etcd/nodes/[nodeId]/status/route.ts) | Read `status` key. |
| `PUT` | `/api/etcd/nodes/[nodeId]/status` | same | Set `running` or `stopped`. |

## etcd — collect-agent configuration

| Method | Path | Source | Purpose |
|---|---|---|---|
| `GET` | `/api/etcd/agents` | [route.ts](../src/app/api/etcd/agents/route.ts) | List collect agents. |
| `POST` | `/api/etcd/agents` | same | Create agent with defaults for `kafka_brokers`, `kafka_topic`, `grpc_port`, `threshold_rules`. |
| `GET` | `/api/etcd/agents/[agentId]` | [route.ts](../src/app/api/etcd/agents/[agentId]/route.ts) | Full agent config with JSON parsing. |
| `PUT` | `/api/etcd/agents/[agentId]` | same | Update brokers, topic, port. |
| `DELETE` | `/api/etcd/agents/[agentId]` | same | Remove agent prefix. |
| `GET` | `/api/etcd/agents/[agentId]/threshold-rules` | [route.ts](../src/app/api/etcd/agents/[agentId]/threshold-rules/route.ts) | Read `threshold_rules` JSON. |
| `PUT` | `/api/etcd/agents/[agentId]/threshold-rules` | same | Replace full `threshold_rules` object. |

## Analytics

| Method | Path | Source | Purpose |
|---|---|---|---|
| `GET` | `/api/analytics/user-usage?mode=summary\|timeseries\|apps\|app-timeseries&uid=&resource=&from=&to=` | [route.ts](../src/app/api/analytics/user-usage/route.ts) | Four analytic modes over `user_app_hourly`. |
| `GET` | `/api/analytics/cluster-stats?range=1h\|6h\|24h` | [route.ts](../src/app/api/analytics/cluster-stats/route.ts) | Cluster aggregates from `node_status_hourly`. |
| `POST` | `/api/analytics/ai-chart` | [route.ts](../src/app/api/analytics/ai-chart/route.ts) | Keyword-based mock (not used by the current UI; see Chapter 6). |

## Configuration — collection settings

| Method | Path | Source | Purpose |
|---|---|---|---|
| `GET` | `/api/config/collection` | [route.ts](../src/app/api/config/collection/route.ts) | `nodes` LEFT JOIN `collection_settings`. |
| `PUT` | `/api/config/collection/[nodeId]` | [route.ts](../src/app/api/config/collection/[nodeId]/route.ts) | UPSERT and mirror to etcd (non-fatal). |

## Configuration — pipeline rules

| Method | Path | Source | Purpose |
|---|---|---|---|
| `GET` | `/api/config/pipeline` | [route.ts](../src/app/api/config/pipeline/route.ts) | List rules. |
| `POST` | `/api/config/pipeline` | same | Insert rule. |
| `PUT` | `/api/config/pipeline/[id]` | [route.ts](../src/app/api/config/pipeline/[id]/route.ts) | Update rule. |
| `DELETE` | `/api/config/pipeline/[id]` | same | Delete rule. |
| `POST` | `/api/config/pipeline/push-to-etcd` | [route.ts](../src/app/api/config/pipeline/push-to-etcd/route.ts) | Fan-out enabled rules to every agent. |

## Configuration — alert rules

| Method | Path | Source | Purpose |
|---|---|---|---|
| `GET` | `/api/config/alerts` | [route.ts](../src/app/api/config/alerts/route.ts) | List rules. |
| `POST` | `/api/config/alerts` | same | Insert rule. |
| `PUT` | `/api/config/alerts/[id]` | [route.ts](../src/app/api/config/alerts/[id]/route.ts) | Update rule. |
| `DELETE` | `/api/config/alerts/[id]` | same | Delete rule. |
| `POST` | `/api/config/alerts/push-to-etcd` | [route.ts](../src/app/api/config/alerts/push-to-etcd/route.ts) | Build `threshold_rules` (most-restrictive wins) and push to every agent. |

## Configuration — governance

| Method | Path | Source | Purpose |
|---|---|---|---|
| `GET` | `/api/config/governance/versions` | [route.ts](../src/app/api/config/governance/versions/route.ts) | List versions newest first. |
| `POST` | `/api/config/governance/versions` | same | Insert version row. |
| `GET` | `/api/config/governance/audit` | [route.ts](../src/app/api/config/governance/audit/route.ts) | Last 100 audit entries. |
| `POST` | `/api/config/governance/rollout` | [route.ts](../src/app/api/config/governance/rollout/route.ts) | Activate a version; replay its snapshot to etcd. |
| `POST` | `/api/config/governance/snapshot-and-push` | [route.ts](../src/app/api/config/governance/snapshot-and-push/route.ts) | Snapshot DB + push to etcd + audit (single flow). |

## Notifications

| Method | Path | Source | Purpose |
|---|---|---|---|
| `GET` | `/api/notifications` | [route.ts](../src/app/api/notifications/route.ts) | List with JOIN on `nodes` for `node_name`. |
| `POST` | `/api/notifications` | same | Insert notification. |
| `PUT` | `/api/notifications/[id]` | [route.ts](../src/app/api/notifications/[id]/route.ts) | Set `acknowledged = true`. |

## Chat (stub)

| Method | Path | Source | Purpose |
|---|---|---|---|
| `POST` | `/api/chat` | [route.ts](../src/app/api/chat/route.ts) | Keyword-based canned replies; documented contract mismatch with the chat page (Chapter 6). |
