# Appendix B — etcd key reference

All etcd keys that the admin application reads or writes. Paths are literal; `{nodeId}` and `{agentId}` are substituted at request time.

## Compute node prefix — `/config/compute_node/`

| Key | Type | Written by | Purpose |
|---|---|---|---|
| `/config/compute_node/{nodeId}/target_collect_agent` | string `"ip:port"` | admin app + agent bootstrap | Collect agent this compute-node sends gRPC metrics to. |
| `/config/compute_node/{nodeId}/window` | string seconds | admin app | Sampling window for the compute-node agent. |
| `/config/compute_node/{nodeId}/heartbeat_interval` | string seconds | admin app | Heartbeat cadence. |
| `/config/compute_node/{nodeId}/status` | string `"running"` or `"stopped"` | admin app | Intent flag read by the agent loop. |

## Heartbeat prefix — `/nodes/` (read only)

| Key | Type | Written by | Purpose |
|---|---|---|---|
| `/nodes/{nodeId}/heartbeat` | JSON `{ timestamp:int, status:"alive", collection_active:bool }` | compute-node agent | Used by the admin app to derive live node status. |

### Status derivation

```
threshold = heartbeat_interval * 3      # default 20s × 3 = 60s
isAlive = heartbeat.status == "alive" && (now - heartbeat.timestamp) <= threshold
node.status = isAlive ? "running" : "stopped"
```

Source: [src/app/api/etcd/nodes/route.ts](../src/app/api/etcd/nodes/route.ts) §41–66.

## Collect agent prefix — `/config/collect_agent/`

This is the schema that the **collect agent** actually reads. The admin web app currently pushes a slightly different subset (see the note at the end of this section and [Chapter 6 §6.2](06-conclusion.md#62-limitations)).

| Key | Type | Read by | Purpose |
|---|---|---|---|
| `/config/collect_agent/{agentId}/kafka_brokers` | JSON array of strings | agent | Kafka bootstrap servers. |
| `/config/collect_agent/{agentId}/kafka_topic` | string | agent | Destination topic. |
| `/config/collect_agent/{agentId}/pipeline_stages` | JSON array of strings | agent | Ordered list of processing-stage names the agent instantiates on startup. |
| `/config/collect_agent/{agentId}/process_fields` | JSON array of strings | agent | Allow-list of per-process fields retained after the `field_projection` stage. |
| `/config/collect_agent/{agentId}/comm_prefixes` | JSON array of strings | agent | Process-name (`comm`) prefixes folded by the `prefix_aggregation` stage. |
| `/config/collect_agent/{agentId}/threshold_rules` | JSON object | agent | Per-resource `max` thresholds evaluated by the `threshold_checker` stage. |

### Example values

```
/config/collect_agent/collect_agent_1/kafka_brokers
["172.28.10.129:9092"]

/config/collect_agent/collect_agent_1/kafka_topic
monitoring_metrics

/config/collect_agent/collect_agent_1/pipeline_stages
["SchemaValidator","field_projection","prefix_aggregation","metrics_enricher","threshold_checker"]

/config/collect_agent/collect_agent_1/process_fields
["pid","cpu_ontime_ns","uid","comm","read_bytes","write_bytes"]

/config/collect_agent/collect_agent_1/comm_prefixes
["StreamT","IPC","FSBroker","gvfsd","gsd","kworker"]

/config/collect_agent/collect_agent_1/threshold_rules
{"cpu_usage_percent":{"max":80},"memory_usage_percent":{"max":85},"gpu_utilization_percent":{"max":90}}
```

### `threshold_rules` shape

```json
{
  "cpu_usage_percent":      { "max": 80 },
  "memory_usage_percent":   { "max": 85 },
  "gpu_utilization_percent":{ "max": 90 },
  "disk_usage_percent":     { "max": 85 }
}
```

The admin application maps `alert_rules.resource` to the JSON key as follows:

| DB value | JSON key |
|---|---|
| `cpu` | `cpu_usage_percent` |
| `mem` | `memory_usage_percent` |
| `gpu` | `gpu_utilization_percent` |
| `disk` | `disk_usage_percent` |
| `net` | (skipped — in-app notifications only) |

### Known schema drift between the admin app and the agent

The current admin application writes a single `pipeline_rules` array (projected from the `pipeline_rules` table), whereas the agent reads three separate keys — `pipeline_stages`, `process_fields`, `comm_prefixes` — that carry different semantics. Only `threshold_rules` and the Kafka keys are read by both sides today. Aligning the push handler (`/api/config/pipeline/push-to-etcd`) with the agent schema is tracked in [Chapter 6 §6.3](06-conclusion.md#63-future-work).

## Discovery patterns

The application never stores a registry of agents or nodes separately; it discovers them from prefix scans:

- Discover agents: `etcd.getAll().prefix('/config/collect_agent/').strings()` → split on `/` → `parts[3]` is `agentId`.
- Discover nodes: `etcd.getAll().prefix('/config/compute_node/').strings()` → same pattern.

See [src/app/api/config/governance/snapshot-and-push/route.ts](../src/app/api/config/governance/snapshot-and-push/route.ts) §20–40.
