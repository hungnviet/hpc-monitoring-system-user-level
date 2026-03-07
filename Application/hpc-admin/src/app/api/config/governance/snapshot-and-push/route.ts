import pool from "@/lib/db"
import etcd from "@/lib/etcd"
import { NextResponse } from "next/server"

// Maps alert_rules.resource to the etcd threshold_rules key (same as alerts/push-to-etcd)
const RESOURCE_TO_ETCD_KEY: Record<string, string> = {
  cpu:  "cpu_usage_percent",
  mem:  "memory_usage_percent",
  gpu:  "gpu_max_utilization_percent",
  disk: "disk_usage_percent",
}

function nextVersion(latest: string | undefined): string {
  if (!latest) return "1.0.0"
  const parts = latest.split(".").map(Number)
  if (parts.length !== 3 || parts.some(isNaN)) return "1.0.0"
  return `${parts[0]}.${parts[1]}.${parts[2] + 1}`
}

// Discover all unique agent IDs registered in etcd
async function discoverAgents(): Promise<string[]> {
  const kv = await etcd.getAll().prefix("/config/collect_agent/").strings()
  const seen = new Set<string>()
  for (const key of Object.keys(kv)) {
    const parts = key.split("/")
    if (parts.length >= 4) seen.add(parts[3])
  }
  return Array.from(seen)
}

// Discover all node IDs registered in etcd
async function discoverNodes(): Promise<string[]> {
  const kv = await etcd.getAll().prefix("/config/compute_node/").strings()
  const seen = new Set<string>()
  for (const key of Object.keys(kv)) {
    const parts = key.split("/")
    if (parts.length >= 4) seen.add(parts[3])
  }
  return Array.from(seen)
}

// POST /api/config/governance/snapshot-and-push
//
// 1. Reads current state from DB (collection_settings, pipeline_rules, alert_rules)
// 2. Builds a config snapshot
// 3. Auto-increments the version number
// 4. Saves the snapshot to config_versions (marking it active)
// 5. Deactivates all other versions
// 6. Pushes collection settings to each node in etcd
// 7. Pushes pipeline_rules + threshold_rules to each collect agent in etcd
// 8. Writes an audit log entry
//
// Body: { description?: string, author?: string }
export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}))
  const { description = "Configuration snapshot", author = "admin" } = body

  const pgClient = await pool.connect()
  try {
    // ── 1. Gather current config from DB ────────────────────────────────────
    const [collectionRes, pipelineRes, alertsRes, latestVersionRes] = await Promise.all([
      pgClient.query(
        `SELECT n.id AS node_id, n.name, n.group_name, n.collect_agent AS default_agent,
                COALESCE(cs.interval_seconds, 10) AS interval_seconds,
                COALESCE(cs.window_seconds, 60)   AS window_seconds,
                COALESCE(cs.collect_agent, n.collect_agent) AS collect_agent
         FROM nodes n
         LEFT JOIN collection_settings cs ON n.id = cs.node_id`
      ),
      pgClient.query(
        "SELECT id, name, type, resource, condition FROM pipeline_rules WHERE enabled = TRUE ORDER BY created_at"
      ),
      pgClient.query(
        "SELECT name, resource, operator, threshold FROM alert_rules WHERE enabled = TRUE AND operator IN ('>', '>=')"
      ),
      pgClient.query(
        "SELECT version FROM config_versions ORDER BY created_at DESC LIMIT 1"
      ),
    ])

    const collectionSettings = collectionRes.rows
    const pipelineRules = pipelineRes.rows
    const alertRules = alertsRes.rows
    const latestVersion = latestVersionRes.rows[0]?.version

    // ── 2. Build threshold_rules from alert rules ────────────────────────────
    const thresholds: Record<string, { max: number }> = {}
    for (const rule of alertRules) {
      const key = RESOURCE_TO_ETCD_KEY[rule.resource]
      if (!key) continue
      if (!thresholds[key] || rule.threshold < thresholds[key].max) {
        thresholds[key] = { max: rule.threshold }
      }
    }

    // ── 3. Build the config snapshot ─────────────────────────────────────────
    const configSnapshot = {
      collection_settings: collectionSettings,
      pipeline_rules: pipelineRules,
      threshold_rules: thresholds,
    }

    const newVersion = nextVersion(latestVersion)

    // ── 4. Save to DB (in a transaction) ─────────────────────────────────────
    await pgClient.query("BEGIN")

    await pgClient.query("UPDATE config_versions SET active = FALSE")

    const { rows: savedVersion } = await pgClient.query(
      `INSERT INTO config_versions (version, author, description, config_snapshot, active)
       VALUES ($1, $2, $3, $4, TRUE)
       RETURNING *`,
      [newVersion, author, description, JSON.stringify(configSnapshot)]
    )

    await pgClient.query(
      `INSERT INTO audit_logs (actor, action, target, detail)
       VALUES ($1, 'ROLLOUT', 'config_version', $2)`,
      [author, `Snapshot v${newVersion} created and pushed to all nodes`]
    )

    await pgClient.query("COMMIT")

    // ── 5. Push to etcd (non-fatal: DB is already committed) ─────────────────
    let pushedToNodes: string[] = []
    let pushedToAgents: string[] = []
    const etcdErrors: string[] = []

    try {
      const [nodeIds, agentIds] = await Promise.all([discoverNodes(), discoverAgents()])

      // Map collection_settings by nodeId for quick lookup
      const settingsByNode = new Map(collectionSettings.map(s => [s.node_id, s]))

      // Push per-node collection config
      const nodePushes = nodeIds.map(nodeId => {
        const s = settingsByNode.get(nodeId)
        if (!s) return Promise.resolve()
        const base = `/config/compute_node/${nodeId}`
        return Promise.all([
          etcd.put(`${base}/window`).value(String(s.window_seconds)),
          etcd.put(`${base}/heartbeat_interval`).value(String(s.interval_seconds)),
          etcd.put(`${base}/target_collect_agent`).value(String(s.collect_agent)),
        ])
      })
      await Promise.all(nodePushes)
      pushedToNodes = nodeIds

      // Push pipeline_rules + threshold_rules to each agent
      const pipelinePayload = JSON.stringify(pipelineRules)
      const thresholdPayload = JSON.stringify(thresholds)
      const agentPushes = agentIds.map(agentId =>
        Promise.all([
          etcd.put(`/config/collect_agent/${agentId}/pipeline_rules`).value(pipelinePayload),
          ...(Object.keys(thresholds).length > 0
            ? [etcd.put(`/config/collect_agent/${agentId}/threshold_rules`).value(thresholdPayload)]
            : []
          ),
        ])
      )
      await Promise.all(agentPushes)
      pushedToAgents = agentIds
    } catch (etcdErr) {
      etcdErrors.push(etcdErr instanceof Error ? etcdErr.message : "etcd push failed")
    }

    return NextResponse.json({
      version: savedVersion[0],
      pushed_to_nodes: pushedToNodes,
      pushed_to_agents: pushedToAgents,
      node_count: pushedToNodes.length,
      agent_count: pushedToAgents.length,
      rule_count: pipelineRules.length,
      threshold_count: Object.keys(thresholds).length,
      etcd_errors: etcdErrors,
    })
  } catch (err) {
    await pgClient.query("ROLLBACK").catch(() => {})
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Snapshot failed" },
      { status: 500 }
    )
  } finally {
    pgClient.release()
  }
}
