import pool from "@/lib/db"
import etcd from "@/lib/etcd"
import { NextResponse } from "next/server"

// POST /api/config/governance/rollout
// Body: { versionId: string, actor?: string }
//
// 1. Marks the given version active in DB (deactivates others)
// 2. Writes an audit log entry
// 3. If the version has a config_snapshot, replays it to etcd so all nodes
//    and agents immediately receive the rolled-back configuration.
//    etcd push is non-fatal — DB changes are committed first.
export async function POST(req: Request) {
  const body = await req.json()
  const { versionId, actor = "admin" } = body
  const pgClient = await pool.connect()
  try {
    await pgClient.query("BEGIN")

    await pgClient.query("UPDATE config_versions SET active = FALSE")

    const { rows } = await pgClient.query(
      "UPDATE config_versions SET active = TRUE WHERE id = $1 RETURNING *",
      [versionId]
    )
    if (rows.length === 0) {
      await pgClient.query("ROLLBACK")
      return NextResponse.json({ error: "Version not found" }, { status: 404 })
    }

    await pgClient.query(
      `INSERT INTO audit_logs (actor, action, target, detail)
       VALUES ($1, 'ROLLOUT', 'config_version', $2)`,
      [actor, `Activated config version ${rows[0].version}`]
    )

    await pgClient.query("COMMIT")

    const version = rows[0]
    const etcdResult = { pushed_to_nodes: [] as string[], pushed_to_agents: [] as string[], error: null as string | null }

    // ── Replay snapshot to etcd if available ──────────────────────────────────
    if (version.config_snapshot) {
      try {
        const snapshot = typeof version.config_snapshot === "string"
          ? JSON.parse(version.config_snapshot)
          : version.config_snapshot

        const collectionSettings: Array<{
          node_id: string; window_seconds: number; interval_seconds: number; collect_agent: string
        }> = snapshot.collection_settings ?? []

        const pipelineRules = snapshot.pipeline_rules ?? []
        const thresholds = snapshot.threshold_rules ?? {}

        // Discover registered nodes + agents in etcd
        const [nodeKV, agentKV] = await Promise.all([
          etcd.getAll().prefix("/config/compute_node/").strings(),
          etcd.getAll().prefix("/config/collect_agent/").strings(),
        ])

        const nodeIds = Array.from(new Set(
          Object.keys(nodeKV).map(k => k.split("/")[3]).filter(Boolean)
        ))
        const agentIds = Array.from(new Set(
          Object.keys(agentKV).map(k => k.split("/")[3]).filter(Boolean)
        ))

        const settingsByNode = new Map(collectionSettings.map(s => [s.node_id, s]))

        // Push collection config to each node
        await Promise.all(
          nodeIds.map(nodeId => {
            const s = settingsByNode.get(nodeId)
            if (!s) return Promise.resolve()
            const base = `/config/compute_node/${nodeId}`
            return Promise.all([
              etcd.put(`${base}/window`).value(String(s.window_seconds)),
              etcd.put(`${base}/heartbeat_interval`).value(String(s.interval_seconds)),
              etcd.put(`${base}/target_collect_agent`).value(String(s.collect_agent)),
            ])
          })
        )
        etcdResult.pushed_to_nodes = nodeIds

        // Push pipeline_rules + threshold_rules to each agent
        const pipelinePayload = JSON.stringify(pipelineRules)
        const thresholdPayload = JSON.stringify(thresholds)
        await Promise.all(
          agentIds.map(agentId =>
            Promise.all([
              etcd.put(`/config/collect_agent/${agentId}/pipeline_rules`).value(pipelinePayload),
              ...(Object.keys(thresholds).length > 0
                ? [etcd.put(`/config/collect_agent/${agentId}/threshold_rules`).value(thresholdPayload)]
                : []
              ),
            ])
          )
        )
        etcdResult.pushed_to_agents = agentIds
      } catch (e) {
        etcdResult.error = e instanceof Error ? e.message : "etcd push failed"
      }
    }

    return NextResponse.json({ ...version, etcd: etcdResult })
  } catch {
    await pgClient.query("ROLLBACK").catch(() => {})
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    pgClient.release()
  }
}
