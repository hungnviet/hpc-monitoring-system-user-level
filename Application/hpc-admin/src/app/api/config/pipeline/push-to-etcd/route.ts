import pool from "@/lib/db"
import etcd from "@/lib/etcd"
import { NextResponse } from "next/server"

// POST /api/config/pipeline/push-to-etcd
//
// Reads all enabled pipeline rules from TimescaleDB and publishes them as a
// JSON array to every collect agent in etcd under:
//   /config/collect_agent/{agentId}/pipeline_rules
//
// Collect agents watch this key and reload their preprocessing pipeline on
// change, without needing a restart.
export async function POST() {
  const pgClient = await pool.connect()
  try {
    // 1. Fetch all enabled pipeline rules from DB
    const { rows } = await pgClient.query(
      "SELECT id, name, type, resource, condition FROM pipeline_rules WHERE enabled = TRUE ORDER BY created_at"
    )

    // 2. Discover all collect agents registered in etcd
    let agentIds: string[] = []
    try {
      const kv = await etcd.getAll().prefix("/config/collect_agent/").strings()
      const seen = new Set<string>()
      for (const key of Object.keys(kv)) {
        // key = /config/collect_agent/{agentId}/{field}
        const parts = key.split("/")
        if (parts.length >= 4) seen.add(parts[3])
      }
      agentIds = Array.from(seen)
    } catch {
      return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
    }

    if (agentIds.length === 0) {
      return NextResponse.json({ error: "No collect agents found in etcd" }, { status: 404 })
    }

    // 3. Push the rule set to every agent in parallel
    const payload = JSON.stringify(rows)
    await Promise.all(
      agentIds.map(id =>
        etcd.put(`/config/collect_agent/${id}/pipeline_rules`).value(payload)
      )
    )

    return NextResponse.json({
      pushed_to: agentIds,
      rule_count: rows.length,
      pushed_at: new Date().toISOString(),
    })
  } catch {
    return NextResponse.json({ error: "Push failed" }, { status: 500 })
  } finally {
    pgClient.release()
  }
}
