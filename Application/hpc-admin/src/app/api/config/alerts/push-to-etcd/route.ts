import pool from "@/lib/db"
import etcd from "@/lib/etcd"
import { NextResponse } from "next/server"

// Maps alert_rules.resource values to the threshold_rules keys used by
// collect agents in etcd.
// Only resources with a direct "max" threshold mapping are included.
const RESOURCE_TO_ETCD_KEY: Record<string, string> = {
  cpu:  "cpu_usage_percent",
  mem:  "memory_usage_percent",
  gpu:  "gpu_max_utilization_percent",
  disk: "disk_usage_percent",
}

// POST /api/config/alerts/push-to-etcd
//
// Builds a threshold_rules object from all enabled alert rules that use a
// > or >= operator (upper-bound thresholds), then writes that object to
// /config/collect_agent/{agentId}/threshold_rules for every agent in etcd.
//
// Rules with < or <= operators, or resources without a direct etcd mapping
// (e.g. "net"), are skipped — they are only used for in-app notifications.
//
// When multiple rules target the same resource, the most restrictive
// (lowest max) threshold wins.
export async function POST() {
  const pgClient = await pool.connect()
  try {
    // 1. Fetch enabled upper-bound rules from DB
    const { rows } = await pgClient.query(
      `SELECT name, resource, operator, threshold, severity
       FROM alert_rules
       WHERE enabled = TRUE AND operator IN ('>', '>=')`
    )

    // 2. Build threshold_rules object
    const thresholds: Record<string, { max: number }> = {}
    const skipped: string[] = []

    for (const rule of rows) {
      const key = RESOURCE_TO_ETCD_KEY[rule.resource]
      if (!key) {
        skipped.push(rule.name)
        continue
      }
      // Most restrictive wins
      if (!thresholds[key] || rule.threshold < thresholds[key].max) {
        thresholds[key] = { max: rule.threshold }
      }
    }

    if (Object.keys(thresholds).length === 0) {
      return NextResponse.json({
        error: "No syncable rules found (need enabled > or >= rules for cpu/mem/gpu/disk)",
      }, { status: 422 })
    }

    // 3. Discover collect agents in etcd
    let agentIds: string[] = []
    try {
      const kv = await etcd.getAll().prefix("/config/collect_agent/").strings()
      const seen = new Set<string>()
      for (const key of Object.keys(kv)) {
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

    // 4. Push to all agents in parallel
    const payload = JSON.stringify(thresholds)
    await Promise.all(
      agentIds.map(id =>
        etcd.put(`/config/collect_agent/${id}/threshold_rules`).value(payload)
      )
    )

    return NextResponse.json({
      pushed_to: agentIds,
      thresholds,
      skipped,
      pushed_at: new Date().toISOString(),
    })
  } catch {
    return NextResponse.json({ error: "Push failed" }, { status: 500 })
  } finally {
    pgClient.release()
  }
}
