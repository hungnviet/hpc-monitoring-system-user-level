import pool from "@/lib/db"
import etcd from "@/lib/etcd"
import { NextResponse } from "next/server"

// PUT /api/config/collection/[nodeId]
// Upserts collection settings in TimescaleDB and pushes the same values to etcd
// so the collect agent picks them up live without a restart.
export async function PUT(
  req: Request,
  { params }: { params: Promise<{ nodeId: string }> }
) {
  const { nodeId } = await params
  const body = await req.json()
  const { interval_seconds, window_seconds, collect_agent } = body
  const client = await pool.connect()
  try {
    // 1. Persist to TimescaleDB (source of truth for the UI)
    const { rows } = await client.query(
      `INSERT INTO collection_settings (node_id, interval_seconds, window_seconds, collect_agent, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (node_id) DO UPDATE SET
         interval_seconds = EXCLUDED.interval_seconds,
         window_seconds   = EXCLUDED.window_seconds,
         collect_agent    = EXCLUDED.collect_agent,
         updated_at       = NOW()
       RETURNING *`,
      [nodeId, interval_seconds, window_seconds, collect_agent]
    )

    // 2. Push live to etcd so the collect agent reloads without restart.
    //    Failures here are non-fatal — DB is the source of truth.
    const base = `/config/compute_node/${nodeId}`
    await Promise.all([
      etcd.put(`${base}/window`).value(String(window_seconds)),
      etcd.put(`${base}/heartbeat_interval`).value(String(interval_seconds)),
      etcd.put(`${base}/target_collect_agent`).value(String(collect_agent)),
    ]).catch(() => {
      // etcd push failed — log and continue; UI shows DB value
      console.warn(`[etcd] Failed to push config for node ${nodeId}`)
    })

    return NextResponse.json(rows[0])
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}
