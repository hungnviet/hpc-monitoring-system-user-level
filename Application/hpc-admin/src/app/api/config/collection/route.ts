import pool from "@/lib/db"
import { NextResponse } from "next/server"

// GET /api/config/collection
// Returns all nodes joined with their collection settings
export async function GET() {
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      `SELECT
         n.id, n.name, n.ip, n.group_name, n.collect_agent,
         COALESCE(cs.interval_seconds, 10) AS interval_seconds,
         COALESCE(cs.window_seconds, 60)   AS window_seconds,
         cs.updated_at
       FROM nodes n
       LEFT JOIN collection_settings cs ON n.id = cs.node_id
       ORDER BY n.name`
    )
    return NextResponse.json(rows)
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}
