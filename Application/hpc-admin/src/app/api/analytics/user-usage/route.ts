import pool from "@/lib/db"
import { NextResponse } from "next/server"

// Hardcoded SQL expressions per resource — no user input in SQL
const RESOURCE_SQL: Record<string, string> = {
  cpu:  "SUM(h.total_cpu_time_seconds)",
  mem:  "MAX(h.max_rss_memory_bytes) / 1048576.0",
  gpu:  "MAX(h.max_gpu_memory_mib)",
  disk: "SUM(h.total_read_bytes + h.total_write_bytes) / 1048576.0",
  net:  "SUM(h.total_net_rx_bytes + h.total_net_tx_bytes) / 1048576.0",
}

function parseUids(raw: string | null): number[] {
  if (!raw) return []
  return raw.split(",").map(Number).filter(n => !isNaN(n) && n > 0)
}

// GET /api/analytics/user-usage?mode=summary|timeseries|apps|app-timeseries
// Params: uid (comma-sep), resource, from, to
export async function GET(req: Request) {
  const { searchParams } = new URL(req.url)
  const mode = searchParams.get("mode") ?? "summary"
  const from = searchParams.get("from") ?? new Date(Date.now() - 7 * 86400_000).toISOString()
  const to = searchParams.get("to") ?? new Date().toISOString()
  const uids = parseUids(searchParams.get("uid"))

  const client = await pool.connect()
  try {
    // ── Timeseries: hourly buckets for a single uid + resource ──────────
    if (mode === "timeseries" && uids.length > 0) {
      const resource = searchParams.get("resource") ?? "cpu"
      const valueSql = RESOURCE_SQL[resource]
      if (!valueSql) return NextResponse.json([])

      const { rows } = await client.query(
        `SELECT
           time_bucket('1 hour', h.bucket_time) AS t,
           ${valueSql} AS value
         FROM user_app_hourly h
         WHERE h.uid = $1
           AND h.bucket_time >= $2
           AND h.bucket_time <= $3
         GROUP BY t
         ORDER BY t`,
        [uids[0], from, to]
      )
      return NextResponse.json(rows)
    }

    // ── App-timeseries: hourly buckets per user+app for multiple uids ─
    if (mode === "app-timeseries" && uids.length > 0) {
      const resource = searchParams.get("resource") ?? "cpu"
      const valueSql = RESOURCE_SQL[resource]
      if (!valueSql) return NextResponse.json([])

      const { rows } = await client.query(
        `SELECT
           time_bucket('1 hour', h.bucket_time) AS t,
           u.username,
           h.comm,
           ${valueSql} AS value
         FROM user_app_hourly h
         JOIN hpc_users u ON h.uid = u.uid
         WHERE h.uid = ANY($1::int[])
           AND h.bucket_time >= $2
           AND h.bucket_time <= $3
         GROUP BY t, h.uid, u.username, h.comm
         ORDER BY t, u.username, h.comm`,
        [uids, from, to]
      )
      return NextResponse.json(rows)
    }

    // ── Apps: per-app breakdown with all resources for multiple uids ────
    if (mode === "apps" && uids.length > 0) {
      const { rows } = await client.query(
        `SELECT
           u.username, h.comm,
           SUM(h.total_cpu_time_seconds)                               AS cpu_seconds,
           MAX(h.max_rss_memory_bytes) / 1048576.0                    AS peak_mem_mb,
           MAX(h.max_gpu_memory_mib)                                  AS peak_gpu_mib,
           SUM(h.total_read_bytes + h.total_write_bytes) / 1048576.0  AS disk_io_mb,
           SUM(h.total_net_rx_bytes + h.total_net_tx_bytes) / 1048576.0 AS net_io_mb,
           SUM(h.process_count)                                       AS total_processes
         FROM user_app_hourly h
         JOIN hpc_users u ON h.uid = u.uid
         WHERE h.uid = ANY($1::int[])
           AND h.bucket_time >= $2
           AND h.bucket_time <= $3
         GROUP BY u.username, h.comm
         ORDER BY cpu_seconds DESC`,
        [uids, from, to]
      )
      return NextResponse.json(rows)
    }

    // ── Summary: aggregated totals per user (default) ───────────────────
    const { rows } = await client.query(
      `SELECT
         u.uid, u.username, u.group_name,
         SUM(h.total_cpu_time_seconds)                            AS total_cpu_seconds,
         MAX(h.max_rss_memory_bytes)                              AS peak_mem_bytes,
         MAX(h.max_gpu_memory_mib)                                AS peak_gpu_mib,
         SUM(h.total_read_bytes + h.total_write_bytes)            AS total_disk_bytes,
         SUM(h.total_net_rx_bytes + h.total_net_tx_bytes)         AS total_net_bytes
       FROM hpc_users u
       LEFT JOIN user_app_hourly h ON h.uid = u.uid
         AND h.bucket_time >= $1
         AND h.bucket_time <= $2
       GROUP BY u.uid, u.username, u.group_name
       ORDER BY total_cpu_seconds DESC NULLS LAST`,
      [from, to]
    )
    return NextResponse.json(rows)
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}
