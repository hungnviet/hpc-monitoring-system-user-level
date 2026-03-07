import pool from "@/lib/db"
import { NextResponse } from "next/server"

// GET /api/analytics/user-usage?uid=<uid>&resource=<resource>&from=<iso>&to=<iso>
// Returns per-user aggregated usage or time-series depending on `mode` param.
// mode=summary (default): aggregated totals per user
// mode=timeseries: hourly buckets for a specific uid
// mode=apps: per-app breakdown for a specific uid
export async function GET(req: Request) {
  const { searchParams } = new URL(req.url)
  const mode = searchParams.get("mode") ?? "summary"
  const from = searchParams.get("from") ?? new Date(Date.now() - 7 * 86400_000).toISOString()
  const to = searchParams.get("to") ?? new Date().toISOString()
  const uid = searchParams.get("uid")

  const client = await pool.connect()
  try {
    if (mode === "timeseries" && uid) {
      const resource = searchParams.get("resource") ?? "cpu"
      // Map resource to safe, hardcoded SQL expression (no user input in SQL)
      const RESOURCE_SQL: Record<string, string> = {
        cpu:  "SUM(h.total_cpu_time_seconds) / 3600.0",
        mem:  "MAX(h.max_rss_memory_bytes) / 1048576.0",
        gpu:  "MAX(h.max_gpu_memory_mib)",
        disk: "SUM(h.total_read_bytes + h.total_write_bytes) / 1048576.0",
      }
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
        [parseInt(uid), from, to]
      )
      return NextResponse.json(rows)
    }

    if (mode === "apps" && uid) {
      const { rows } = await client.query(
        `SELECT
           u.username, h.comm,
           SUM(h.total_cpu_time_seconds)  AS total_cpu_seconds,
           MAX(h.max_rss_memory_bytes)    AS peak_mem_bytes,
           SUM(h.process_count)           AS total_process_count
         FROM user_app_hourly h
         JOIN hpc_users u ON h.uid = u.uid
         WHERE h.uid = $1
           AND h.bucket_time >= $2
           AND h.bucket_time <= $3
         GROUP BY u.username, h.comm
         ORDER BY total_cpu_seconds DESC`,
        [parseInt(uid), from, to]
      )
      return NextResponse.json(rows)
    }

    // Default: summary per user
    const { rows } = await client.query(
      `SELECT
         u.uid, u.username, u.group_name,
         SUM(h.total_cpu_time_seconds)                       AS total_cpu_seconds,
         MAX(h.max_rss_memory_bytes)                         AS peak_mem_bytes,
         MAX(h.max_gpu_memory_mib)                           AS peak_gpu_mib,
         SUM(h.total_read_bytes + h.total_write_bytes)       AS total_disk_bytes
       FROM user_app_hourly h
       JOIN hpc_users u ON h.uid = u.uid
       WHERE h.bucket_time >= $1
         AND h.bucket_time <= $2
       GROUP BY u.uid, u.username, u.group_name
       ORDER BY total_cpu_seconds DESC`,
      [from, to]
    )
    return NextResponse.json(rows)
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}
