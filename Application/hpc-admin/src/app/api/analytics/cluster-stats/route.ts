import { NextRequest, NextResponse } from "next/server"
import pool from "@/lib/db"

export async function GET(req: NextRequest) {
  const range = req.nextUrl.searchParams.get("range") ?? "1h"
  const allowed = ["1h", "6h", "24h"]
  const safeRange = allowed.includes(range) ? range : "1h"

  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      `SELECT
        ROUND(AVG(avg_cpu_usage_percent)::numeric, 1)                                          AS avg_cpu_pct,
        ROUND(AVG(avg_gpu_utilization)::numeric, 1)                                            AS avg_gpu_pct,
        ROUND(AVG(avg_mem_usage_percent)::numeric, 1)                                          AS avg_mem_pct,
        ROUND(((SUM(total_disk_read_bytes) + SUM(total_disk_write_bytes)) / 1048576.0)::numeric, 1) AS total_disk_mb,
        ROUND((SUM(total_net_rx_bytes) / 1048576.0)::numeric, 1)                               AS net_rx_mb,
        ROUND((SUM(total_net_tx_bytes) / 1048576.0)::numeric, 1)                               AS net_tx_mb
      FROM node_status_hourly
      WHERE bucket_time >= NOW() - ($1::text)::interval`,
      [safeRange]
    )
    const row = rows[0] ?? {}
    return NextResponse.json({
      avg_cpu_pct:   row.avg_cpu_pct   != null ? Number(row.avg_cpu_pct)   : null,
      avg_gpu_pct:   row.avg_gpu_pct   != null ? Number(row.avg_gpu_pct)   : null,
      avg_mem_pct:   row.avg_mem_pct   != null ? Number(row.avg_mem_pct)   : null,
      total_disk_mb: row.total_disk_mb != null ? Number(row.total_disk_mb) : null,
      net_rx_mb:     row.net_rx_mb     != null ? Number(row.net_rx_mb)     : null,
      net_tx_mb:     row.net_tx_mb     != null ? Number(row.net_tx_mb)     : null,
    })
  } catch (err) {
    console.error("[cluster-stats]", err)
    return NextResponse.json({ error: "query failed" }, { status: 500 })
  } finally {
    client.release()
  }
}
