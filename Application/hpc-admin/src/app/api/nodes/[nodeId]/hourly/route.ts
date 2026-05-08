import { NextRequest, NextResponse } from "next/server"
import pool from "@/lib/db"

const RANGE_MAP: Record<string, string> = {
  "1d":  "1 day",
  "2d":  "2 days",
  "7d":  "7 days",
  // backward-compat aliases
  "24h": "1 day",
  "48h": "2 days",
  "30d": "30 days",
}

const SELECT_COLUMNS = `
  bucket_time, avg_cpu_usage_percent, max_cpu_usage_percent,
  avg_mem_usage_percent, max_mem_used_bytes,
  avg_gpu_utilization, max_gpu_temperature, total_gpu_power_watts,
  total_disk_read_bytes, total_disk_write_bytes,
  total_net_rx_bytes, total_net_tx_bytes, is_active
`

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ nodeId: string }> }
) {
  const { nodeId } = await params
  const range = req.nextUrl.searchParams.get("range") ?? "1d"
  const fromParam = req.nextUrl.searchParams.get("from")
  const toParam = req.nextUrl.searchParams.get("to")

  const client = await pool.connect()
  try {
    if (range === "custom" && fromParam && toParam) {
      const { rows } = await client.query(
        `SELECT ${SELECT_COLUMNS}
         FROM node_status_hourly
         WHERE node_id = $1
           AND bucket_time >= $2::timestamptz
           AND bucket_time <= $3::timestamptz
         ORDER BY bucket_time ASC`,
        [nodeId, fromParam, toParam]
      )
      return NextResponse.json(rows)
    }

    const interval = RANGE_MAP[range] ?? "1 day"
    const { rows } = await client.query(
      `SELECT ${SELECT_COLUMNS}
       FROM node_status_hourly
       WHERE node_id = $1
         AND bucket_time >= NOW() - ($2::text)::interval
       ORDER BY bucket_time ASC`,
      [nodeId, interval]
    )
    return NextResponse.json(rows)
  } finally {
    client.release()
  }
}
