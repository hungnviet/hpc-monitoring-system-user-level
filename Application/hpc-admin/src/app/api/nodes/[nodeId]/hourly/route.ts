import { NextRequest, NextResponse } from "next/server"
import pool from "@/lib/db"

const RANGE_MAP: Record<string, string> = {
  "24h": "24 hours",
  "48h": "48 hours",
  "7d":  "7 days",
  "30d": "30 days",
}

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ nodeId: string }> }
) {
  const { nodeId } = await params
  const range = req.nextUrl.searchParams.get("range") ?? "24h"
  const interval = RANGE_MAP[range] ?? "24 hours"

  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      `SELECT bucket_time, avg_cpu_usage_percent, max_cpu_usage_percent,
              avg_mem_usage_percent, max_mem_used_bytes,
              avg_gpu_utilization, max_gpu_temperature, total_gpu_power_watts,
              total_disk_read_bytes, total_disk_write_bytes,
              total_net_rx_bytes, total_net_tx_bytes, is_active
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
