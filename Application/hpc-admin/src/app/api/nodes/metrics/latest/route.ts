import { NextResponse } from "next/server"
import pool from "@/lib/db"

export async function GET() {
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      `SELECT DISTINCT ON (node_id)
         node_id, bucket_time,
         avg_cpu_usage_percent AS cpu,
         avg_gpu_utilization   AS gpu,
         avg_mem_usage_percent AS mem
       FROM node_status_hourly
       ORDER BY node_id, bucket_time DESC`
    )
    const result: Record<string, { cpu: number | null; gpu: number | null; mem: number | null }> = {}
    for (const row of rows) {
      result[row.node_id] = {
        cpu: row.cpu !== null ? Number(row.cpu) : null,
        gpu: row.gpu !== null ? Number(row.gpu) : null,
        mem: row.mem !== null ? Number(row.mem) : null,
      }
    }
    return NextResponse.json(result)
  } finally {
    client.release()
  }
}
