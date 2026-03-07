import pool from "@/lib/db"
import { NextResponse } from "next/server"

export async function GET() {
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      "SELECT * FROM alert_rules ORDER BY created_at"
    )
    return NextResponse.json(rows)
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}

export async function POST(req: Request) {
  const body = await req.json()
  const { name, node_group, resource, operator, threshold, severity, enabled } = body
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      `INSERT INTO alert_rules (name, node_group, resource, operator, threshold, severity, enabled)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [name, node_group, resource, operator, threshold, severity, enabled ?? true]
    )
    return NextResponse.json(rows[0], { status: 201 })
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}
