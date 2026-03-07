import pool from "@/lib/db"
import { NextResponse } from "next/server"

export async function GET() {
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      `SELECT n.*, nd.name AS node_name
       FROM notifications n
       LEFT JOIN nodes nd ON n.node_id = nd.id
       ORDER BY n.created_at DESC`
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
  const { severity, message, node_id, rule_id } = body
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      `INSERT INTO notifications (severity, message, node_id, rule_id)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [severity, message, node_id ?? null, rule_id ?? null]
    )
    return NextResponse.json(rows[0], { status: 201 })
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}
