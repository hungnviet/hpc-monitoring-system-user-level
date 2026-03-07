import pool from "@/lib/db"
import { NextResponse } from "next/server"

export async function GET() {
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      "SELECT * FROM nodes ORDER BY name"
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
  const { id, name, ip, group_name, collect_agent } = body
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      `INSERT INTO nodes (id, name, ip, group_name, collect_agent)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [id, name, ip, group_name, collect_agent]
    )
    return NextResponse.json(rows[0], { status: 201 })
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}
