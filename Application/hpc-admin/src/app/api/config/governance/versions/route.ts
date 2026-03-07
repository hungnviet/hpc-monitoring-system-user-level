import pool from "@/lib/db"
import { NextResponse } from "next/server"

export async function GET() {
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      "SELECT * FROM config_versions ORDER BY created_at DESC"
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
  const { version, author, description, config_snapshot } = body
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      `INSERT INTO config_versions (version, author, description, config_snapshot)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [version, author ?? "admin", description, JSON.stringify(config_snapshot ?? {})]
    )
    return NextResponse.json(rows[0], { status: 201 })
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}
