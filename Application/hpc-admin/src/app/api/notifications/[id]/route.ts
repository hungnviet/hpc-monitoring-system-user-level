import pool from "@/lib/db"
import { NextResponse } from "next/server"

// PUT /api/notifications/[id]
// Body: { acknowledged: boolean }
export async function PUT(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params
  const body = await req.json()
  const { acknowledged } = body
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      "UPDATE notifications SET acknowledged=$2 WHERE id=$1 RETURNING *",
      [id, acknowledged ?? true]
    )
    if (rows.length === 0) {
      return NextResponse.json({ error: "Notification not found" }, { status: 404 })
    }
    return NextResponse.json(rows[0])
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}
