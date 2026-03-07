import pool from "@/lib/db"
import { NextResponse } from "next/server"

export async function PUT(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params
  const body = await req.json()
  const { name, type, resource, condition, enabled } = body
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      `UPDATE pipeline_rules
       SET name=$2, type=$3, resource=$4, condition=$5, enabled=$6, updated_at=NOW()
       WHERE id=$1
       RETURNING *`,
      [id, name, type, resource, condition, enabled]
    )
    if (rows.length === 0) {
      return NextResponse.json({ error: "Rule not found" }, { status: 404 })
    }
    return NextResponse.json(rows[0])
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}

export async function DELETE(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params
  const client = await pool.connect()
  try {
    await client.query("DELETE FROM pipeline_rules WHERE id=$1", [id])
    return NextResponse.json({ success: true })
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}
