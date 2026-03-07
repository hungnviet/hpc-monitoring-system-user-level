import pool from "@/lib/db"
import { NextResponse } from "next/server"

export async function PUT(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params
  const body = await req.json()
  const { name, node_group, resource, operator, threshold, severity, enabled } = body
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      `UPDATE alert_rules
       SET name=$2, node_group=$3, resource=$4, operator=$5,
           threshold=$6, severity=$7, enabled=$8
       WHERE id=$1
       RETURNING *`,
      [id, name, node_group, resource, operator, threshold, severity, enabled]
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
    await client.query("DELETE FROM alert_rules WHERE id=$1", [id])
    return NextResponse.json({ success: true })
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}
