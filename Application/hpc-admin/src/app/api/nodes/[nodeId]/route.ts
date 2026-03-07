import pool from "@/lib/db"
import { NextResponse } from "next/server"

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ nodeId: string }> }
) {
  const { nodeId } = await params
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      "SELECT * FROM nodes WHERE id = $1",
      [nodeId]
    )
    if (rows.length === 0) {
      return NextResponse.json({ error: "Node not found" }, { status: 404 })
    }
    return NextResponse.json(rows[0])
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}

export async function PUT(
  req: Request,
  { params }: { params: Promise<{ nodeId: string }> }
) {
  const { nodeId } = await params
  const body = await req.json()
  const { name, ip, group_name, collect_agent } = body
  const client = await pool.connect()
  try {
    const { rows } = await client.query(
      `UPDATE nodes SET name=$2, ip=$3, group_name=$4, collect_agent=$5
       WHERE id=$1 RETURNING *`,
      [nodeId, name, ip, group_name, collect_agent]
    )
    if (rows.length === 0) {
      return NextResponse.json({ error: "Node not found" }, { status: 404 })
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
  { params }: { params: Promise<{ nodeId: string }> }
) {
  const { nodeId } = await params
  const client = await pool.connect()
  try {
    await client.query("DELETE FROM nodes WHERE id=$1", [nodeId])
    return NextResponse.json({ success: true })
  } catch {
    return NextResponse.json({ error: "DB error" }, { status: 500 })
  } finally {
    client.release()
  }
}
