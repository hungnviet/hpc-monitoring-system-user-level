import etcd from "@/lib/etcd"
import { NextResponse } from "next/server"

// GET /api/etcd/nodes/[nodeId]/status
// Returns the current status of a compute node.
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ nodeId: string }> }
) {
  const { nodeId } = await params
  try {
    const status = await etcd.get(`/config/compute_node/${nodeId}/status`).string()
    if (status === null) {
      return NextResponse.json({ error: "Node not found in etcd" }, { status: 404 })
    }
    return NextResponse.json({ nodeId, status })
  } catch {
    return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
  }
}

// PUT /api/etcd/nodes/[nodeId]/status
// Sets node status to "running" or "stopped".
// Body: { status: "running" | "stopped" }
export async function PUT(
  req: Request,
  { params }: { params: Promise<{ nodeId: string }> }
) {
  const { nodeId } = await params
  const body = await req.json()
  const { status } = body

  if (status !== "running" && status !== "stopped") {
    return NextResponse.json(
      { error: 'status must be "running" or "stopped"' },
      { status: 400 }
    )
  }

  try {
    await etcd.put(`/config/compute_node/${nodeId}/status`).value(status)
    return NextResponse.json({ nodeId, status })
  } catch {
    return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
  }
}
