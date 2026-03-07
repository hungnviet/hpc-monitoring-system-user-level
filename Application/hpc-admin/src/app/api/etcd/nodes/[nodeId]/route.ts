import etcd from "@/lib/etcd"
import { NextResponse } from "next/server"

const base = (nodeId: string) => `/config/compute_node/${nodeId}`

// GET /api/etcd/nodes/[nodeId]
// Returns all config fields for one compute node.
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ nodeId: string }> }
) {
  const { nodeId } = await params
  try {
    const prefix = `${base(nodeId)}/`
    const kv = await etcd.getAll().prefix(prefix).strings()
    if (Object.keys(kv).length === 0) {
      return NextResponse.json({ error: "Node not found in etcd" }, { status: 404 })
    }
    const config: Record<string, string> = { nodeId }
    for (const [key, value] of Object.entries(kv)) {
      const field = key.slice(prefix.length)
      config[field] = value
    }
    return NextResponse.json(config)
  } catch {
    return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
  }
}

// PUT /api/etcd/nodes/[nodeId]
// Updates editable config fields: target_collect_agent, window, heartbeat_interval.
// Does NOT change status — use the /status sub-route for that.
export async function PUT(
  req: Request,
  { params }: { params: Promise<{ nodeId: string }> }
) {
  const { nodeId } = await params
  const body = await req.json()
  const { target_collect_agent, window, heartbeat_interval } = body
  try {
    await Promise.all([
      ...(target_collect_agent !== undefined
        ? [etcd.put(`${base(nodeId)}/target_collect_agent`).value(String(target_collect_agent))]
        : []),
      ...(window !== undefined
        ? [etcd.put(`${base(nodeId)}/window`).value(String(window))]
        : []),
      ...(heartbeat_interval !== undefined
        ? [etcd.put(`${base(nodeId)}/heartbeat_interval`).value(String(heartbeat_interval))]
        : []),
    ])

    return NextResponse.json({ nodeId, target_collect_agent, window, heartbeat_interval })
  } catch {
    return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
  }
}

// DELETE /api/etcd/nodes/[nodeId]
// Removes all config keys for this node from etcd.
export async function DELETE(
  _req: Request,
  { params }: { params: Promise<{ nodeId: string }> }
) {
  const { nodeId } = await params
  try {
    await etcd.delete().prefix(`${base(nodeId)}/`)
    return NextResponse.json({ success: true })
  } catch {
    return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
  }
}
