import etcd from "@/lib/etcd"
import { NextResponse } from "next/server"

const base = (agentId: string) => `/config/collect_agent/${agentId}`

// GET /api/etcd/agents/[agentId]
// Returns all config fields for one collect agent.
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ agentId: string }> }
) {
  const { agentId } = await params
  try {
    const prefix = `${base(agentId)}/`
    const kv = await etcd.getAll().prefix(prefix).strings()
    if (Object.keys(kv).length === 0) {
      return NextResponse.json({ error: "Agent not found in etcd" }, { status: 404 })
    }
    const config: Record<string, unknown> = { agentId }
    for (const [key, value] of Object.entries(kv)) {
      const field = key.slice(prefix.length)
      // Parse JSON fields
      if (field === "threshold_rules" || field === "kafka_brokers") {
        try { config[field] = JSON.parse(value) } catch { config[field] = value }
      } else {
        config[field] = value
      }
    }
    return NextResponse.json(config)
  } catch {
    return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
  }
}

// PUT /api/etcd/agents/[agentId]
// Updates editable fields: kafka_brokers, kafka_topic, grpc_port.
// To update threshold_rules use the /threshold-rules sub-route.
export async function PUT(
  req: Request,
  { params }: { params: Promise<{ agentId: string }> }
) {
  const { agentId } = await params
  const body = await req.json()
  const { kafka_brokers, kafka_topic, grpc_port } = body
  try {
    const brokersVal = kafka_brokers !== undefined
      ? (Array.isArray(kafka_brokers) ? JSON.stringify(kafka_brokers) : kafka_brokers)
      : undefined

    await Promise.all([
      ...(brokersVal !== undefined
        ? [etcd.put(`${base(agentId)}/kafka_brokers`).value(brokersVal)]
        : []),
      ...(kafka_topic !== undefined
        ? [etcd.put(`${base(agentId)}/kafka_topic`).value(kafka_topic)]
        : []),
      ...(grpc_port !== undefined
        ? [etcd.put(`${base(agentId)}/grpc_port`).value(String(grpc_port))]
        : []),
    ])

    return NextResponse.json({ agentId, kafka_brokers, kafka_topic, grpc_port })
  } catch {
    return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
  }
}

// DELETE /api/etcd/agents/[agentId]
// Removes all config keys for this collect agent from etcd.
export async function DELETE(
  _req: Request,
  { params }: { params: Promise<{ agentId: string }> }
) {
  const { agentId } = await params
  try {
    await etcd.delete().prefix(`${base(agentId)}/`)
    return NextResponse.json({ success: true })
  } catch {
    return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
  }
}
