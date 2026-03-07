import etcd from "@/lib/etcd"
import { NextResponse } from "next/server"

const key = (agentId: string) =>
  `/config/collect_agent/${agentId}/threshold_rules`

// GET /api/etcd/agents/[agentId]/threshold-rules
// Returns the current threshold rules object for a collect agent.
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ agentId: string }> }
) {
  const { agentId } = await params
  try {
    const raw = await etcd.get(key(agentId)).string()
    if (raw === null) {
      return NextResponse.json({ error: "Agent not found in etcd" }, { status: 404 })
    }
    return NextResponse.json({ agentId, threshold_rules: JSON.parse(raw) })
  } catch {
    return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
  }
}

// PUT /api/etcd/agents/[agentId]/threshold-rules
// Replaces the full threshold_rules object for a collect agent.
// Body: {
//   cpu_usage_percent?:           { max: number }
//   memory_usage_percent?:        { max: number }
//   gpu_max_temperature_celsius?: { max: number }
//   gpu_max_power_watts?:         { max: number }
//   gpu_max_utilization_percent?: { max: number }
// }
export async function PUT(
  req: Request,
  { params }: { params: Promise<{ agentId: string }> }
) {
  const { agentId } = await params
  const body = await req.json()
  try {
    await etcd.put(key(agentId)).value(JSON.stringify(body))
    return NextResponse.json({ agentId, threshold_rules: body })
  } catch {
    return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
  }
}
