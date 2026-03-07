import etcd from "@/lib/etcd"
import { NextResponse } from "next/server"

const AGENT_PREFIX = "/config/collect_agent/"

function parseAgents(kv: Record<string, string>) {
  const agents: Record<string, Record<string, string>> = {}
  for (const [key, value] of Object.entries(kv)) {
    const relative = key.slice(AGENT_PREFIX.length) // "collect_agent_1/kafka_topic"
    const slash = relative.indexOf("/")
    if (slash === -1) continue
    const agentId = relative.slice(0, slash)
    const field = relative.slice(slash + 1)
    if (!agents[agentId]) agents[agentId] = { agentId }
    agents[agentId][field] = value
  }
  return Object.values(agents)
}

// GET /api/etcd/agents
// Returns all collect agents stored in etcd with their current config.
export async function GET() {
  try {
    const kv = await etcd.getAll().prefix(AGENT_PREFIX).strings()
    return NextResponse.json(parseAgents(kv))
  } catch {
    return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
  }
}

// POST /api/etcd/agents
// Creates a new collect agent config in etcd.
// Body: { agentId, kafka_brokers, kafka_topic?, grpc_port?, threshold_rules? }
export async function POST(req: Request) {
  try {
    const body = await req.json()
    const {
      agentId,
      kafka_brokers,
      kafka_topic = "monitoring_metrics",
      grpc_port = "50051",
      threshold_rules = {
        cpu_usage_percent: { max: 90 },
        memory_usage_percent: { max: 85 },
        gpu_max_temperature_celsius: { max: 85 },
        gpu_max_power_watts: { max: 300 },
        gpu_max_utilization_percent: { max: 95 },
      },
    } = body

    if (!agentId || !kafka_brokers) {
      return NextResponse.json(
        { error: "agentId and kafka_brokers are required" },
        { status: 400 }
      )
    }

    const base = `${AGENT_PREFIX}${agentId}`
    const brokersStr = Array.isArray(kafka_brokers)
      ? JSON.stringify(kafka_brokers)
      : kafka_brokers

    await Promise.all([
      etcd.put(`${base}/kafka_brokers`).value(brokersStr),
      etcd.put(`${base}/kafka_topic`).value(kafka_topic),
      etcd.put(`${base}/grpc_port`).value(String(grpc_port)),
      etcd.put(`${base}/threshold_rules`).value(
        typeof threshold_rules === "string"
          ? threshold_rules
          : JSON.stringify(threshold_rules)
      ),
    ])

    return NextResponse.json(
      { agentId, kafka_brokers, kafka_topic, grpc_port, threshold_rules },
      { status: 201 }
    )
  } catch {
    return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
  }
}
