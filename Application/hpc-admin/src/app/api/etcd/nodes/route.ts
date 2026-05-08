import etcd from "@/lib/etcd"
import { NextResponse } from "next/server"

const NODE_PREFIX = "/config/compute_node/"
const HEARTBEAT_PREFIX = "/nodes/"

// Parse a flat KV map like:
//   { "/config/compute_node/node_id_1/window": "5.0", ... }
// into a list of structured node config objects.
function parseNodes(kv: Record<string, string>) {
  const nodes: Record<string, Record<string, string>> = {}
  for (const [key, value] of Object.entries(kv)) {
    const relative = key.slice(NODE_PREFIX.length) // "node_id_1/window"
    const slash = relative.indexOf("/")
    if (slash === -1) continue
    const nodeId = relative.slice(0, slash)
    const field = relative.slice(slash + 1)
    if (!nodes[nodeId]) nodes[nodeId] = { nodeId }
    nodes[nodeId][field] = value
  }
  return Object.values(nodes)
}

// Parse heartbeat keys like /nodes/node_id_1/heartbeat into a nodeId → heartbeat map.
function parseHeartbeats(kv: Record<string, string>): Record<string, { timestamp: number; status: string; collection_active: boolean }> {
  const out: Record<string, { timestamp: number; status: string; collection_active: boolean }> = {}
  for (const [key, value] of Object.entries(kv)) {
    const relative = key.slice(HEARTBEAT_PREFIX.length) // "node_id_1/heartbeat"
    const slash = relative.indexOf("/")
    if (slash === -1) continue
    const nodeId = relative.slice(0, slash)
    const field  = relative.slice(slash + 1)
    if (field !== "heartbeat") continue
    try { out[nodeId] = JSON.parse(value) } catch { /* ignore malformed */ }
  }
  return out
}

// GET /api/etcd/nodes
// Returns all compute nodes stored in etcd with live status derived from heartbeat data.
export async function GET() {
  try {
    const [configKv, heartbeatKv] = await Promise.all([
      etcd.getAll().prefix(NODE_PREFIX).strings(),
      etcd.getAll().prefix(HEARTBEAT_PREFIX).strings(),
    ])
    const nodes      = parseNodes(configKv)
    const heartbeats = parseHeartbeats(heartbeatKv)
    const nowSec     = Math.floor(Date.now() / 1000)

    const result = nodes.map(node => {
      const interval  = parseFloat(node.heartbeat_interval ?? "20")
      const threshold = isNaN(interval) ? 60 : interval * 3
      const hb        = heartbeats[node.nodeId]
      const isAlive   =
        hb !== undefined &&
        hb.status === "alive" &&
        (nowSec - hb.timestamp) <= threshold
      return { ...node, status: isAlive ? "running" : "stopped" }
    })

    return NextResponse.json(result)
  } catch (e) {
    console.error("[/api/etcd/nodes]", e)
    return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
  }
}

// POST /api/etcd/nodes
// Creates a new compute node config in etcd.
// Body: { nodeId, target_collect_agent, window?, heartbeat_interval? }
export async function POST(req: Request) {
  try {
    const body = await req.json()
    const {
      nodeId,
      target_collect_agent,
      window = "5.0",
      heartbeat_interval = "10.0",
    } = body

    if (!nodeId || !target_collect_agent) {
      return NextResponse.json(
        { error: "nodeId and target_collect_agent are required" },
        { status: 400 }
      )
    }

    const base = `${NODE_PREFIX}${nodeId}`
    await Promise.all([
      etcd.put(`${base}/target_collect_agent`).value(target_collect_agent),
      etcd.put(`${base}/window`).value(String(window)),
      etcd.put(`${base}/heartbeat_interval`).value(String(heartbeat_interval)),
      etcd.put(`${base}/status`).value("stopped"),
    ])

    return NextResponse.json(
      { nodeId, target_collect_agent, window, heartbeat_interval, status: "stopped" },
      { status: 201 }
    )
  } catch (e) {
    console.error("[/api/etcd/nodes]", e)
    return NextResponse.json({ error: "etcd unavailable" }, { status: 503 })
  }
}
