import { NextResponse } from "next/server"

// POST /api/chat
// Body: { message: string }
// Stub: returns canned responses based on keywords
export async function POST(req: Request) {
  const { message } = await req.json()
  const lower = (message as string).toLowerCase()

  let reply: string

  if (lower.includes("cpu")) {
    reply =
      "Current CPU utilization across the cluster is averaging 62%. Node compute-03 is the highest at 89%. Consider redistributing workloads."
  } else if (lower.includes("gpu")) {
    reply =
      "GPU cluster is running at 74% average utilization. All 4 A100 nodes are healthy. Temperature readings are nominal (max 78°C)."
  } else if (lower.includes("mem") || lower.includes("memory")) {
    reply =
      "Memory usage is at 55% cluster-wide. No nodes are near their limits. Peak usage occurred yesterday at 14:00 UTC."
  } else if (lower.includes("disk")) {
    reply =
      "Disk usage is at 41% average. Node storage-01 is at 78% — consider archiving old job data."
  } else if (lower.includes("alert") || lower.includes("notification")) {
    reply =
      "There are 3 active alerts: 2 warnings on cpu-cluster (high CPU) and 1 info on gpu-cluster (temperature above 75°C)."
  } else if (lower.includes("node") || lower.includes("status")) {
    reply =
      "All 8 compute nodes are currently active. Last check was 5 seconds ago. No nodes are reported as down."
  } else if (lower.includes("user") || lower.includes("job")) {
    reply =
      "Top resource consumers in the last 24h: user42 (1,240 CPU-hours), user17 (890 CPU-hours), user99 (650 CPU-hours)."
  } else {
    reply =
      "I can help with cluster status, resource utilization (CPU/GPU/memory/disk), active alerts, and user job analytics. What would you like to know?"
  }

  return NextResponse.json({
    id: crypto.randomUUID(),
    role: "assistant",
    content: reply,
    timestamp: new Date().toISOString(),
  })
}
