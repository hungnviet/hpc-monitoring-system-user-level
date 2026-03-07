import { NextResponse } from "next/server"

// POST /api/analytics/ai-chart
// Body: { prompt: string }
// Stub: parses prompt keywords and returns a mock chart config
export async function POST(req: Request) {
  const { prompt } = await req.json()
  const lower = (prompt as string).toLowerCase()

  const resource = lower.includes("gpu")
    ? "gpu"
    : lower.includes("mem")
    ? "mem"
    : lower.includes("disk")
    ? "disk"
    : lower.includes("net")
    ? "net"
    : "cpu"

  const chartType = lower.includes("bar")
    ? "bar"
    : lower.includes("stacked")
    ? "stacked"
    : "line"

  return NextResponse.json({
    title: `${resource.toUpperCase()} usage — AI generated`,
    resource,
    chartType,
    data: Array.from({ length: 12 }, (_, i) => ({
      t: new Date(Date.now() - (11 - i) * 3600_000).toISOString(),
      value: Math.round(20 + Math.random() * 60),
    })),
  })
}
