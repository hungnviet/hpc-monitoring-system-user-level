"use client"
import { useState } from "react"
import { UsageChart } from "@/components/analytics/UsageChart"
import { Button } from "@/components/ui/Button"

const EXAMPLES = [
  "Show GPU usage for all users in the last 24 hours",
  "Compare CPU usage between alice and bob",
  "Plot memory consumption trend for the ML team",
]

interface GeneratedChart {
  title: string
  series: { name: string; data: { timestamp: string; value: number }[] }[]
  chartType: "line" | "bar"
  prompt: string
}

export default function AiChartPage() {
  const [prompt, setPrompt] = useState("")
  const [chart, setChart] = useState<GeneratedChart | null>(null)
  const [loading, setLoading] = useState(false)

  async function generate() {
    if (!prompt.trim()) return
    setLoading(true)
    try {
      const res = await fetch("/api/analytics/ai-chart", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt }),
      })
      const result = await res.json()
      setChart({
        title: `${result.resource.toUpperCase()} Usage — AI Generated`,
        series: [{ name: result.resource, data: result.data.map((d: { t: string; value: number }) => ({ timestamp: d.t, value: d.value })) }],
        chartType: result.chartType,
        prompt,
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-[#e6edf3]">AI Chart Generator</h1>
        <p className="text-sm text-[#8b949e] mt-0.5">Describe what you want to visualize in natural language</p>
      </div>

      {/* Prompt input */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
        <div className="flex gap-3">
          <input
            value={prompt}
            onChange={e => setPrompt(e.target.value)}
            onKeyDown={e => e.key === "Enter" && generate()}
            placeholder="e.g. Show GPU usage for all users in the last 24 hours…"
            className="flex-1 bg-[#0d1117] border border-[#30363d] rounded-md px-4 py-2.5 text-sm text-[#e6edf3] placeholder-[#6e7681] focus:outline-none focus:ring-1 focus:ring-[#58a6ff]"
          />
          <Button onClick={generate} loading={loading} disabled={!prompt.trim()}>
            Generate
          </Button>
        </div>

        {/* Example prompts */}
        <div className="mt-3">
          <p className="text-xs text-[#6e7681] mb-2">Try an example:</p>
          <div className="flex flex-wrap gap-2">
            {EXAMPLES.map(ex => (
              <button key={ex} onClick={() => setPrompt(ex)}
                className="text-xs px-3 py-1.5 rounded-full border border-[#30363d] text-[#8b949e] hover:border-[#58a6ff] hover:text-[#58a6ff] transition-colors">
                {ex}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-8 flex flex-col items-center gap-3">
          <div className="w-8 h-8 rounded-full border-2 border-[#58a6ff] border-t-transparent animate-spin" />
          <p className="text-sm text-[#8b949e]">Parsing intent and generating chart…</p>
        </div>
      )}

      {/* Chart result */}
      {!loading && chart && (
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5 space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-sm font-semibold text-[#e6edf3]">{chart.title}</p>
              <p className="text-xs text-[#6e7681] mt-0.5 italic">&ldquo;{chart.prompt}&rdquo;</p>
            </div>
            <span className="text-xs bg-[#1a3c2b] text-[#3fb950] border border-[#2a5a3a] px-2 py-0.5 rounded-full">AI Generated</span>
          </div>
          <UsageChart series={chart.series} chartType={chart.chartType} height={300} />
        </div>
      )}
    </div>
  )
}
