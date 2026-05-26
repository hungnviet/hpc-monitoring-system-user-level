"use client"
import { useState } from "react"
import { GrafanaPanel } from "@/components/dashboard/GrafanaPanel"
import { Button } from "@/components/ui/Button"

const EXAMPLES = [
  "Show GPU memory usage",
  "Show CPU usage for all nodes",
  "Plot memory consumption over time",
  "Give me the line chart show the cpu  memory usage of node 2 and node 3 in last 2 days"
]

interface AiResult {
  reasoning: string
  pipeline: string
  svgMarkup: string | null
  embedUrl: string | null
  prompt: string
}

export default function AiChartPage() {
  const [prompt, setPrompt] = useState("")
  const [result, setResult] = useState<AiResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [saved, setSaved] = useState(false)

  async function generate() {
    if (!prompt.trim()) return
    setLoading(true)
    setSaved(false)
    setResult(null)
    try {
      const res = await fetch(process.env.NEXT_PUBLIC_AI_VISUALIZE_URL!, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: prompt }),
      })
      const data = await res.json()
      const rawUrl: string | null = data.panel_embed_url ?? null
      const embedUrl = rawUrl
        ? rawUrl.replace(/^https?:\/\/[^/]+/, (match) => {
            const port = new URL(match).port
            return port ? `http://localhost:${port}` : "http://localhost"
          })
        : null
      setResult({
        reasoning: data.reasoning ?? "",
        pipeline: data.pipeline ?? "unknown",
        svgMarkup: data.code_render_svg ?? null,
        embedUrl,
        prompt,
      })
    } finally {
      setLoading(false)
    }
  }

  function handleDiscard() {
    setResult(null)
    setPrompt("")
    setSaved(false)
  }

  function handleSave() {
    setSaved(true)
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
            placeholder="e.g. Show GPU memory usage…"
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
          <p className="text-sm text-[#8b949e]">Parsing intent and generating visualization…</p>
        </div>
      )}

      {!loading && result && (
        <>
          {/* Reasoning card */}
          <div className="bg-[#161b22] border border-[#30363d] border-l-4 border-l-[#58a6ff] rounded-xl p-5">
            <div className="flex items-center justify-between mb-2">
              <p className="text-xs font-semibold text-[#e6edf3] uppercase tracking-wide">Reasoning</p>
              <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${
                result.pipeline === "realtime"
                  ? "bg-[#1a3c2b] text-[#3fb950] border-[#2a5a3a]"
                  : "bg-[#2d1f5e] text-[#a78bfa] border-[#4c3a8a]"
              }`}>
                {result.pipeline}
              </span>
            </div>
            <p className="text-sm text-[#8b949e] leading-relaxed">{result.reasoning}</p>
          </div>

          {/* Result card */}
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-[#e6edf3]">Visualization Result</p>
              <span className="text-xs bg-[#1a3c2b] text-[#3fb950] border border-[#2a5a3a] px-2 py-0.5 rounded-full">AI Generated</span>
            </div>

            <p className="text-xs text-[#6e7681] italic">&ldquo;{result.prompt}&rdquo;</p>

            <div className="border-t border-[#30363d] pt-4">
              {result.svgMarkup ? (
                <div
                  className="w-full overflow-auto bg-[#0d1117] rounded-lg p-4 flex justify-center"
                  dangerouslySetInnerHTML={{ __html: result.svgMarkup }}
                />
              ) : result.embedUrl ? (
                <GrafanaPanel src={result.embedUrl} height={360} />
              ) : (
                <p className="text-sm text-[#8b949e]">No visualization returned.</p>
              )}
            </div>

            {/* Save / Discard */}
            <div className="border-t border-[#30363d] pt-4">
              {saved ? (
                <div className="flex items-center gap-2 text-sm text-[#3fb950]">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  Visualization saved
                </div>
              ) : (
                <div className="flex items-center justify-between">
                  <button
                    onClick={handleDiscard}
                    className="text-sm px-4 py-2 rounded-md border border-[#30363d] text-[#8b949e] hover:border-[#f85149] hover:text-[#f85149] transition-colors">
                    Discard
                  </button>
                  <button
                    onClick={handleSave}
                    className="text-sm px-4 py-2 rounded-md bg-[#1f6feb] text-white hover:bg-[#388bfd] transition-colors">
                    Save
                  </button>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
