"use client"
import { useState } from "react"

interface GrafanaPanelProps {
  src?: string         // full Grafana embed URL; if empty, shows placeholder
  height?: number      // explicit pixel height; if omitted, fills parent (h-full)
  className?: string   // forwarded to the outer wrapper (e.g. CSS-grid placement)
  title?: string       // optional small label above the panel
}

export function GrafanaPanel({ src, height, className, title }: GrafanaPanelProps) {
  const [loaded, setLoaded] = useState(false)
  const fixed = typeof height === "number"

  return (
    <div
      className={`bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden ${fixed ? "" : "h-full"} ${className ?? ""}`}
      style={fixed ? { height } : undefined}
    >
      {title && (
        <div className="px-3 pt-2 pb-1 text-[10px] font-medium uppercase tracking-wide text-[#8b949e] truncate">
          {title}
        </div>
      )}
      <div className={`relative w-full ${title ? "h-[calc(100%-24px)]" : "h-full"}`}>
        {src ? (
          <>
            {!loaded && (
              <div className="absolute inset-0 flex items-center justify-center bg-[#0d1117]">
                <div className="animate-pulse flex flex-col items-center gap-2">
                  <div className="w-6 h-6 rounded-full bg-[#30363d]" />
                  <div className="text-[10px] text-[#6e7681]">Loading panel…</div>
                </div>
              </div>
            )}
            <iframe
              src={src}
              onLoad={() => setLoaded(true)}
              className="block w-full h-full border-0"
            />
          </>
        ) : (
          <div className="flex flex-col items-center justify-center h-full gap-2 bg-[#0d1117]">
            <svg className="w-6 h-6 text-[#30363d]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
            <div className="text-center">
              <p className="text-[10px] text-[#6e7681]">Grafana panel</p>
              <p className="text-[10px] text-[#6e7681] mt-0.5">Configure <code className="text-[#58a6ff]">GRAFANA_BASE_URL</code></p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
