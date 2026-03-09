"use client"
import { useState } from "react"

interface GrafanaPanelProps {
  src?: string        // full Grafana embed URL; if empty, shows placeholder
  height?: number
}

export function GrafanaPanel({ src, height = 220 }: GrafanaPanelProps) {
  const [loaded, setLoaded] = useState(false)

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
      <div style={{ height }} className="relative">
        {src ? (
          <>
            {!loaded && (
              <div className="absolute inset-0 flex items-center justify-center bg-[#0d1117]">
                <div className="animate-pulse flex flex-col items-center gap-2">
                  <div className="w-8 h-8 rounded-full bg-[#30363d]" />
                  <div className="text-xs text-[#6e7681]">Loading panel…</div>
                </div>
              </div>
            )}
            <iframe
              src={src}
              width="100%"
              height={height}
              frameBorder="0"
              onLoad={() => setLoaded(true)}
              className="block"
            />
          </>
        ) : (
          <div className="flex flex-col items-center justify-center h-full gap-3 bg-[#0d1117]">
            <svg className="w-8 h-8 text-[#30363d]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
            <div className="text-center">
              <p className="text-xs text-[#6e7681]">Grafana panel</p>
              <p className="text-xs text-[#6e7681] mt-0.5">Configure <code className="text-[#58a6ff]">GRAFANA_BASE_URL</code></p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
