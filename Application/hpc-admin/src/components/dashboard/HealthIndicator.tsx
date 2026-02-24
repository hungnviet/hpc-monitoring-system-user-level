interface HealthIndicatorProps {
  activeNodes: number
  totalNodes: number
}

export function HealthIndicator({ activeNodes, totalNodes }: HealthIndicatorProps) {
  const ratio = activeNodes / totalNodes
  const health = ratio >= 0.9 ? "Healthy" : ratio >= 0.6 ? "Degraded" : "Critical"
  const color  = ratio >= 0.9 ? "text-[#3fb950]" : ratio >= 0.6 ? "text-[#d29922]" : "text-[#f85149]"
  const bg     = ratio >= 0.9 ? "bg-[#1a3c2b]"   : ratio >= 0.6 ? "bg-[#3d2e05]"   : "bg-[#3c1a1a]"
  const border = ratio >= 0.9 ? "border-[#2a5a3a]": ratio >= 0.6 ? "border-[#5a4310]":"border-[#5a2525]"

  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full border ${bg} ${border}`}>
      <span className={`w-2 h-2 rounded-full ${color.replace("text", "bg")} animate-pulse`} />
      <span className={`text-sm font-semibold ${color}`}>{health}</span>
      <span className="text-xs text-[#6e7681]">{activeNodes}/{totalNodes} nodes</span>
    </div>
  )
}
