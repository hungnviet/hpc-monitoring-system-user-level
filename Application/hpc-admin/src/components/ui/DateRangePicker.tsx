"use client"

interface DateRangePickerProps {
  from: string
  to: string
  onFromChange: (iso: string) => void
  onToChange: (iso: string) => void
}

const PRESETS = [
  { label: "Last 24h", ms: 86_400_000 },
  { label: "Last 7 days", ms: 604_800_000 },
  { label: "Last 30 days", ms: 2_592_000_000 },
]

function toLocal(iso: string): string {
  if (!iso) return ""
  const d = new Date(iso)
  const off = d.getTimezoneOffset()
  const local = new Date(d.getTime() - off * 60_000)
  return local.toISOString().slice(0, 16)
}

function toIso(local: string): string {
  if (!local) return ""
  return new Date(local).toISOString()
}

function CalendarIcon() {
  return (
    <svg className="w-4 h-4 text-[#6e7681]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
    </svg>
  )
}

function ArrowIcon() {
  return (
    <svg className="w-5 h-5 text-[#6e7681]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
    </svg>
  )
}

export function DateRangePicker({ from, to, onFromChange, onToChange }: DateRangePickerProps) {
  const applyPreset = (ms: number) => {
    const now = new Date()
    onToChange(now.toISOString())
    onFromChange(new Date(now.getTime() - ms).toISOString())
  }

  const resetToNow = () => {
    const now = new Date()
    onToChange(now.toISOString())
  }

  return (
    <div className="space-y-3">
      {/* Preset buttons */}
      <div className="flex items-center gap-2">
        <span className="text-[10px] font-medium text-[#6e7681] uppercase tracking-wide mr-1">Quick select:</span>
        {PRESETS.map(preset => (
          <button
            key={preset.label}
            type="button"
            onClick={() => applyPreset(preset.ms)}
            className="px-2.5 py-1 text-[11px] rounded-md border border-[#30363d] text-[#8b949e] hover:border-[#58a6ff] hover:text-[#58a6ff] transition-colors cursor-pointer"
          >
            {preset.label}
          </button>
        ))}
      </div>

      {/* Date inputs */}
      <div className="flex items-end gap-3">
        <label className="flex flex-col gap-1.5 flex-1 max-w-[220px]">
          <span className="text-[10px] font-medium text-[#8b949e] uppercase tracking-wide flex items-center gap-1.5">
            <CalendarIcon />
            From
          </span>
          <input
            type="datetime-local"
            value={toLocal(from)}
            onChange={e => onFromChange(toIso(e.target.value))}
            className="w-full rounded-lg border border-[#30363d] bg-[#0d1117] px-3 py-2 text-sm text-[#e6edf3] outline-none focus:border-[#58a6ff] focus:ring-1 focus:ring-[#58a6ff]/20 transition-all"
          />
        </label>

        <div className="pb-2.5">
          <ArrowIcon />
        </div>

        <label className="flex flex-col gap-1.5 flex-1 max-w-[220px]">
          <span className="text-[10px] font-medium text-[#8b949e] uppercase tracking-wide flex items-center gap-1.5">
            <CalendarIcon />
            To
          </span>
          <input
            type="datetime-local"
            value={toLocal(to)}
            onChange={e => onToChange(toIso(e.target.value))}
            className="w-full rounded-lg border border-[#30363d] bg-[#0d1117] px-3 py-2 text-sm text-[#e6edf3] outline-none focus:border-[#58a6ff] focus:ring-1 focus:ring-[#58a6ff]/20 transition-all"
          />
        </label>

        <button
          type="button"
          onClick={resetToNow}
          className="pb-2 text-[11px] text-[#6e7681] hover:text-[#58a6ff] transition-colors cursor-pointer whitespace-nowrap"
          title="Set end time to now"
        >
          Set to now
        </button>
      </div>
    </div>
  )
}
