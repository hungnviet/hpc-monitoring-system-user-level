"use client"
import { InputHTMLAttributes } from "react"

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string
  error?: string
}

export function Input({ label, error, className = "", id, ...props }: InputProps) {
  const inputId = id ?? label?.toLowerCase().replace(/\s+/g, "-")
  return (
    <div className="flex flex-col gap-1">
      {label && <label htmlFor={inputId} className="text-xs font-medium text-[#8b949e]">{label}</label>}
      <input
        id={inputId}
        {...props}
        className={`bg-[#0d1117] border ${error ? "border-[#f85149]" : "border-[#30363d]"} rounded-md px-3 py-2 text-sm text-[#e6edf3] placeholder-[#6e7681] focus:outline-none focus:ring-1 focus:ring-[#58a6ff] focus:border-[#58a6ff] transition-colors ${className}`}
      />
      {error && <p className="text-xs text-[#f85149]">{error}</p>}
    </div>
  )
}
