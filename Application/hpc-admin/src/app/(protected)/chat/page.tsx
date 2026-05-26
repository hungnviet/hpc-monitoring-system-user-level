"use client"
import { useState, useRef, useEffect } from "react"
import type { ChatMessage, Citation } from "@/types"

const SUPPORT_URL = process.env.NEXT_PUBLIC_AI_SUPPORT_URL!

const INITIAL_MESSAGES: ChatMessage[] = [
  {
    id: "0",
    role: "assistant",
    content: "Hi! I'm the HPC monitoring assistant. I can help you with dashboard navigation, metric explanations, and troubleshooting. What would you like to know?",
    timestamp: new Date().toISOString(),
  },
]

const SUGGESTIONS = ["Explain for me how system work?", "How do alerts work?", "Which data i can retrieve from that tool", "How to use Grafana panels?"]

function Citations({ citations }: { citations: Citation[] }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="mt-2 border-t border-[#30363d] pt-2">
      <button
        onClick={() => setOpen(v => !v)}
        className="flex items-center gap-1 text-xs text-[#8b949e] hover:text-[#58a6ff] transition-colors"
      >
        <svg
          className={`w-3 h-3 transition-transform ${open ? "rotate-180" : ""}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
        {citations.length} source{citations.length !== 1 ? "s" : ""}
      </button>
      {open && (
        <ul className="mt-1.5 space-y-1">
          {citations.map(c => (
            <li key={c.chunk_id} className="text-xs text-[#8b949e]">
              <span className="text-[#58a6ff]">p.{c.page}</span>
              {" — "}
              {c.section_path[c.section_path.length - 1]}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function MessageBubble({ msg }: { msg: ChatMessage }) {
  const isUser = msg.role === "user"
  const isTyping = msg.streaming && msg.content === ""

  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"} gap-2`}>
      {!isUser && (
        <div className="w-7 h-7 rounded-full bg-[#1f6feb] flex items-center justify-center shrink-0 mt-0.5">
          <svg className="w-3.5 h-3.5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
          </svg>
        </div>
      )}
      <div className={`max-w-[80%] rounded-xl px-4 py-2.5 text-sm ${
        isUser
          ? "bg-[#1f6feb] text-white rounded-br-sm"
          : "bg-[#1c2128] border border-[#30363d] rounded-bl-sm"
      } ${msg.error ? "text-[#f85149]" : isUser ? "" : "text-[#e6edf3]"}`}>
        {isTyping ? (
          <div className="flex gap-1 items-center py-0.5">
            {[0, 1, 2].map(i => (
              <div key={i} className="w-1.5 h-1.5 rounded-full bg-[#8b949e] animate-bounce" style={{ animationDelay: `${i * 150}ms` }} />
            ))}
          </div>
        ) : (
          <>
            <span className="whitespace-pre-wrap break-words">{msg.content}</span>
            {msg.streaming && <span className="inline-block w-0.5 h-3.5 bg-[#e6edf3] ml-0.5 animate-pulse align-middle" />}
            {!msg.streaming && msg.citations && msg.citations.length > 0 && (
              <Citations citations={msg.citations} />
            )}
          </>
        )}
      </div>
    </div>
  )
}

export default function ChatPage() {
  const [messages, setMessages] = useState<ChatMessage[]>(INITIAL_MESSAGES)
  const [input, setInput] = useState("")
  const bottomRef = useRef<HTMLDivElement>(null)

  const isStreaming = messages.some(m => m.streaming)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [messages])

  async function send(text?: string) {
    const content = (text ?? input).trim()
    if (!content || isStreaming) return
    setInput("")

    const userMsg: ChatMessage = {
      id: String(Date.now()),
      role: "user",
      content,
      timestamp: new Date().toISOString(),
    }
    const streamId = String(Date.now() + 1)
    const placeholder: ChatMessage = {
      id: streamId,
      role: "assistant",
      content: "",
      timestamp: new Date().toISOString(),
      citations: [],
      streaming: true,
    }

    setMessages(prev => [...prev, userMsg, placeholder])

    try {
      const res = await fetch(SUPPORT_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: content }),
      })

      if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`)

      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ""

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split("\n")
        buffer = lines.pop() ?? ""

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue
          let packet: { type: string; citations?: Citation[]; text?: string; message?: string }
          try {
            packet = JSON.parse(line.slice(6))
          } catch {
            continue
          }

          if (packet.type === "citation") {
            setMessages(prev => prev.map(m =>
              m.id === streamId ? { ...m, citations: packet.citations ?? [] } : m
            ))
          } else if (packet.type === "token") {
            setMessages(prev => prev.map(m =>
              m.id === streamId ? { ...m, content: m.content + (packet.text ?? "") } : m
            ))
          } else if (packet.type === "done") {
            setMessages(prev => prev.map(m =>
              m.id === streamId ? { ...m, streaming: false } : m
            ))
          } else if (packet.type === "error") {
            setMessages(prev => prev.map(m =>
              m.id === streamId
                ? { ...m, content: "The server currently has a problem, please try again.", streaming: false, error: true }
                : m
            ))
          }
        }
      }
    } catch {
      setMessages(prev => prev.map(m =>
        m.id === streamId
          ? { ...m, content: "The server currently has a problem, please try again.", streaming: false, error: true }
          : m
      ))
    }
  }

  return (
    <div className="p-6 h-[calc(100vh-3.5rem)] flex flex-col">
      <div className="mb-4">
        <h1 className="text-lg font-semibold text-[#e6edf3]">Chatbot Assistant</h1>
        <p className="text-sm text-[#8b949e]">Ask questions about dashboards, metrics, and troubleshooting</p>
      </div>

      <div className="flex-1 bg-[#161b22] border border-[#30363d] rounded-xl flex flex-col overflow-hidden">
        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {messages.map(m => <MessageBubble key={m.id} msg={m} />)}
          <div ref={bottomRef} />
        </div>

        {/* Suggestions */}
        <div className="px-5 py-2 border-t border-[#21262d] flex gap-2 flex-wrap">
          {SUGGESTIONS.map(s => (
            <button key={s} onClick={() => send(s)} disabled={isStreaming}
              className="text-xs px-3 py-1.5 rounded-full border border-[#30363d] text-[#8b949e] hover:border-[#58a6ff] hover:text-[#58a6ff] disabled:opacity-40 transition-colors">
              {s}
            </button>
          ))}
        </div>

        {/* Input */}
        <div className="p-4 border-t border-[#30363d] flex gap-3">
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === "Enter" && !e.shiftKey && send()}
            placeholder="Ask a question…"
            disabled={isStreaming}
            className="flex-1 bg-[#0d1117] border border-[#30363d] rounded-lg px-4 py-2.5 text-sm text-[#e6edf3] placeholder-[#6e7681] focus:outline-none focus:ring-1 focus:ring-[#58a6ff] disabled:opacity-50"
          />
          <button
            onClick={() => send()}
            disabled={!input.trim() || isStreaming}
            className="px-4 py-2.5 bg-[#1f6feb] hover:bg-[#388bfd] disabled:opacity-50 text-white rounded-lg transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
            </svg>
          </button>
        </div>
      </div>
    </div>
  )
}
