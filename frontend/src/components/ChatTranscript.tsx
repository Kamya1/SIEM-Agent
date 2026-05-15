import { MitreBadge } from "./MitreBadge";

export type ChatMsg = {
  role: "user" | "assistant";
  content: string;
  meta?: string;
  latencyMs?: number;
  mitre?: string[];
  shield?: "clean" | "pii" | "flagged" | "blocked";
  piiFound?: string[];
  redactionCount?: number;
};

function shieldBadge(shield?: ChatMsg["shield"], piiFound?: string[], redactionCount?: number) {
  if (!shield || shield === "clean") {
    return (
      <span className="mt-2 inline-flex items-center gap-1 text-[10px] text-emerald-400">
        ✓ Clean
      </span>
    );
  }
  if (shield === "pii") {
    return (
      <div className="mt-2 text-[10px] text-amber-300">
        <span>⚠ PII Redacted</span>
        {piiFound && piiFound.length > 0 && (
          <p className="mt-1 text-slate-500">
            {redactionCount ?? 0} replacement(s): {piiFound.join(", ")}
          </p>
        )}
      </div>
    );
  }
  if (shield === "flagged") {
    return <span className="mt-2 inline-flex text-[10px] text-amber-alert">⚠ Flagged</span>;
  }
  return <span className="mt-2 inline-flex text-[10px] text-red-400">✗ Blocked</span>;
}

function latencyClass(ms?: number) {
  if (ms == null) return "text-slate-500";
  if (ms < 1000) return "text-emerald-400";
  if (ms <= 2000) return "text-amber-300";
  return "text-red-400";
}

export function ChatTranscript({ messages, loading }: { messages: ChatMsg[]; loading: boolean }) {
  return (
    <div className="scroll-thin flex-1 space-y-4 overflow-y-auto px-5 py-4">
      {messages.length === 0 && (
        <p className="text-sm text-slate-500">
          No messages yet. Describe an alert or paste log lines — watch latency and MITRE badges on replies.
        </p>
      )}
      {messages.map((m, i) => (
        <div key={`${i}-${m.role}`} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
          <div
            className={`max-w-[92%] rounded-2xl px-4 py-3 text-sm leading-relaxed ${
              m.role === "user"
                ? "bg-cyan-glow/15 text-slate-100 ring-1 ring-cyan-glow/25"
                : "bg-black/35 text-slate-200 ring-1 ring-white/10"
            }`}
          >
            <p className="whitespace-pre-wrap font-sans">{m.content}</p>
            {m.mitre && m.mitre.length > 0 && <MitreBadge techniques={m.mitre} />}
            {m.role === "assistant" && m.latencyMs != null && (
              <p className={`mt-2 text-[10px] font-mono ${latencyClass(m.latencyMs)}`}>
                latency {m.latencyMs.toFixed(0)} ms
              </p>
            )}
            {m.role === "user" && shieldBadge(m.shield, m.piiFound, m.redactionCount)}
            {m.meta && <p className="mt-1 text-[10px] font-mono text-slate-500">{m.meta}</p>}
          </div>
        </div>
      ))}
      {loading && (
        <div className="flex justify-start">
          <div className="rounded-2xl bg-black/35 px-4 py-3 text-sm text-slate-400 ring-1 ring-white/10">
            Thinking…
          </div>
        </div>
      )}
    </div>
  );
}
