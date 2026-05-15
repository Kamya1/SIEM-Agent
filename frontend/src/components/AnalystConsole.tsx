import { useCallback, useEffect, useMemo, useState } from "react";
import { chat, health, resetSession, type HealthInfo, type MemoryMode } from "../api";
import { ChatTranscript, type ChatMsg } from "./ChatTranscript";

const MODES: { id: MemoryMode; label: string; hint: string }[] = [
  { id: "no_memory", label: "No memory", hint: "Stateless — only the current utterance is sent." },
  { id: "short_term", label: "Short-term", hint: "Sliding window (10 turns) + prefs + adaptive compression." },
  { id: "long_term", label: "Long-term", hint: "STM + vector LTM retrieval (cosine, top-3, thresholded)." },
  { id: "hybrid", label: "Hybrid", hint: "STM always; LTM when topic similarity drops or recall cues appear." },
];

const SEVERITY = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

type Props = {
  sessionId: string;
  setSessionId: (id: string) => void;
  healthInfo: HealthInfo | null;
  onHealth: (h: HealthInfo) => void;
};

export function AnalystConsole({ sessionId, setSessionId, healthInfo, onHealth }: Props) {
  const [mode, setMode] = useState<MemoryMode>("short_term");
  const [severity, setSeverity] = useState<(typeof SEVERITY)[number]>("MEDIUM");
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<ChatMsg[]>([]);
  const [lastPreview, setLastPreview] = useState<Record<string, unknown> | null>(null);
  const [warn, setWarn] = useState<string | null>(null);

  useEffect(() => {
    health().then(onHealth).catch(() => null);
  }, [onHealth]);

  const modeLabel = useMemo(() => MODES.find((m) => m.id === mode)?.label ?? mode, [mode]);

  const send = useCallback(async () => {
    const text = input.trim();
    if (!text || loading) return;
    const payload = `[Alert severity: ${severity}] ${text}`;
    setLoading(true);
    setInput("");
    setWarn(null);
    setMessages((m) => [...m, { role: "user", content: payload, shield: "clean" }]);
    try {
      const res = await chat(sessionId, mode, payload);
      if (res.session_id) setSessionId(res.session_id);
      const prev = res.context_preview ?? {};
      const lat = typeof prev.latency_ms === "number" ? prev.latency_ms : undefined;
      setLastPreview(prev);
      if (res.security_warning) setWarn(res.security_warning);
      const ev = res.security_event;
      setMessages((m) => [
        ...m.slice(0, -1),
        {
          role: "user",
          content: payload,
          shield: ev?.shield === "blocked" ? "blocked" : ev?.pii_found?.length ? "pii" : ev?.shield ?? "clean",
          piiFound: ev?.pii_found,
          redactionCount: ev?.redaction_count,
        },
        {
          role: "assistant",
          content: res.reply,
          latencyMs: lat,
          mitre: res.mitre_techniques ?? [],
          shield: ev?.shield ?? "clean",
        },
      ]);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Request failed";
      setMessages((m) => [...m, { role: "assistant", content: `**Error:** ${msg}` }]);
    } finally {
      setLoading(false);
    }
  }, [input, loading, sessionId, mode, severity, setSessionId]);

  const clearSession = async () => {
    await resetSession(sessionId).catch(() => null);
    setMessages([]);
    setLastPreview(null);
    setSessionId(`sess-${crypto.randomUUID().slice(0, 8)}`);
  };

  const exportChat = () => {
    const blob = new Blob([messages.map((m) => `${m.role}: ${m.content}`).join("\n\n")], {
      type: "text/plain",
    });
    const u = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = u;
    a.download = `siem-chat-${sessionId}.txt`;
    a.click();
    URL.revokeObjectURL(u);
  };

  const tokenHint = useMemo(() => {
    const stm = typeof lastPreview?.stm_tokens === "number" ? (lastPreview.stm_tokens as number) : 0;
    return stm + Math.ceil(input.length / 4);
  }, [lastPreview, input]);

  return (
    <div className="grid gap-6 lg:grid-cols-[320px_1fr]">
      <aside className="space-y-4">
        <section className="rounded-2xl border border-white/10 bg-void-50/90 p-5 shadow-panel">
          <h2 className="text-sm font-semibold text-white">Memory mode</h2>
          <div className="mt-4 space-y-3">
            {MODES.map((m) => (
              <label
                key={m.id}
                className={`flex cursor-pointer gap-3 rounded-xl border p-3 transition ${
                  mode === m.id ? "border-cyan-glow/50 bg-cyan-glow/5" : "border-white/10 hover:border-white/20"
                }`}
              >
                <input
                  type="radio"
                  name="mode"
                  className="mt-1 accent-cyan-glow"
                  checked={mode === m.id}
                  onChange={() => setMode(m.id)}
                />
                <div>
                  <p className="text-sm font-medium text-white">{m.label}</p>
                  <p className="text-xs text-slate-400">{m.hint}</p>
                </div>
              </label>
            ))}
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => void clearSession()}
              className="rounded-lg bg-white/10 px-3 py-2 text-xs font-medium text-white hover:bg-white/15"
            >
              Clear session (STM)
            </button>
            <button
              type="button"
              onClick={exportChat}
              className="rounded-lg bg-white/10 px-3 py-2 text-xs font-medium text-white hover:bg-white/15"
            >
              Export chat
            </button>
            <span className="font-mono text-[11px] text-slate-500 self-center">{sessionId}</span>
          </div>
        </section>

        <section className="rounded-2xl border border-white/10 bg-void-50/90 p-5 shadow-panel">
          <h2 className="text-sm font-semibold text-white">Runtime</h2>
          <dl className="mt-3 space-y-2 text-xs font-mono text-slate-300">
            <div className="flex justify-between gap-2">
              <dt>LLM</dt>
              <dd className="text-right text-cyan-glow/90">{healthInfo?.groq_connected ? "groq" : "mock"}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt>Model</dt>
              <dd className="max-w-[180px] text-right text-slate-200">{healthInfo?.model ?? "…"}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt>LTM</dt>
              <dd>{healthInfo?.ltm_encrypted ? "encrypted" : "plain"}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt>Ctx tokens (approx)</dt>
              <dd>{tokenHint}</dd>
            </div>
          </dl>
        </section>
      </aside>

      <section className="flex min-h-[520px] flex-col rounded-2xl border border-white/10 bg-void-50/80 shadow-panel">
        <div className="border-b border-white/10 px-5 py-4 flex flex-wrap items-center gap-4">
          <div className="flex-1">
            <h2 className="text-sm font-semibold text-white">Analyst console</h2>
            <p className="text-xs text-slate-400">Inputs pass through sanitize → PII redact → threat scan before memory.</p>
          </div>
          <label className="flex items-center gap-2 text-xs text-slate-300">
            Alert severity
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as (typeof SEVERITY)[number])}
              className="rounded-lg border border-white/10 bg-black/30 px-2 py-1 text-slate-100"
            >
              {SEVERITY.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
        </div>
        {warn && (
          <div className="mx-5 mt-3 rounded-lg border border-amber-alert/40 bg-amber-alert/10 px-3 py-2 text-xs text-amber-200">
            Security: {warn}
          </div>
        )}
        <ChatTranscript messages={messages} loading={loading} />
        {lastPreview && (
          <div className="border-t border-white/10 px-5 py-3 font-mono text-[11px] text-slate-400">
            <span className="text-slate-500">Context preview:</span>{" "}
            <span className="text-slate-300">{JSON.stringify(lastPreview)}</span>
          </div>
        )}
        <div className="mt-auto flex gap-2 border-t border-white/10 p-4">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                void send();
              }
            }}
            rows={3}
            placeholder="Describe an alert or ask for triage…"
            className="min-h-[88px] flex-1 resize-y rounded-xl border border-white/10 bg-black/30 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-glow/50 focus:outline-none focus:ring-1 focus:ring-cyan-glow/30"
          />
          <button
            type="button"
            disabled={loading || !input.trim()}
            onClick={() => void send()}
            className="self-end rounded-xl bg-cyan-glow/90 px-5 py-3 text-sm font-semibold text-void hover:bg-cyan-glow disabled:opacity-40"
          >
            Send
          </button>
        </div>
      </section>
    </div>
  );
}
