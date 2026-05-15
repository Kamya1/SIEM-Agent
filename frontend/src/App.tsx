import { useCallback, useState } from "react";
import { AnalystConsole } from "./components/AnalystConsole";
import { MemoryInspector } from "./components/MemoryInspector";
import { ReportTab } from "./components/ReportTab";
import { ResultsTab } from "./components/ResultsTab";
import { SecurityPanel } from "./components/SecurityPanel";
import { TheoryTab } from "./components/TheoryTab";
import type { EvalCompletePayload, HealthInfo } from "./api";

function newSessionId() {
  return `sess-${crypto.randomUUID().slice(0, 8)}`;
}

type Tab = "chat" | "eval" | "about" | "memory" | "report" | "security";

export default function App() {
  const [tab, setTab] = useState<Tab>("chat");
  const [sessionId, setSessionId] = useState(newSessionId);
  const [healthInfo, setHealthInfo] = useState<HealthInfo | null>(null);
  const [evalData, setEvalData] = useState<EvalCompletePayload | null>(null);

  const refreshHealth = useCallback((h: HealthInfo) => setHealthInfo(h), []);

  const tabs: { id: Tab; label: string }[] = [
    { id: "chat", label: "Analyst console" },
    { id: "eval", label: "Results" },
    { id: "about", label: "Theory" },
    { id: "memory", label: "Memory" },
    { id: "security", label: "Security" },
    { id: "report", label: "Report" },
  ];

  return (
    <div className="min-h-screen text-slate-100">
      <header className="border-b border-white/10 bg-void-50/80 backdrop-blur-md sticky top-0 z-20">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-4 py-4">
          <div>
            <h1 className="font-semibold text-xl text-white">Evaluating STM vs LTM in LLM SIEM Analyst Agents</h1>
            <p className="mt-1 text-[11px] text-slate-500">
              Security events · poisoning blocked:{" "}
              <span className="text-amber-alert">{healthInfo?.memory_poisoning_attempts ?? 0}</span>
              {healthInfo?.ltm_encrypted ? (
                <span className="ml-2 text-emerald-400">LTM encrypted</span>
              ) : (
                <span className="ml-2 text-red-400">LTM not encrypted</span>
              )}
            </p>
          </div>
          <nav className="flex flex-wrap gap-2">
            {tabs.map(({ id, label }) => (
              <button
                key={id}
                type="button"
                onClick={() => setTab(id)}
                className={`rounded-lg px-3 py-2 text-sm font-medium transition ${
                  tab === id
                    ? "bg-cyan-glow/15 text-cyan-glow shadow-panel ring-1 ring-cyan-glow/30"
                    : "bg-white/5 text-slate-300 hover:bg-white/10"
                }`}
              >
                {label}
              </button>
            ))}
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-8">
        {tab === "chat" && (
          <AnalystConsole
            sessionId={sessionId}
            setSessionId={setSessionId}
            healthInfo={healthInfo}
            onHealth={refreshHealth}
          />
        )}
        {tab === "eval" && <ResultsTab data={evalData} onData={setEvalData} />}
        {tab === "about" && <TheoryTab />}
        {tab === "memory" && <MemoryInspector sessionId={sessionId} />}
        {tab === "security" && (
          <SecurityPanel sessionId={sessionId} ltmEncrypted={healthInfo?.ltm_encrypted} />
        )}
        {tab === "report" && <ReportTab lastEval={evalData} />}
      </main>

      <footer className="border-t border-white/10 py-8 text-center text-xs text-slate-600">
        Agentic SIEM — defensive security research demo
      </footer>
    </div>
  );
}
