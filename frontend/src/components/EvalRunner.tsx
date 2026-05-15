import { useState } from "react";
import type { EvalCompletePayload, EvalRunBody, MemoryMode } from "../api";
import { runEvalStream } from "../api";

const SCENARIOS = [
  "lanl-failed-logins-001",
  "lanl-same-source-repeated",
  "lanl-suspicious-sequence",
  "lanl-privilege-escalation",
  "lanl-lateral-movement",
  "lanl-after-hours",
  "lanl-credential-stuffing",
  "cross-session-recall-001",
];

const MODES: MemoryMode[] = ["no_memory", "short_term", "long_term", "hybrid"];
const MODE_LABEL: Record<string, string> = {
  no_memory: "No memory",
  short_term: "Short-term",
  long_term: "Long-term",
  hybrid: "Hybrid",
};

type Props = {
  onComplete: (data: EvalCompletePayload) => void;
};

export function EvalRunner({ onComplete }: Props) {
  const [selScen, setSelScen] = useState<Set<string>>(() => new Set(["all"]));
  const [selModes, setSelModes] = useState<Set<MemoryMode>>(() => new Set(MODES));
  const [runs, setRuns] = useState(1);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [log, setLog] = useState<string[]>([]);

  const toggle = (s: Set<string>, v: string, allKey = "all") => {
    const n = new Set(s);
    if (v === allKey) {
      return new Set([allKey]);
    }
    n.delete(allKey);
    if (n.has(v)) n.delete(v);
    else n.add(v);
    if (n.size === 0) n.add(allKey);
    return n;
  }

  const toggleMode = (m: MemoryMode) => {
    const n = new Set(selModes);
    if (n.has(m)) n.delete(m);
    else n.add(m);
    if (n.size === 0) MODES.forEach((x) => n.add(x));
    setSelModes(n);
  };

  const run = async () => {
    setBusy(true);
    setLog([]);
    setProgress(5);
    const scen = selScen.has("all") ? ["all"] : [...selScen];
    const body: EvalRunBody = {
      scenarios: scen,
      modes: [...selModes],
      runs_per_scenario: runs,
    };
    try {
      const data = await runEvalStream(body, (evt) => {
        if (evt.type === "progress") {
          setLog((l) => [
            ...l,
            `Running ${String(evt.scenario)} in ${String(evt.mode)}… retention=${Number(evt.retention).toFixed(3)} agg=${Number(evt.aggregate).toFixed(3)}`,
          ]);
          setProgress((p) => Math.min(95, p + 2));
        }
      });
      setProgress(100);
      onComplete(data);
      setLog((l) => [...l, `Complete run_id=${data.run_id}`]);
    } catch (e) {
      setLog((l) => [...l, `Error: ${e instanceof Error ? e.message : String(e)}`]);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-2xl border border-white/10 bg-void-50/80 p-5 shadow-panel space-y-4">
      <h3 className="text-sm font-semibold text-white">Run evaluation</h3>
      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <p className="text-xs text-slate-400 mb-2">Scenarios</p>
          <div className="flex flex-wrap gap-2">
            <label className="flex items-center gap-2 text-xs text-slate-300">
              <input
                type="checkbox"
                checked={selScen.has("all")}
                onChange={() => setSelScen(new Set(["all"]))}
              />
              all
            </label>
            {SCENARIOS.map((id) => (
              <label key={id} className="flex items-center gap-2 text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={!selScen.has("all") && selScen.has(id)}
                  onChange={() => setSelScen((s) => toggle(s, id))}
                />
                {id}
              </label>
            ))}
          </div>
        </div>
        <div>
          <p className="text-xs text-slate-400 mb-2">Memory modes</p>
          <div className="flex flex-wrap gap-2">
            {MODES.map((m) => (
              <label key={m} className="flex items-center gap-2 text-xs text-slate-300">
                <input type="checkbox" checked={selModes.has(m)} onChange={() => toggleMode(m)} />
                {MODE_LABEL[m]}
              </label>
            ))}
          </div>
          <label className="mt-3 flex items-center gap-2 text-xs text-slate-400">
            runs_per_scenario
            <input
              type="number"
              min={1}
              max={5}
              value={runs}
              onChange={(e) => setRuns(Number(e.target.value) || 1)}
              className="w-16 rounded border border-white/10 bg-black/30 px-2 py-1 text-slate-100"
            />
          </label>
        </div>
      </div>
      <button
        type="button"
        disabled={busy}
        onClick={() => void run()}
        className="rounded-xl bg-cyan-glow/90 px-5 py-2 text-sm font-semibold text-void hover:bg-cyan-glow disabled:opacity-40"
      >
        {busy ? "Running…" : "Run (SSE)"}
      </button>
      <div className="h-2 w-full overflow-hidden rounded-full bg-black/40">
        <div className="h-full bg-cyan-glow/80 transition-all" style={{ width: `${progress}%` }} />
      </div>
      <div className="max-h-40 overflow-y-auto rounded-lg bg-black/30 p-2 font-mono text-[10px] text-slate-400">
        {log.map((l, i) => (
          <div key={`${i}-${l}`}>{l}</div>
        ))}
      </div>
    </div>
  );
}
