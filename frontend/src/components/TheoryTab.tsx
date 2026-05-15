import type { ReactNode } from "react";
import { useState } from "react";

type CardProps = { title: string; children: ReactNode; pros: string[]; cons: string[] };

function Card({ title, children, pros, cons }: CardProps) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-2xl border border-white/10 bg-void-50/80 shadow-panel overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between px-5 py-4 text-left hover:bg-white/5"
      >
        <span className="font-semibold text-white">{title}</span>
        <span className="text-slate-400">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="border-t border-white/10 px-5 py-4 text-sm text-slate-300 space-y-3">
          <div>{children}</div>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <p className="text-xs font-semibold uppercase text-emerald-400">Pros</p>
              <ul className="mt-1 list-disc pl-5 space-y-1">
                {pros.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            </div>
            <div>
              <p className="text-xs font-semibold uppercase text-amber-300">Cons</p>
              <ul className="mt-1 list-disc pl-5 space-y-1">
                {cons.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const MITRE_ROWS = [
  { id: "T1110", name: "Brute Force", scenarios: "Failed logins, credential stuffing" },
  { id: "T1021", name: "Remote Services", scenarios: "Lateral movement" },
  { id: "T1078", name: "Valid Accounts", scenarios: "Privilege patterns, after-hours" },
];

export function TheoryTab() {
  return (
    <div className="max-w-3xl space-y-4 text-sm text-slate-300">
      <h2 className="text-xl font-semibold text-white">Theory & concepts</h2>
      <Card
        title="No memory (stateless)"
        pros={["Lowest latency", "No privacy risk from stored chats", "Deterministic context budget"]}
        cons={["No cross-turn recall", "Poor personalization continuity", "High analyst repetition"]}
      >
        Each LLM call sees only the current user utterance (plus system prompt). This mimics a default chat integration
        without transcript threading.
      </Card>
      <Card
        title="Short-term memory (session buffer)"
        pros={["Strong same-session retention", "Adaptive compression reduces overflow", "Preference detection"]}
        cons={["No cross-session recall", "Still bounded; very long chats compress lossily"]}
      >
        A sliding window of recent turns with optional LLM summarization of older turns into{" "}
        <code className="text-slate-400">[COMPRESSED CONTEXT]</code> blocks preserves entities and preferences.
      </Card>
      <Card
        title="Long-term memory (vector LTM + SQLite)"
        pros={["Cross-session institutional recall", "Semantic retrieval with cosine similarity", "Audit metadata per entry"]}
        cons={["Higher latency for embed+search", "Requires poisoning safeguards", "Storage growth"]}
      >
        Exchanges are embedded with <code className="text-slate-400">all-MiniLM-L6-v2</code> (384-d) and retrieved when
        similar to the current query, above a similarity threshold.
      </Card>
      <Card
        title="Hybrid memory (STM + conditional LTM)"
        pros={["Keeps STM hot path fast", "Pulls LTM on topic drift / explicit recall cues", "Dedupes STM overlap"]}
        cons={["More complex tuning (similarity thresholds)", "Extra embedding calls when gated on"]}
      >
        Hybrid always includes STM. LTM activates when cosine similarity between the query and recent session context is
        low, or when the analyst uses phrases like “earlier” / “previously”.
      </Card>

      <div className="rounded-2xl border border-white/10 bg-void-50/80 p-5 shadow-panel">
        <h3 className="text-sm font-semibold text-white">MITRE ATT&CK (scenario tags)</h3>
        <table className="mt-3 w-full text-xs">
          <thead className="text-slate-500">
            <tr>
              <th className="text-left py-2">ID</th>
              <th className="text-left py-2">Name</th>
              <th className="text-left py-2">Scenarios</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/10">
            {MITRE_ROWS.map((r) => (
              <tr key={r.id}>
                <td className="py-2 font-mono text-cyan-glow/90">
                  <a href={`https://attack.mitre.org/techniques/${r.id}/`} target="_blank" rel="noreferrer">
                    {r.id}
                  </a>
                </td>
                <td className="py-2">{r.name}</td>
                <td className="py-2 text-slate-400">{r.scenarios}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="rounded-2xl border border-white/10 bg-black/25 p-5 text-xs text-slate-400">
        <h3 className="text-sm font-semibold text-white">Glossary</h3>
        <dl className="mt-2 space-y-2">
          <div>
            <dt className="text-slate-200">SIEM</dt>
            <dd>Security Information and Event Management — centralized log ingestion, correlation, and alerting.</dd>
          </div>
          <div>
            <dt className="text-slate-200">LLM</dt>
            <dd>Large Language Model used here as an analyst copilot for triage narratives and checklists.</dd>
          </div>
          <div>
            <dt className="text-slate-200">RAG</dt>
            <dd>Retrieval-Augmented Generation — inject retrieved memory chunks into the prompt.</dd>
          </div>
          <div>
            <dt className="text-slate-200">Vector embedding</dt>
            <dd>Dense semantic representation used for cosine similarity instead of sparse TF–IDF alone.</dd>
          </div>
          <div>
            <dt className="text-slate-200">Alert fatigue</dt>
            <dd>Analyst desensitization from noisy alerts; memory can help maintain consistent investigation framing.</dd>
          </div>
        </dl>
      </div>
    </div>
  );
}
