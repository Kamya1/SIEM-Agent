import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { EvalResult } from "../api";

type Props = {
  data: {
    run_id: string;
    results: EvalResult[];
    summary_by_mode: Record<string, Record<string, number>>;
    dataset_source: string;
  };
};

const MODE_ORDER = ["none", "short_term", "long_term"];
const MODE_LABEL: Record<string, string> = {
  none: "No memory",
  short_term: "Short-term",
  long_term: "Long-term",
};

export function EvalDashboard({ data }: Props) {
  const chartRows = MODE_ORDER.map((k) => {
    const s = data.summary_by_mode[k];
    if (!s) return { mode: MODE_LABEL[k] ?? k, retention: 0, personalization: 0, consistency: 0, aggregate: 0 };
    return {
      mode: MODE_LABEL[k] ?? k,
      retention: s.retention_avg,
      personalization: s.personalization_avg,
      consistency: s.consistency_avg,
      aggregate: s.aggregate_avg,
    };
  });

  return (
    <div className="space-y-8">
      <p className="font-mono text-xs text-slate-500">
        Run ID: <span className="text-slate-300">{data.run_id}</span>
      </p>
      <p className="font-mono text-xs text-slate-500">
        Source: <span className="text-cyan-glow/90">{data.dataset_source}</span>
      </p>

      <div className="h-80 w-full rounded-2xl border border-white/10 bg-void-50/80 p-4 shadow-panel">
        <h3 className="mb-2 text-sm font-semibold text-white">Average scores by memory mode</h3>
        <ResponsiveContainer width="100%" height="90%">
          <BarChart data={chartRows} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
            <XAxis dataKey="mode" tick={{ fill: "#94a3b8", fontSize: 11 }} />
            <YAxis domain={[0, 1]} tick={{ fill: "#94a3b8", fontSize: 11 }} />
            <Tooltip
              contentStyle={{ background: "#0f172a", border: "1px solid rgba(148,163,184,0.2)" }}
              labelStyle={{ color: "#e2e8f0" }}
            />
            <Legend />
            <Bar dataKey="retention" name="Retention" fill="#22d3ee" radius={[4, 4, 0, 0]} />
            <Bar dataKey="personalization" name="Personalization" fill="#fbbf24" radius={[4, 4, 0, 0]} />
            <Bar dataKey="consistency" name="Consistency" fill="#a78bfa" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="rounded-2xl border border-white/10 bg-void-50/80 shadow-panel overflow-hidden">
        <table className="w-full text-left text-sm">
          <thead className="bg-black/40 text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="px-4 py-3">Scenario</th>
              <th className="px-4 py-3">Mode</th>
              <th className="px-4 py-3">Retention</th>
              <th className="px-4 py-3">Personalization</th>
              <th className="px-4 py-3">Consistency</th>
              <th className="px-4 py-3">Aggregate</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/10">
            {data.results.map((r) => (
              <tr key={`${r.scenario_id}-${r.memory_mode}`} className="font-mono text-xs text-slate-300">
                <td className="px-4 py-3 text-slate-200">{r.scenario_id}</td>
                <td className="px-4 py-3">{MODE_LABEL[r.memory_mode] ?? r.memory_mode}</td>
                <td className="px-4 py-3">{r.retention_score.toFixed(2)}</td>
                <td className="px-4 py-3">{r.personalization_score.toFixed(2)}</td>
                <td className="px-4 py-3">{r.consistency_score.toFixed(2)}</td>
                <td className="px-4 py-3 text-cyan-glow/90">{r.aggregate.toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="rounded-2xl border border-white/10 bg-black/25 p-5 text-sm text-slate-400">
        <h3 className="text-sm font-semibold text-white">How to interpret</h3>
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>
            <strong className="text-slate-200">No memory</strong> typically drops retention on turn 2 because prior user
            turns are not in context.
          </li>
          <li>
            <strong className="text-slate-200">Short-term</strong> usually restores recall within the same session.
          </li>
          <li>
            <strong className="text-slate-200">Long-term</strong> adds cross-session institutional retrieval; scores also
            reflect whether TF–IDF retrieved the right chunks (see backend scenarios).
          </li>
        </ul>
      </div>
    </div>
  );
}
