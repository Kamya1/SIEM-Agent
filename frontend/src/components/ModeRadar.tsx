import { useMemo, useState } from "react";
import { PolarAngleAxis, PolarGrid, Radar, RadarChart, ResponsiveContainer, Tooltip } from "recharts";
import type { EvalCompletePayload, MemoryMode } from "../api";

const MODE_ORDER: MemoryMode[] = ["no_memory", "short_term", "long_term", "hybrid"];
const MODE_LABEL: Record<string, string> = {
  no_memory: "No memory",
  short_term: "Short-term",
  long_term: "Long-term",
  hybrid: "Hybrid",
};

type Props = { data: EvalCompletePayload };

export function ModeRadar({ data }: Props) {
  const radarData = useMemo(() => {
    const axes = [
      { metric: "Retention", key: "retention_avg" as const },
      { metric: "Consistency", key: "consistency_avg" as const },
      { metric: "Personalization", key: "personalization_avg" as const },
    ];
    return axes.map((a) => {
      const row: Record<string, string | number> = { metric: a.metric };
      for (const mode of MODE_ORDER) {
        row[MODE_LABEL[mode]] = data.summary_by_mode[mode]?.[a.key] ?? 0;
      }
      return row;
    });
  }, [data.summary_by_mode]);

  const colors = ["#22d3ee", "#34d399", "#a78bfa", "#fbbf24"];

  return (
    <div className="h-80 w-full rounded-2xl border border-white/10 bg-void-50/80 p-4 shadow-panel">
      <h3 className="mb-2 text-sm font-semibold text-white">Radar — average metrics by memory mode</h3>
      <ResponsiveContainer width="100%" height="88%">
        <RadarChart data={radarData} cx="50%" cy="50%" outerRadius="75%">
          <PolarGrid stroke="rgba(148,163,184,0.25)" />
          <PolarAngleAxis dataKey="metric" tick={{ fill: "#94a3b8", fontSize: 11 }} />
          <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid rgba(148,163,184,0.2)" }} />
          {MODE_ORDER.map((mode, i) => (
            <Radar
              key={mode}
              name={MODE_LABEL[mode]}
              dataKey={MODE_LABEL[mode]}
              stroke={colors[i % colors.length]}
              fill={colors[i % colors.length]}
              fillOpacity={0.15}
            />
          ))}
        </RadarChart>
      </ResponsiveContainer>
    </div>
  );
}

type TableProps = { data: EvalCompletePayload };

export function ResultsTable({ data }: TableProps) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<{ k: keyof typeof data.results[0] | "aggregate"; dir: "asc" | "desc" }>({
    k: "aggregate",
    dir: "desc",
  });

  const rows = useMemo(() => {
    let r = [...data.results];
    if (q.trim()) {
      const qq = q.toLowerCase();
      r = r.filter((x) => x.scenario_id.toLowerCase().includes(qq) || x.memory_mode.includes(qq));
    }
    r.sort((a, b) => {
      const va = a[sort.k as keyof typeof a];
      const vb = b[sort.k as keyof typeof b];
      if (typeof va === "number" && typeof vb === "number") {
        return sort.dir === "asc" ? va - vb : vb - va;
      }
      const sa = String(va ?? "");
      const sb = String(vb ?? "");
      return sort.dir === "asc" ? sa.localeCompare(sb) : sb.localeCompare(sa);
    });
    return r;
  }, [data.results, q, sort]);

  const th = (label: string, k: typeof sort.k) => (
    <th className="px-3 py-2">
      <button
        type="button"
        className="text-left uppercase hover:text-cyan-glow"
        onClick={() =>
          setSort((s) => (s.k === k ? { k, dir: s.dir === "asc" ? "desc" : "asc" } : { k, dir: "desc" }))
        }
      >
        {label}
      </button>
    </th>
  );

  return (
    <div className="space-y-3">
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Filter scenario / mode…"
        className="w-full max-w-md rounded-lg border border-white/10 bg-black/30 px-3 py-2 text-sm text-slate-100"
      />
      <div className="overflow-x-auto rounded-2xl border border-white/10 bg-void-50/80 shadow-panel">
        <table className="w-full text-left text-xs">
          <thead className="bg-black/40 uppercase tracking-wide text-slate-400">
            <tr>
              {th("Scenario", "scenario_id")}
              {th("Mode", "memory_mode")}
              {th("R", "retention_score")}
              {th("C", "consistency_score")}
              {th("P", "personalization_score")}
              {th("Agg", "aggregate")}
              {th("Lat ms", "latency_avg_ms")}
              <th className="px-3 py-2">MITRE</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/10 font-mono text-slate-300">
            {rows.map((r) => (
              <tr key={`${r.scenario_id}-${r.memory_mode}`}>
                <td className="px-3 py-2 text-slate-200">{r.scenario_id}</td>
                <td className="px-3 py-2">{r.memory_mode}</td>
                <td className="px-3 py-2">{r.retention_score.toFixed(3)}</td>
                <td className="px-3 py-2">{r.consistency_score.toFixed(3)}</td>
                <td className="px-3 py-2">{r.personalization_score.toFixed(3)}</td>
                <td className="px-3 py-2 text-cyan-glow/90">{r.aggregate.toFixed(3)}</td>
                <td className="px-3 py-2">{r.latency_avg_ms.toFixed(0)}</td>
                <td className="px-3 py-2 text-[10px]">{r.mitre_detected.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
