import { useMemo, useState } from "react";
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
import type { EvalCompletePayload, EvalResult, MemoryMode } from "../api";

const MODE_ORDER: MemoryMode[] = ["no_memory", "short_term", "long_term", "hybrid"];
const MODE_LABEL: Record<string, string> = {
  no_memory: "No memory",
  short_term: "Short-term",
  long_term: "Long-term",
  hybrid: "Hybrid",
};

const METRICS = [
  { key: "retention_score", name: "Retention", fill: "#22d3ee" },
  { key: "consistency_score", name: "Consistency", fill: "#a78bfa" },
  { key: "personalization_score", name: "Personalization", fill: "#fbbf24" },
] as const;

function buildGroupedChartData(results: EvalResult[]) {
  const scenarios = [...new Set(results.map((r) => r.scenario_id))];
  return scenarios.map((sid) => {
    const row: Record<string, string | number> = { scenario: sid };
    for (const mode of MODE_ORDER) {
      const hit = results.find((r) => r.scenario_id === sid && r.memory_mode === mode);
      for (const m of METRICS) {
        const k = `${mode}__${m.key}`;
        row[k] = hit ? (hit[m.key as keyof EvalResult] as number) : 0;
      }
    }
    return row;
  });
}

type Props = { data: EvalCompletePayload };

export function ResultsCharts({ data }: Props) {
  const chartData = useMemo(() => buildGroupedChartData(data.results), [data.results]);
  const consistencyByMode = useMemo(
    () =>
      MODE_ORDER.map((m) => ({
        mode: MODE_LABEL[m],
        consistency: data.summary_by_mode[m]?.consistency_avg ?? 0,
      })),
    [data.summary_by_mode]
  );

  return (
    <div className="space-y-6">
      <div className="h-56 w-full rounded-2xl border border-white/10 bg-void-50/80 p-4 shadow-panel">
        <h3 className="mb-2 text-sm font-semibold text-white">Consistency vs memory mode (research finding)</h3>
        <ResponsiveContainer width="100%" height="88%">
          <BarChart data={consistencyByMode} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
            <XAxis dataKey="mode" tick={{ fill: "#94a3b8", fontSize: 10 }} />
            <YAxis domain={[0, 1]} tick={{ fill: "#94a3b8", fontSize: 11 }} />
            <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid rgba(148,163,184,0.2)" }} />
            <Bar dataKey="consistency" name="Avg consistency (3× Jaccard)" fill="#a78bfa" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="h-[420px] w-full rounded-2xl border border-white/10 bg-void-50/80 p-4 shadow-panel">
        <h3 className="mb-2 text-sm font-semibold text-white">Per-scenario scores (grouped by memory mode)</h3>
        <ResponsiveContainer width="100%" height="92%">
          <BarChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 64 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
            <XAxis dataKey="scenario" angle={-25} textAnchor="end" height={80} tick={{ fill: "#94a3b8", fontSize: 9 }} />
            <YAxis domain={[0, 1]} tick={{ fill: "#94a3b8", fontSize: 11 }} />
            <Tooltip
              contentStyle={{ background: "#0f172a", border: "1px solid rgba(148,163,184,0.2)" }}
              labelStyle={{ color: "#e2e8f0" }}
            />
            <Legend wrapperStyle={{ fontSize: 11 }} />
            {MODE_ORDER.map((mode, mi) =>
              METRICS.map((m, ii) => (
                <Bar
                  key={`${mode}-${m.key}`}
                  dataKey={`${mode}__${m.key}`}
                  name={`${MODE_LABEL[mode]}-${m.name}`}
                  fill={m.fill}
                  opacity={0.55 + mi * 0.1}
                  radius={[2, 2, 0, 0]}
                  maxBarSize={10 + ii * 2}
                />
              ))
            )}
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="h-80 w-full rounded-2xl border border-white/10 bg-void-50/80 p-4 shadow-panel">
        <h3 className="mb-2 text-sm font-semibold text-white">Average latency by mode (ms)</h3>
        <ResponsiveContainer width="100%" height="88%">
          <BarChart
            data={MODE_ORDER.map((mode) => ({
              mode: MODE_LABEL[mode],
              ms: data.summary_by_mode[mode]?.latency_avg_ms ?? 0,
            }))}
            margin={{ top: 8, right: 8, left: 0, bottom: 0 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
            <XAxis dataKey="mode" tick={{ fill: "#94a3b8", fontSize: 11 }} />
            <YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} />
            <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid rgba(148,163,184,0.2)" }} />
            <Bar dataKey="ms" name="Avg latency (ms)" fill="#f472b6" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
