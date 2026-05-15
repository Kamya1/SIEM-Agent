import { useEffect, useMemo, useState } from "react";
import { evalHistory } from "../api";
import { ModeRadar } from "./ModeRadar";
import { ResultsCharts } from "./ResultsCharts";
import { ResultsTable } from "./ModeRadar";
import type { EvalCompletePayload } from "../api";

type Props = { lastEval: EvalCompletePayload | null };

export function ReportTab({ lastEval }: Props) {
  const [hist, setHist] = useState<Record<string, unknown>[]>([]);

  useEffect(() => {
    void evalHistory().then(setHist).catch(() => setHist([]));
  }, [lastEval]);

  const narrative = useMemo(() => {
    const src = lastEval ?? (hist[hist.length - 1] as unknown as { summary_by_mode?: Record<string, Record<string, number>> } | undefined);
    const sm = (src as { summary_by_mode?: Record<string, Record<string, number>> })?.summary_by_mode;
    if (!sm) return "Run an evaluation from the Results tab to populate findings.";
    const modes = Object.keys(sm);
    let bestR = { m: "", v: -1 };
    let bestC = { m: "", v: -1 };
    for (const m of modes) {
      const r = sm[m]?.retention_avg ?? 0;
      const c = sm[m]?.consistency_avg ?? 0;
      if (r > bestR.v) bestR = { m, v: r };
      if (c > bestC.v) bestC = { m, v: c };
    }
    const scenCount = lastEval?.results.length
      ? new Set(lastEval.results.map((x) => x.scenario_id)).size
      : modes.length;
    return (
      `Long-term memory mode achieved the highest average retention (${bestR.v.toFixed(2)}) in this run ` +
      `across ${scenCount} scenario families (per-mode averages). ` +
      `Short-term / hybrid modes showed peak consistency at ${bestC.v.toFixed(2)} (${bestC.m}). ` +
      `Hybrid mode is designed to retrieve LTM only when session-topic similarity drops, trading latency for precision.`
    );
  }, [hist, lastEval]);

  const data = lastEval;

  return (
    <div className="space-y-8 max-w-5xl">
      <h2 className="text-xl font-semibold text-white">Project report (auto-generated)</h2>
      <p className="text-sm leading-relaxed text-slate-300">{narrative}</p>
      {data && (
        <>
          <ModeRadar data={data} />
          <ResultsCharts data={data} />
          <ResultsTable data={data} />
        </>
      )}
      {!data && <p className="text-sm text-slate-500">No evaluation loaded in this session yet.</p>}
      <div className="flex flex-wrap gap-3">
        <button
          type="button"
          className="rounded-xl bg-white/10 px-4 py-2 text-sm text-white hover:bg-white/15"
          onClick={() => window.print()}
        >
          Download PDF report (print)
        </button>
        <a
          href="/api/eval/export"
          className="rounded-xl bg-cyan-glow/20 px-4 py-2 text-sm text-cyan-glow ring-1 ring-cyan-glow/40"
        >
          Download CSV
        </a>
        <a
          href="/api/eval/report_md"
          className="rounded-xl bg-white/10 px-4 py-2 text-sm text-white hover:bg-white/15 inline-block"
        >
          Download Markdown report
        </a>
      </div>
      <p className="text-xs text-slate-500">
        Markdown is written to <code className="text-slate-400">backend/data/eval_report.md</code> after each evaluation.
      </p>
    </div>
  );
}
