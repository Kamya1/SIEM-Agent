import type { EvalCompletePayload } from "../api";
import { EvalRunner } from "./EvalRunner";
import { ModeRadar } from "./ModeRadar";
import { ResultsCharts } from "./ResultsCharts";
import { ResultsTable } from "./ModeRadar";

type Props = {
  data: EvalCompletePayload | null;
  onData: (d: EvalCompletePayload) => void;
};

export function ResultsTab({ data, onData }: Props) {
  return (
    <div className="space-y-8">
      <EvalRunner onComplete={onData} />
      {data && (
        <>
          <p className="font-mono text-xs text-slate-500">
            Run: <span className="text-slate-300">{data.run_id}</span> · Source:{" "}
            <span className="text-cyan-glow/90">{data.dataset_source}</span>
          </p>
          <ModeRadar data={data} />
          <ResultsCharts data={data} />
          <ResultsTable data={data} />
          <div className="flex gap-3">
            <a
              href="/api/eval/export"
              className="rounded-xl bg-cyan-glow/90 px-5 py-3 text-sm font-semibold text-void hover:bg-cyan-glow"
            >
              Export CSV
            </a>
            <a
              href="/api/eval/report_md"
              className="rounded-xl bg-white/10 px-5 py-3 text-sm font-semibold text-white hover:bg-white/15"
            >
              Markdown report
            </a>
          </div>
          <div className="rounded-xl border border-white/10 bg-black/25 p-4 text-xs text-slate-400">
            <p className="font-semibold text-slate-200">Techniques detected (last run)</p>
            <p className="mt-2 font-mono">
              {[
                ...new Set(
                  data.results.flatMap((r) => r.mitre_detected)
                ),
              ].join(", ") || "—"}
            </p>
          </div>
        </>
      )}
    </div>
  );
}
