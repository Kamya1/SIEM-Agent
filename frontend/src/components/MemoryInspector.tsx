import { useCallback, useEffect, useState } from "react";
import { evalExportUrl, memoryClear, memoryDelete, memoryList, memoryShare, type LTMMeta } from "../api";

type Props = { sessionId?: string };

export function MemoryInspector({ sessionId }: Props) {
  const [rows, setRows] = useState<LTMMeta[]>([]);
  const [kb, setKb] = useState(0);
  const [q, setQ] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    setErr(null);
    try {
      const d = await memoryList(sessionId);
      setRows(d.entries);
      setKb(d.total_size_kb);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "load failed");
    }
  }, [sessionId]);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = rows.filter((r) => {
    if (!q.trim()) return true;
    const qq = q.toLowerCase();
    return (
      String(r.id).includes(qq) ||
      (r.scenario_tag || "").toLowerCase().includes(qq) ||
      (r.session_id || "").toLowerCase().includes(qq) ||
      (r.excerpt || "").toLowerCase().includes(qq)
    );
  });

  const onDelete = async (id: number) => {
    await memoryDelete(id, sessionId);
    void load();
  };

  const onShare = async (id: number, shared: boolean) => {
    if (!sessionId) return;
    await memoryShare(id, sessionId, shared);
    void load();
  };

  const onClear = async () => {
    if (!window.confirm("Delete ALL long-term memory entries?")) return;
    await memoryClear();
    void load();
  };

  const maxR = Math.max(1, ...filtered.map((r) => r.retrieval_count));

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Memory inspector (LTM)</h2>
          <p className="text-xs text-slate-400">
            SQLite + vector embeddings · total DB size ~{kb.toFixed(1)} KB · {rows.length} entries
          </p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => void load()}
            className="rounded-lg bg-white/10 px-3 py-2 text-xs text-white hover:bg-white/15"
          >
            Refresh
          </button>
          <button
            type="button"
            onClick={() => void onClear()}
            className="rounded-lg bg-red-500/20 px-3 py-2 text-xs text-red-200 ring-1 ring-red-500/40 hover:bg-red-500/30"
          >
            Clear all
          </button>
          <a
            href={evalExportUrl()}
            className="rounded-lg bg-cyan-glow/20 px-3 py-2 text-xs text-cyan-glow ring-1 ring-cyan-glow/40"
          >
            Export CSV
          </a>
        </div>
      </div>
      {err && <div className="rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-200">{err}</div>}
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Search ID, session, scenario tag, excerpt…"
        className="w-full max-w-xl rounded-lg border border-white/10 bg-black/30 px-3 py-2 text-sm text-slate-100"
      />
      <div className="overflow-x-auto rounded-2xl border border-white/10 bg-void-50/80 shadow-panel">
        <table className="w-full text-left text-xs">
          <thead className="bg-black/40 uppercase tracking-wide text-slate-400">
            <tr>
              <th className="px-3 py-2">ID</th>
              <th className="px-3 py-2">Session</th>
              <th className="px-3 py-2">Time</th>
              <th className="px-3 py-2">Scenario</th>
              <th className="px-3 py-2">Mode</th>
              <th className="px-3 py-2">Retrievals</th>
              <th className="px-3 py-2">Shared</th>
              <th className="px-3 py-2">Excerpt</th>
              <th className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/10 text-slate-300">
            {filtered.map((r) => (
              <tr key={r.id}>
                <td className="px-3 py-2 font-mono">{r.id}</td>
                <td className="px-3 py-2 font-mono text-[10px]">{r.session_id}</td>
                <td className="px-3 py-2 text-[10px]">{r.timestamp}</td>
                <td className="px-3 py-2">{r.scenario_tag}</td>
                <td className="px-3 py-2">{r.memory_mode}</td>
                <td className="px-3 py-2">
                  <div className="flex items-center gap-2">
                    <div className="h-2 w-24 overflow-hidden rounded-full bg-black/40">
                      <div
                        className="h-full bg-cyan-glow/70"
                        style={{ width: `${(r.retrieval_count / maxR) * 100}%` }}
                      />
                    </div>
                    <span className="font-mono">{r.retrieval_count}</span>
                  </div>
                </td>
                <td className="px-3 py-2">
                  {r.shared ? (
                    <span className="text-emerald-400">yes</span>
                  ) : (
                    <button
                      type="button"
                      className="text-cyan-glow hover:underline"
                      disabled={!sessionId}
                      onClick={() => void onShare(r.id, true)}
                    >
                      Share
                    </button>
                  )}
                </td>
                <td className="max-w-xs truncate px-3 py-2 text-[10px]">{r.excerpt}</td>
                <td className="px-3 py-2 flex gap-2">
                  <button
                    type="button"
                    className="text-red-300 hover:underline"
                    onClick={() => void onDelete(r.id)}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
