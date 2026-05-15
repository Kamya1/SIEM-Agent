import { useCallback, useEffect, useState } from "react";
import {
  auditTrail,
  auditVerify,
  securityStatus,
  type AuditEntry,
  type AuditVerifyResult,
  type SecurityStatus,
} from "../api";

type Props = {
  sessionId: string;
  ltmEncrypted?: boolean;
};

const EVENT_COLOR: Record<string, string> = {
  STM_STORE: "text-emerald-400",
  LTM_STORE: "text-emerald-400",
  LTM_RETRIEVE: "text-cyan-glow",
  LTM_DELETE: "text-slate-400",
  SESSION_EXPIRE: "text-amber-300",
  SECURITY_ALERT: "text-amber-alert",
  PII_DETECTED: "text-amber-alert",
  INJECTION_BLOCKED: "text-red-400",
  RATE_LIMITED: "text-red-400",
};

export function SecurityPanel({ sessionId, ltmEncrypted }: Props) {
  const [status, setStatus] = useState<SecurityStatus | null>(null);
  const [trail, setTrail] = useState<AuditEntry[]>([]);
  const [verify, setVerify] = useState<AuditVerifyResult | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [st, tr, vr] = await Promise.all([
        securityStatus(sessionId),
        auditTrail(sessionId, 20),
        auditVerify(),
      ]);
      setStatus(st);
      setTrail(tr);
      setVerify(vr);
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 15000);
    return () => clearInterval(t);
  }, [refresh]);

  const trunc = sessionId.length > 12 ? `${sessionId.slice(0, 12)}…` : sessionId;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Security & privacy</h2>
          <p className="text-xs text-slate-400">
            Sanitization, PII redaction, threat scoring, encrypted LTM, tamper-evident audit log.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void refresh()}
          disabled={loading}
          className="rounded-lg bg-white/10 px-3 py-2 text-xs text-white hover:bg-white/15 disabled:opacity-40"
        >
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <section className="rounded-2xl border border-white/10 bg-void-50/80 p-5 shadow-panel">
          <h3 className="text-sm font-semibold text-white">Session</h3>
          <dl className="mt-3 space-y-2 text-xs font-mono text-slate-300">
            <div className="flex justify-between">
              <dt>Session ID</dt>
              <dd className="text-cyan-glow/90">{trunc}</dd>
            </div>
            <div className="flex justify-between">
              <dt>Expires in</dt>
              <dd>{status?.session?.expires_in_seconds ?? "—"}s</dd>
            </div>
            <div className="flex justify-between">
              <dt>Requests / min</dt>
              <dd>
                {status?.requests_this_minute ?? 0} / {status?.rate_limit_max ?? 30}
              </dd>
            </div>
          </dl>
          <div className="mt-4">
            {ltmEncrypted ? (
              <span className="inline-flex rounded-md bg-emerald-500/20 px-2 py-1 text-[11px] text-emerald-300 ring-1 ring-emerald-500/40">
                LTM encrypted
              </span>
            ) : (
              <span className="inline-flex rounded-md bg-red-500/20 px-2 py-1 text-[11px] text-red-300 ring-1 ring-red-500/40">
                LTM key missing
              </span>
            )}
          </div>
        </section>

        <section className="rounded-2xl border border-white/10 bg-void-50/80 p-5 shadow-panel">
          <h3 className="text-sm font-semibold text-white">Audit log integrity</h3>
          {verify ? (
            <div className="mt-3 text-sm">
              {verify.tampered.length === 0 ? (
                <p className="text-emerald-400">
                  All {verify.valid} / {verify.total} log entries verified
                </p>
              ) : (
                <p className="text-red-400">
                  Tampered: {verify.tampered.join(", ")} ({verify.valid}/{verify.total} valid)
                </p>
              )}
            </div>
          ) : (
            <p className="mt-3 text-xs text-slate-500">No verification run yet.</p>
          )}
          <button
            type="button"
            onClick={() => void auditVerify().then(setVerify)}
            className="mt-3 rounded-lg bg-cyan-glow/20 px-3 py-2 text-xs text-cyan-glow ring-1 ring-cyan-glow/40"
          >
            Verify log integrity
          </button>
        </section>
      </div>

      <section className="rounded-2xl border border-white/10 bg-void-50/80 shadow-panel overflow-hidden">
        <h3 className="border-b border-white/10 px-5 py-3 text-sm font-semibold text-white">
          Audit trail (this session)
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-black/40 uppercase text-slate-500">
              <tr>
                <th className="px-3 py-2">Time</th>
                <th className="px-3 py-2">Event</th>
                <th className="px-3 py-2">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/10 font-mono text-slate-400">
              {trail.length === 0 && (
                <tr>
                  <td colSpan={3} className="px-3 py-4 text-slate-500">
                    No events yet.
                  </td>
                </tr>
              )}
              {trail.map((e) => (
                <tr key={e.event_id}>
                  <td className="px-3 py-2 whitespace-nowrap text-[10px]">
                    {e.timestamp?.slice(11, 19) ?? "—"}
                  </td>
                  <td className={`px-3 py-2 ${EVENT_COLOR[e.event_type] ?? "text-slate-300"}`}>
                    {e.event_type}
                  </td>
                  <td className="max-w-md truncate px-3 py-2 text-[10px]">
                    {JSON.stringify(e.details)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
