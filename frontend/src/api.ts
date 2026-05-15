import axios from "axios";

const http = axios.create({ baseURL: "", timeout: 20_000 });

export type MemoryMode = "no_memory" | "short_term" | "long_term" | "hybrid";

export type HealthInfo = {
  status: string;
  groq_connected: boolean;
  groq_status?: string;
  llm_fallback_mock?: boolean;
  ltm_entry_count: number;
  stm_sessions_active: number;
  model: string;
  memory_poisoning_attempts?: number;
  ltm_encrypted?: boolean;
  audit_log_entries?: number;
};

export type SecurityEventInfo = {
  threat_score: number;
  threat_type: string | null;
  should_block: boolean;
  explanation: string;
  shield: "clean" | "pii" | "flagged" | "blocked";
  pii_found: string[];
  redaction_count: number;
  sanitize_flags: string[];
  session_rotated?: boolean;
  effective_session_id?: string | null;
};

export type SecurityStatus = {
  session: {
    session_id?: string;
    expires_in_seconds?: number;
    age_seconds?: number;
  };
  requests_this_minute: number;
  rate_limit_max: number;
  ltm_encrypted: boolean;
};

export type AuditEntry = {
  event_id: string;
  timestamp: string;
  session_id: string;
  event_type: string;
  details: Record<string, unknown>;
  checksum: string;
};

export type AuditVerifyResult = {
  total: number;
  valid: number;
  tampered: string[];
};

export async function health(): Promise<HealthInfo> {
  const { data } = await http.get<HealthInfo>("/api/health");
  return data;
}

export type ChatContextPreview = Record<string, unknown> & {
  latency_ms?: number;
  stm_tokens?: number;
};

export async function chat(
  sessionId: string,
  memoryMode: MemoryMode,
  message: string,
  scenarioTag?: string
) {
  const { data } = await http.post<{
    reply: string;
    memory_mode: MemoryMode;
    context_preview: ChatContextPreview;
    mitre_techniques: string[];
    security_warning?: string | null;
    security_event?: SecurityEventInfo | null;
    session_id?: string | null;
  }>(
    "/api/chat",
    {
      session_id: sessionId,
      memory_mode: memoryMode,
      message,
      scenario_tag: scenarioTag,
    },
    { timeout: 120_000 }
  );
  return data;
}

export async function resetSession(sessionId: string) {
  const { data } = await http.post<{ status: string }>(`/api/session/reset?session_id=${encodeURIComponent(sessionId)}`);
  return data;
}

export type EvalResult = {
  scenario_id: string;
  memory_mode: MemoryMode;
  turns: number;
  retention_score: number;
  consistency_score: number;
  personalization_score: number;
  aggregate: number;
  latency_avg_ms: number;
  mitre_detected: string[];
  details: Record<string, unknown>;
};

export type EvalCompletePayload = {
  run_id: string;
  results: EvalResult[];
  summary_by_mode: Record<string, Record<string, number>>;
  dataset_source: string;
};

export type EvalRunBody = {
  scenarios: string[];
  modes: MemoryMode[];
  runs_per_scenario: number;
};

export function runEvalStream(
  body: EvalRunBody,
  onEvent: (evt: Record<string, unknown>) => void
): Promise<EvalCompletePayload> {
  return new Promise((resolve, reject) => {
    let settled = false;
    fetch("/api/eval/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then(async (res) => {
        if (!res.ok || !res.body) {
          reject(new Error(`eval stream failed: ${res.status}`));
          return;
        }
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let buf = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          const parts = buf.split("\n\n");
          buf = parts.pop() || "";
          for (const block of parts) {
            const line = block.trim().split("\n").find((l) => l.startsWith("data: "));
            if (!line) continue;
            const json = line.slice(6);
            try {
              const evt = JSON.parse(json) as Record<string, unknown>;
              onEvent(evt);
              if (evt.type === "complete" && !settled) {
                settled = true;
                resolve({
                  run_id: String(evt.run_id),
                  results: evt.results as EvalResult[],
                  summary_by_mode: evt.summary_by_mode as EvalCompletePayload["summary_by_mode"],
                  dataset_source: String(evt.dataset_source ?? ""),
                });
              }
              if (evt.type === "error") {
                reject(new Error(String(evt.message)));
                settled = true;
                return;
              }
            } catch {
              /* ignore */
            }
          }
        }
        if (!settled) reject(new Error("Evaluation stream ended without a complete event"));
      })
      .catch(reject);
  });
}

export async function runEvalSync(body?: Partial<EvalRunBody>) {
  const { data } = await http.post<EvalCompletePayload & { run_id: string }>("/api/eval/run_sync", body ?? {});
  return data;
}

export type LTMMeta = {
  id: number;
  session_id: string | null;
  timestamp: string | null;
  scenario_tag: string | null;
  memory_mode: string | null;
  retrieval_count: number;
  excerpt: string;
  shared?: boolean;
};

export async function memoryList(sessionId?: string) {
  const q = sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : "";
  const { data } = await http.get<{ entries: LTMMeta[]; total_size_kb: number }>(`/api/memory/list${q}`);
  return data;
}

export async function memoryShare(entryId: number, sessionId: string, shared: boolean) {
  const { data } = await http.patch<{ status: string; shared: boolean }>(
    `/api/memory/share/${entryId}?session_id=${encodeURIComponent(sessionId)}`,
    { shared }
  );
  return data;
}

export async function securityStatus(sessionId: string) {
  const { data } = await http.get<SecurityStatus>(
    `/api/security/status?session_id=${encodeURIComponent(sessionId)}`
  );
  return data;
}

export async function auditTrail(sessionId: string, limit = 50) {
  const { data } = await http.get<AuditEntry[]>(
    `/api/audit/trail?session_id=${encodeURIComponent(sessionId)}&limit=${limit}`
  );
  return data;
}

export async function auditVerify() {
  const { data } = await http.get<AuditVerifyResult>("/api/audit/verify");
  return data;
}

export async function memoryDelete(id: number, sessionId?: string) {
  const q = sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : "";
  const { data } = await http.delete<{ status: string }>(`/api/memory/delete/${id}${q}`);
  return data;
}

export async function memoryClear() {
  const { data } = await http.delete<{ deleted: number }>("/api/memory/clear");
  return data;
}

export async function evalHistory() {
  const { data } = await http.get<Record<string, unknown>[]>("/api/eval/history");
  return data;
}

export function evalExportUrl() {
  return "/api/eval/export";
}
