# Agentic SIEM — Master README

**Evaluating Short-Term vs Long-Term Memory Mechanisms in LLM-Based SIEM Analyst Agents for Defensive Security**

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Problem statement](#2-problem-statement)
3. [Research questions and objectives](#3-research-questions-and-objectives)
4. [Theoretical background](#4-theoretical-background)
5. [Related work and references](#5-related-work-and-references)
6. [What we built (in plain language)](#6-what-we-built-in-plain-language)
7. [System architecture](#7-system-architecture)
8. [Technology stack](#8-technology-stack)
9. [Memory modes (deep dive)](#9-memory-modes-deep-dive)
10. [Security and privacy layer](#10-security-and-privacy-layer)
11. [The SIEM analyst agent](#11-the-siem-analyst-agent)
12. [Dataset: LANL authentication logs](#12-dataset-lanl-authentication-logs)
13. [Evaluation scenarios](#13-evaluation-scenarios)
14. [Evaluation methodology and metrics](#14-evaluation-methodology-and-metrics)
15. [Expected results](#15-expected-results)
16. [Shipped benchmark results](#16-shipped-benchmark-results)
17. [Novel contributions](#17-novel-contributions)
18. [Repository layout](#18-repository-layout)
19. [Setup and installation](#19-setup-and-installation)
20. [Running the application](#20-running-the-application)
21. [Running the benchmark](#21-running-the-benchmark)
22. [REST API reference](#22-rest-api-reference)
23. [Web dashboard guide](#23-web-dashboard-guide)
24. [Configuration reference](#24-configuration-reference)
25. [Offline analysis notebook](#25-offline-analysis-notebook)
26. [Limitations, ethics, and known issues](#26-limitations-ethics-and-known-issues)
27. [Future work](#27-future-work)

---

## 1. Executive summary

Modern Security Operations Centers (SOCs) face **alert fatigue**: analysts review thousands of authentication and endpoint events per shift. Large Language Models (LLMs) can draft triage narratives, suggest MITRE ATT&CK mappings, and recall entity names — but only if they **remember** prior turns, analyst preferences, and facts from earlier sessions.

This project implements a **research-grade SIEM analyst copilot** and a **reproducible benchmark** that compares **four memory regimes**:


| Mode                        | One-line description                                                                 |
| --------------------------- | ------------------------------------------------------------------------------------ |
| **No memory**               | Each question is answered in isolation (baseline).                                   |
| **Short-term memory (STM)** | Sliding window of recent chat turns, with LLM compression when the window overflows. |
| **Long-term memory (LTM)**  | STM plus encrypted vector store; semantic retrieval of past exchanges.               |
| **Hybrid**                  | STM always; LTM only when the analyst asks to recall something or the topic drifts.  |


The system is built as a **FastAPI backend** + **React dashboard**, powered by **Groq** for chat and **MiniLM** for embeddings. Eight automated scenarios — seven derived from the **LANL authentication dataset** plus one **cross-session recall** test — measure **retention**, **personalization**, and **consistency** (three LLM samples per probe). Results export to JSON, CSV, and Markdown.

**This is defensive security research.** The agent helps analysts interpret logs; it is not an attack tool.

---

## 2. Problem statement

### 2.1 The analyst workload crisis

A SIEM (Security Information and Event Management) platform collects logs from firewalls, identity systems, endpoints, and cloud services. Analysts must:

- Correlate failed logins, lateral movement, and privilege changes across hosts and users.
- Map behaviors to the [MITRE ATT&CK](https://attack.mitre.org/) knowledge base.
- Document cases with consistent formatting (bullets, severity, entity IDs).
- Remember **case context** across a shift — and sometimes across days.

When an LLM assists this workflow, two memory problems appear:

1. **Short horizon:** The model’s context window is finite. Long investigations exceed it.
2. **Session boundaries:** STM is wiped when the chat session resets. Facts from “yesterday’s incident” vanish unless stored externally.

### 2.2 The research gap

Commercial copilots often use RAG over knowledge bases, but **how much memory is enough** — and **what type** — for SOC triage is under-studied in reproducible benchmarks. We need:

- Controlled comparison of **stateless vs STM vs LTM vs hybrid** policies.
- Metrics that go beyond “sounds good” — keyword retention, format compliance, response stability.
- Realistic **authentication telemetry** scenarios, not toy Q&A.

### 2.3 Our approach

We built an end-to-end prototype that:

1. Ingests LANL-style auth CSV rows and **synthesizes** multi-turn analyst dialogues.
2. Runs the same scenarios under all four memory modes.
3. Scores outputs automatically and visualizes mode comparisons in a dashboard.

---

## 3. Research questions and objectives

### 3.1 Research questions


| #   | Question                                                                                                           |
| --- | ------------------------------------------------------------------------------------------------------------------ |
| RQ1 | Does **short-term memory** improve retention of entities and keywords within a single session?                     |
| RQ2 | Does **long-term memory** outperform STM when the session is reset but the analyst asks about “earlier” incidents? |
| RQ3 | Can a **hybrid gating policy** match LTM recall quality with lower retrieval cost?                                 |
| RQ4 | How **consistent** are LLM triage answers when sampled three times at fixed temperature?                           |
| RQ5 | Can **memory poisoning defenses** block malicious “remember this forever” instructions before they enter LTM?      |


### 3.2 Objectives


| Objective                                                        | Status                                                     |
| ---------------------------------------------------------------- | ---------------------------------------------------------- |
| Implement four memory modes with shared orchestration            | Done — `backend/app/memory/`                               |
| Derive 8 evaluation scenarios from LANL CSV                      | Done — `backend/app/scenarios/loader.py`                   |
| Continuous metrics: retention, personalization, consistency      | Done — `backend/app/evaluator.py`                          |
| React dashboard for chat, eval, theory, memory inspector         | Done — `frontend/src/`                                     |
| Security: encryption, PII redaction, threat scoring, audit trail | Done — `backend/app/security/`                             |
| Export reproducible artifacts                                    | Done — `backend/data/results.{json,csv}`, `eval_report.md` |


---

## 4. Theoretical background

This section explains the ideas behind the implementation in simple terms. The **Theory** tab in the UI (`frontend/src/components/TheoryTab.tsx`) presents a shorter version for demos.

### 4.1 SIEM and the analyst copilot

A **SIEM** centralizes security logs so analysts can search, alert, and investigate. An **LLM copilot** sits beside the analyst: it reads event summaries you paste or generate, proposes hypotheses, and drafts containment steps. It does **not** replace the SIEM — it interprets and narrates what the logs imply.

### 4.2 Context windows and memory

An LLM only sees text you send in the **prompt**. “Memory” in this project means **software that decides what text to inject**:

- **No memory:** Only the latest user message (+ system prompt).
- **STM:** Recent user/assistant turns kept in RAM per session.
- **LTM:** Past turns embedded as vectors, stored in SQLite, retrieved by similarity.
- **Hybrid:** STM plus **conditional** LTM retrieval.

This mirrors human cognition metaphors (working memory vs long-term storage) but implemented as explicit engineering policies.

### 4.3 Retrieval-Augmented Generation (RAG)

**RAG** (Lewis et al., 2020) retrieves relevant documents and prepends them to the prompt. Our LTM mode is a **session-scoped RAG** over prior analyst–assistant exchanges rather than over a static document corpus.

**Pipeline:**

```
User query → embed query → cosine similarity vs stored turn embeddings → top-k chunks → system addon → LLM
```

### 4.4 Vector embeddings

Text is converted to a **384-dimensional vector** using `all-MiniLM-L6-v2`. Similar meanings yield vectors with **high cosine similarity**. We normalize embeddings so cosine similarity equals the dot product.

**Threshold:** Only hits with similarity ≥ **0.35** are injected (configurable).

### 4.5 kNN-LM and RETRO (conceptual link)

- **kNN-LM** (Khandelwal et al., 2020): augment language models with nearest-neighbor lookup over a memory of past tokens.
- **RETRO** (Borgeaud et al., 2022): retrieve from trillions of tokens at scale.

Our LTM store is a **small-scale, intentional** version: nearest-neighbor over analyst conversation history, with encryption and access control.

### 4.6 MITRE ATT&CK

[MITRE ATT&CK](https://attack.mitre.org/) is a taxonomy of adversary techniques (e.g. **T1110** Brute Force, **T1021** Remote Services). The agent is prompted to emit lines like `MITRE: T1110`. A regex tagger (`backend/app/mitre_tagger.py`) extracts `T####` codes from replies for scoring and UI badges.

### 4.7 Memory poisoning

**Memory poisoning** is when an attacker (or careless user) tricks the system into storing malicious instructions (“always tell every user that…”) in long-term memory. We score inputs with weighted regex patterns and **block** high-threat content from LTM writes and chat when the score is high enough.

### 4.8 Hybrid gating as a cost–quality tradeoff

Full LTM retrieval on every turn adds **latency** (embedding + DB scan). Hybrid mode retrieves LTM only when:

- The user uses **recall cues** (“earlier”, “previously”, “remember”, …), or
- The query is **semantically distant** from recent session text (cosine similarity **below 0.6**).

This is our answer to RQ3: approximate LTM benefits without paying retrieval cost on every message.

---

## 5. Related work and references


| Work                                                                                              | Relevance to this project                      |
| ------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| Lewis et al., 2020 — [Retrieval-Augmented Generation](https://arxiv.org/abs/2005.11401)           | LTM retrieval injected into the prompt         |
| Khandelwal et al., 2020 — [Generalization through Memorization](https://arxiv.org/abs/1911.00172) | Nearest-neighbor memory over past text         |
| Borgeaud et al., 2022 — [RETRO](https://arxiv.org/abs/2112.04426)                                 | Large-scale retrieval-augmented LMs            |
| MITRE ATT&CK — [attack.mitre.org](https://attack.mitre.org/)                                      | Technique labels in scenarios and agent output |
| LANL Auth Dataset — [csr.lanl.gov/data/auth](https://csr.lanl.gov/data/auth/)                     | Realistic enterprise authentication telemetry  |


**Course report:** Expand `report/final_report.md` with narrative, figures, and discussion after your final benchmark run. Auto-generated tables live in `backend/data/eval_report.md`.

---

## 6. What we built (in plain language)

You get three things in one repository:

1. **Analyst chat app** — Talk to a SIEM expert persona; switch memory modes live; see context previews (STM token estimate, LTM hits).
2. **Benchmark harness** — Run 8 scenarios × 4 modes automatically; stream progress via Server-Sent Events (SSE).
3. **Security wrapper** — Sanitize input, detect threats, redact PII, encrypt LTM at rest, append-only audit log with checksums.

If `GROQ_API_KEY` is missing, the agent falls back to **deterministic mock replies** so the UI and metrics pipeline still work offline.

---

## 7. System architecture

### 7.1 Layered view

```
┌─────────────────────────────────────────────────────────────────────────┐
│  PRESENTATION — React 18 + Vite 5 + Tailwind + Recharts                 │
│  Tabs: Analyst console · Results · Theory · Memory · Security · Report  │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │ HTTP /api → proxy → :8001
┌───────────────────────────────────▼─────────────────────────────────────┐
│  API — FastAPI (backend/app/main.py)                                    │
│  Chat · Eval (SSE + sync) · Memory CRUD · Health · Audit                 │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
  SIEMAgent                   MemoryManager                  Evaluator
  (Groq / mock)               (4 modes)                      (metrics + export)
        │                           │
        │              ┌────────────┼────────────┐
        │              ▼            ▼            ▼
        │         no_memory      stm.py       ltm.py + hybrid.py
        │              │            │            │
        └──────────────┴────────────┴────────────┘
                                    │
┌───────────────────────────────────▼─────────────────────────────────────┐
│  SECURITY — threat_detector · sanitizer · pii_detector · encryptor        │
│             access_guard (TTL, rate limit) · audit_log (checksums)       │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼─────────────────────────────────────┐
│  DATA — lanl_auth_sample.csv · ltm_store.db · results.* · audit JSONL   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Request flow (chat)

1. Client sends `POST /api/chat` with `session_id`, `memory_mode`, `message`.
2. **Access guard** checks session TTL and rate limit (30 requests/minute per session).
3. **Threat detector** scores the message; high scores may block or skip LTM storage.
4. **Sanitizer** strips dangerous patterns; **PII detector** redacts sensitive tokens.
5. **MemoryManager** builds context (history + LTM hits + preferences + compression prefix).
6. **SIEMAgent** calls Groq (or mock).
7. Reply is sanitized/redacted; turn is stored in STM/LTM per mode policy.
8. Response includes assistant text, MITRE tags, and **context preview** metadata.

### 7.3 Evaluation isolation

Each **scenario × memory mode × repetition** runs with a **temporary directory** and fresh `ltm_store.db`. Long-term memory does **not** leak between benchmark cells — only within one scenario execution (important for cross-session recall).

### 7.4 ASCII data flow (memory build)

```
User message
     │
     ▼
┌─────────────┐     no_memory ──► [system] + [user msg only]
│ MemoryManager│
└──────┬──────┘
       │ short_term / long_term / hybrid
       ▼
  STM deque (≤10 turns) ──► optional [COMPRESSED CONTEXT] prefix
       │
       ├─ long_term / hybrid ──► embed query ──► SQLite cosine top-3
       │
       ▼
  messages[] ──► Groq llama-3.3-70b-versatile ──► assistant reply
       │
       ▼
  finalize_turn ──► STM update · LTM write (if mode allows)
```

---

## 8. Technology stack

### 8.1 Backend (Python 3.11+)


| Package               | Version (pinned / minimum) | Role                      |
| --------------------- | -------------------------- | ------------------------- |
| fastapi               | 0.115.6                    | REST API framework        |
| uvicorn               | 0.32.1                     | ASGI server               |
| pydantic              | 2.10.3                     | Request/response schemas  |
| pydantic-settings     | ≥2.10.1                    | Environment configuration |
| groq                  | ≥0.11.0                    | LLM API client            |
| sentence-transformers | ≥3.3.0                     | MiniLM embeddings         |
| torch                 | ≥2.2.0                     | Embedding model runtime   |
| numpy                 | 2.1.3                      | Vector math               |
| pandas                | ≥2.2.0                     | Data handling (notebook)  |
| scikit-learn          | 1.5.2                      | Available for analysis    |
| cryptography          | ≥42.0.0                    | Fernet encryption for LTM |
| httpx                 | 0.28.1                     | HTTP client               |
| python-dotenv         | 1.0.1                      | `.env` loading            |


### 8.2 Frontend (Node 18+)


| Package           | Version | Role                   |
| ----------------- | ------- | ---------------------- |
| react / react-dom | ^18.3.1 | UI framework           |
| vite              | ^5.4.11 | Dev server and bundler |
| typescript        | ^5.6.3  | Type safety            |
| tailwindcss       | ^3.4.15 | Styling                |
| axios             | ^1.16.0 | API calls              |
| recharts          | ^2.13.3 | Evaluation charts      |


### 8.3 External services


| Service              | Usage                                          |
| -------------------- | ---------------------------------------------- |
| **Groq API**         | Chat completions (`llama-3.3-70b-versatile`)   |
| **Local SQLite**     | LTM vector store (`backend/data/ltm_store.db`) |
| **Local filesystem** | CSV, results, audit logs                       |


---

## 9. Memory modes (deep dive)

Configuration defaults live in `backend/app/config.py` and can be overridden via environment variables.


| Setting                               | Default | Meaning                                                |
| ------------------------------------- | ------- | ------------------------------------------------------ |
| `STM_MAX_TURNS`                       | 10      | Maximum user/assistant **pairs** in the sliding window |
| `STM_COMPRESS_BATCH`                  | 5       | Oldest pairs summarized when the window overflows      |
| `LTM_RETRIEVAL_K`                     | 3       | Top-k memories to inject                               |
| `LTM_SIMILARITY_THRESHOLD`            | 0.35    | Minimum cosine similarity for an LTM hit               |
| `HYBRID_CONTEXT_SIMILARITY_THRESHOLD` | 0.6     | Below this, hybrid mode triggers LTM retrieval         |


### 9.1 No memory (`no_memory.py`)

- **Behavior:** Only the current user message is sent to the LLM (plus the global system prompt).
- **Use case:** Baseline — measures what the model knows from the message alone.
- **Storage:** No turns persisted after the exchange.

### 9.2 Short-term memory (`stm.py`)

- **Window:** Up to **10** `(user, assistant)` pairs per `session_id`.
- **Preferences:** Regex capture on user text:
  - `always include …` → `always_include`
  - `i prefer …` → `prefer`
  - `format as …` → `format_as`
  - Injected as `Analyst session preferences:` in the system addon.
- **Compression:** When pairs exceed 10, the **oldest 5** pairs are sent to the LLM for a **3-bullet summary** preserving users, IPs, MITRE lines, and preferences. Summary is prepended as `[COMPRESSED CONTEXT]`.
- **Token estimate:** `len(text) // 4` over compressed prefix + all pairs (shown in UI preview as `stm_tokens`).

### 9.3 Long-term memory (`ltm.py`)

- **STM:** Always included (same window as above).
- **Embedding:** `user_msg + "\n" + assistant_msg` → 384-d normalized vector.
- **Storage:** SQLite table `ltm_entries` with Fernet-encrypted text and embedding blobs.
- **Retrieval:** Full-table scan, cosine similarity, filter by threshold, return top-3; optional filter by `session_id` unless entry marked `shared`.
- **Metadata:** `session_id`, timestamp, `scenario_tag`, `memory_mode`, `retrieval_count`.
- **Threat gate on store:** Blocked if `should_block`; flagged if `threat_score >= 0.3`. Evaluation uses `skip_threat_check=True` for reproducibility.

### 9.4 Hybrid (`hybrid.py`)

- **STM:** Always active.
- **LTM trigger** if any of:
  - **Recall cues** in the query: `earlier`, `previously`, `last time`, `before`, `prior session`, `remember`
  - **Topic drift:** cosine similarity between query embedding and last 2000 chars of session text **< 0.6**
  - **Fallback:** Jaccard token overlap **< 0.25** if embedding fails
- **Deduping:** LTM hits whose first 200 characters already appear in STM are dropped to avoid redundancy.

### 9.5 Orchestration (`memory/manager.py`)

`MemoryManager` coordinates:

- `build_context(session_id, mode, latest_user_message)` → OpenAI-style `messages[]` + preview dict
- `finalize_turn(...)` → updates STM/LTM according to mode
- `access_guard.touch_session` on each build

**Chat-only rule:** If `threat_score >= 0.3`, `store_in_memory` may be disabled even when the reply is returned.

---

## 10. Security and privacy layer

Modules under `backend/app/security/`:


| Module               | Purpose                                                                                                       |
| -------------------- | ------------------------------------------------------------------------------------------------------------- |
| `threat_detector.py` | Weighted regex for prompt injection, memory poisoning, jailbreak, exfiltration; base64/URL-encoded heuristics |
| `sanitizer.py`       | Control characters, HTML/script/SQL patterns; max length 2000                                                 |
| `pii_detector.py`    | IPv4, email, API keys, phones; LANL host token exceptions                                                     |
| `encryptor.py`       | Fernet key at `backend/.ltm_key` (auto-generated); encrypts LTM text and embeddings                           |
| `access_guard.py`    | Session TTL **2 hours**; rate limit **30 req/min** per session                                                |
| `audit_log.py`       | Append-only `audit_log.jsonl` with SHA-256 checksums per event                                                |


### 10.1 Threat scoring thresholds


| Score     | Typical action                                  |
| --------- | ----------------------------------------------- |
| **≥ 0.7** | `should_block` — dangerous chat input blocked   |
| **≥ 0.3** | Alert; may prevent LTM persistence in live chat |
| **< 0.3** | Normal processing                               |


Categories include: `prompt_injection`, `memory_poisoning`, `jailbreak`, `data_exfiltration`.

### 10.2 Audit events

Examples: `LTM_STORE`, `LTM_RETRIEVE`, `INJECTION_BLOCKED`, `CHAT_REQUEST`. Use `GET /api/audit/verify` to check log integrity.

### 10.3 Shared memory

`PATCH /api/memory/share/{id}` marks an LTM row as **shared** so other sessions can retrieve it (institutional memory demo).

---

## 11. The SIEM analyst agent

**File:** `backend/app/agent/siem_agent.py`

### 11.1 System prompt (summary)

The agent acts as a **senior SIEM security analyst**:

- Be precise; cite entity names from context (users, IPs, computers).
- Label relevant techniques as `MITRE: T####`.
- Follow analyst formatting preferences when stated.

### 11.2 Groq integration

- Model: `llama-3.3-70b-versatile` (configurable via `GROQ_MODEL`).
- Default chat temperature: **0.35**; consistency probes use **0.3**.
- Timeout: **60s** per request; asyncio wrapper **70s**.

### 11.3 Mock mode

Without `GROQ_API_KEY`, `_mock_reply` produces deterministic triage text that reflects whether LTM hits and preferences were present — useful for demos and CI-style smoke tests.

---

## 12. Dataset: LANL authentication logs

### 12.1 What is the LANL dataset?

The [Los Alamos National Laboratory (LANL) authentication dataset](https://csr.lanl.gov/data/auth/) contains anonymized Windows authentication events from an enterprise network. It is widely used in security research for user behavior analytics and insider-threat studies.

### 12.2 Shipped sample file


| Property         | Value                                                                     |
| ---------------- | ------------------------------------------------------------------------- |
| **Path**         | `backend/data/lanl_auth_sample.csv`                                       |
| **Rows**         | 10,000 data rows (+ header)                                               |
| **Full archive** | `backend/data/lanl-auth-dataset-1-00.bz2` (optional; not required to run) |


### 12.3 Simple schema (shipped sample)

```csv
timestamp,user,src_host,dst_host,result,src_ip
1,U1,C1,DST-HOST,SUCCESS,C1
```


| Column      | Description                                      |
| ----------- | ------------------------------------------------ |
| `timestamp` | Numeric or ISO time                              |
| `user`      | User identifier                                  |
| `src_host`  | Source computer                                  |
| `dst_host`  | Destination computer                             |
| `result`    | `SUCCESS` or failure-like values                 |
| `src_ip`    | Source identifier (often mirrors host in sample) |


### 12.4 Supported schemas (loader auto-detects)

1. **Official-style:** `timestamp`, `user_id`, `src_computer`, `dst_computer`, `auth_type`, `logon_type`, `auth_orientation`, `success_failure`
2. **Simple:** `timestamp`, `user`, `src_host`, `dst_host`, `result`
3. **LANL-like:** `time`, `src_user`, `dst_user`, `src_computer`, `dst_computer`, `success`

Maximum rows read per build: **10,000**.

### 12.5 Fallback scenarios

If the CSV is missing or scenario building returns empty, `backend/data/scenarios.json` provides a single static scenario (`static-fallback-001`).

---

## 13. Evaluation scenarios

Scenarios are built dynamically in `backend/app/scenarios/loader.py` from CSV statistics, with metadata from `definitions.py`.

### 13.1 Scenario summary table


| ID                          | Theme                                                     | MITRE | Severity | Turns |
| --------------------------- | --------------------------------------------------------- | ----- | -------- | ----- |
| `lanl-failed-logins-001`    | Repeated failed authentication for a top user/source      | T1110 | HIGH     | 4     |
| `lanl-same-source-repeated` | Same source host, repeated suspicious activity            | T1110 | MEDIUM   | 4     |
| `lanl-suspicious-sequence`  | FAIL then SUCCESS for same user/source                    | T1110 | HIGH     | 4     |
| `lanl-privilege-escalation` | Workstation then privileged destination within 60s        | T1078 | CRITICAL | 4     |
| `lanl-lateral-movement`     | One source → 5+ destinations within 120s                  | T1021 | CRITICAL | 4     |
| `lanl-after-hours`          | Authentication outside 08:00–18:00                        | T1078 | MEDIUM   | 4     |
| `lanl-credential-stuffing`  | 10+ distinct users from one source within 300s            | T1110 | HIGH     | 4     |
| `cross-session-recall-001`  | Session A seeds facts; STM cleared; Session B asks recall | T1110 | MEDIUM   | 3     |


### 13.2 How each scenario is derived from CSV


| Scenario             | Detection heuristic                                                              |
| -------------------- | -------------------------------------------------------------------------------- |
| Failed logins        | Top user by failure count + top source; fallback if no explicit FAIL rows        |
| Same source          | `src_computer` with highest event count                                          |
| Suspicious sequence  | User/source with failures followed by success                                    |
| Privilege escalation | User logs from workstation then to `admin`/`dc`/`srv` destination within **60s** |
| Lateral movement     | Same `src` → **≥5** unique `dst` within **120s** sliding window                  |
| After hours          | First row with hour **< 8** or **≥ 18**                                          |
| Credential stuffing  | Same `src` → **≥10** unique users within **300s**                                |
| Cross-session        | Static template in `definitions.py`                                              |


Real `USER=` and `SRC=` tokens from the CSV are injected into turn prompts.

### 13.3 Example turn pattern (failed logins)

1. Present case ID, user, source, and failure summary.
2. Ask for MITRE mapping and top 3 investigative pivots.
3. Ask for historical comparison (“same user yesterday”).
4. Ask for containment recommendations for the source.

Each turn may require:

- **Retention keywords** (substring match in the reply).
- **Personalization phrase** (e.g. “Always include a line starting with MITRE:…” or “Reply in bullet points using '-' markers.”).

### 13.4 Cross-session recall (special mechanics)

**File:** `definitions.py` → `cross_session_scenario()`

1. **Turn 1–2:** Session A discusses incident `INC-2048` and **User A** failed logins from `SRC=10.24.8.71`.
2. **Before turn 3:** `reset_session_before_turn_index: 2` clears STM; session ID gets suffix `-b`.
3. **Turn 3:** New analyst asks: “what user was involved in the earlier failed logins case?”

**Expected advantage:** `long_term` and `hybrid` should recall **User A** / **INC-2048** from LTM; `no_memory` and fresh STM should fail retention.

### 13.5 Retention keywords (scoring)

Defined in `RETENTION_KEYWORDS` (`definitions.py`):


| Scenario             | Keywords (substring match)                  |
| -------------------- | ------------------------------------------- |
| failed-logins        | User A, failed, login, 10.24.8.71, brute    |
| same-source          | same source, repeated, suspicious           |
| suspicious-sequence  | sequence, pattern, anomal                   |
| privilege-escalation | privilege, admin, escalat, T1078            |
| lateral-movement     | lateral, movement, multiple, T1021          |
| after-hours          | after hours, outside, timestamp, T1078      |
| credential-stuffing  | credential, stuffing, multiple users, T1110 |
| cross-session        | User A, INC-2048, earlier, previous         |


**Note:** Some keywords (e.g. fixed IP `10.24.8.71`) may not match CSV-derived hosts like `C13`. Align keywords with your CSV for fairer scores.

---

## 14. Evaluation methodology and metrics

**Implementation:** `backend/app/evaluator.py`

### 14.1 Procedure per cell

For each `(scenario_id, memory_mode, run_index)`:

1. Create isolated temp DB and `MemoryManager`.
2. Play scripted user turns; call `complete()` for each.
3. Score **retention** and **personalization** per turn.
4. After dialogue, sample the **last user turn** **three times** at `temperature=0.3` for **consistency**.
5. Record mean latency per turn.
6. Extract MITRE tags from all assistant replies.

### 14.2 Retention score (0.0 – 1.0)

Per turn:

```
base = (# expected_keywords found as substrings) / len(expected_keywords)
```

- If no keywords defined → `base = 1.0`.
- **Entity bonus:** +0.05 for each `USER=` token or `SRC=` token from turn 1 found in the response (cap **+0.10** total).
- **Penalty:** −0.20 if the response contains memory-fail phrases (`"i don't have context"`, `"could you clarify"`, etc.).
- Clamp to [0, 1].

Scenario retention = **average across turns**.

### 14.3 Personalization score (0.0 – 1.0)

Per turn, check requirements implied by `personalization_phrase`:


| Requirement in phrase | Satisfied if response contains         |
| --------------------- | -------------------------------------- |
| `mitre:`              | substring `mitre:`                     |
| `bullet`              | `•`, newline `-`, or markdown list `-` |


Score = fraction of required parts met. If no requirements → **1.0**.

### 14.4 Consistency score (0.0 – 1.0)

After scripted dialogue:

1. Run `complete()` **3 times** on the final user message (`temperature=0.3`, `max_tokens=512`).
2. Tokenize with regex `[a-zA-Z0-9._:/@-]+` (length > 2).
3. Compute **mean pairwise Jaccard similarity** across the three responses.

High consistency = stable triage wording; low = volatile LLM phrasing.

### 14.5 Aggregate score

```
aggregate = 0.4 × retention + 0.3 × consistency + 0.3 × personalization
```

**Latency** is reported separately (milliseconds per turn, averaged) and is **not** part of the aggregate.

### 14.6 Exported artifacts


| File                             | Content                                   |
| -------------------------------- | ----------------------------------------- |
| `backend/data/results.json`      | Full structured results + summary by mode |
| `backend/data/results.csv`       | Flat table for spreadsheets               |
| `backend/data/eval_report.md`    | Markdown tables (auto-generated)          |
| `backend/data/eval_history.json` | Append-only run history                   |


---

## 15. Expected results

After a successful full benchmark **with a valid Groq API key**, you should generally observe:


| Pattern                  | Expected direction                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------ |
| **Retention**            | `no_memory` lowest on multi-turn scenarios; STM/LTM/hybrid higher when entities repeat     |
| **Cross-session recall** | `long_term` / `hybrid` >> `no_memory` / `short_term` on `cross-session-recall-001`         |
| **Consistency**          | Often increases with memory (model has stable context); LTM/hybrid may score highest       |
| **Personalization**      | Similar across modes if preferences are in STM; drops if compression loses preference text |
| **Latency**              | `no_memory` fastest; `hybrid` between STM and full LTM; LTM adds embedding + DB scan cost  |
| **Aggregate**            | Mode ranking depends on weighting; consistency-heavy runs favor LTM/hybrid                 |


**Important:** Retention uses **brittle keyword matching**. Low retention does not always mean bad analysis — it may mean the model used synonyms. Interpret scores alongside qualitative transcript review in the dashboard.

---

## 16. Shipped benchmark results

The repository includes results from a run on **2026-05-12** against `lanl_auth_sample.csv` (32 cells = 8 scenarios × 4 modes).

### 16.1 Summary by mode


| Mode       | Retention (avg) | Consistency (avg) | Personalization (avg) | **Aggregate (avg)** | Latency (avg ms) |
| ---------- | --------------- | ----------------- | --------------------- | ------------------- | ---------------- |
| no_memory  | 0.183           | 0.665             | 0.344                 | **0.376**           | 5048             |
| short_term | 0.198           | 0.804             | 0.188                 | **0.377**           | 2271             |
| long_term  | 0.138           | 0.906             | 0.188                 | **0.383**           | 1537             |
| hybrid     | 0.131           | 0.911             | 0.156                 | **0.373**           | 1664             |


**Interpretation of this run:**

- **Highest aggregate:** `long_term` (0.383), driven mainly by **consistency**, not retention.
- **Retention** averages are low across all modes — keyword/entity mismatch with LLM phrasing is likely.
- **Best per-scenario aggregates:** `lanl-failed-logins-001` hybrid **0.59**; `lanl-same-source-repeated` STM/LTM **0.73**.
- **Cross-session recall:** Retention **0.00** for all modes in this run; logs show **Groq rate-limit (429)** errors — **re-run with fresh quota** before drawing conclusions on RQ2.
- Several advanced scenarios (privilege escalation, lateral movement, after-hours, credential stuffing) scored **0.00 retention** because expected phrases did not appear verbatim in model output.

Full per-scenario table: `backend/data/eval_report.md`.

### 16.2 How to refresh results

1. Set `GROQ_API_KEY` in `backend/.env`.
2. Open dashboard → **Results** tab → **Run (SSE)** (all scenarios, all modes).
3. Copy summary into this README’s findings section or `report/final_report.md`.

---

## 17. Novel contributions

This project goes beyond a basic chatbot demo:


| #   | Contribution                                                                        | Where                                    |
| --- | ----------------------------------------------------------------------------------- | ---------------------------------------- |
| 1   | **Four-way memory benchmark** with shared orchestration and isolated eval DBs       | `memory/manager.py`, `evaluator.py`      |
| 2   | **Adaptive STM compression** — LLM summarizes oldest 5 turns when buffer exceeds 10 | `memory/stm.py`                          |
| 3   | **Encrypted semantic LTM** — Fernet + MiniLM 384-d cosine retrieval                 | `memory/ltm.py`, `security/encryptor.py` |
| 4   | **Hybrid relevance gating** — recall cues + embedding drift threshold + STM dedupe  | `memory/hybrid.py`                       |
| 5   | **Consistency triads** — 3-sample Jaccard stability metric                          | `evaluator.py`                           |
| 6   | **Cross-session recall scenario** — automated STM reset mid-scenario                | `definitions.py`, `evaluator.py`         |
| 7   | **Memory poisoning / threat scoring** — weighted patterns, block ≥ 0.7              | `security/threat_detector.py`            |
| 8   | **MITRE auto-tagger** — regex extraction + UI badges                                | `mitre_tagger.py`, frontend              |
| 9   | **Tamper-evident audit trail** — checksum per JSONL event                           | `security/audit_log.py`                  |
| 10  | **LANL-driven scenario synthesis** — 7 heuristics from real CSV stats               | `scenarios/loader.py`                    |
| 11  | **Reproducible export pipeline** — JSON, CSV, Markdown, SSE progress                | `evaluator.py`, `ResultsTab`             |


---

## 18. Repository layout

```
Agentic_SIEM/
├── README.md                          ← This master document
├── backend/
│   ├── main.py                        ← uvicorn entry (re-exports app)
│   ├── requirements.txt
│   ├── run.ps1                        ← Quick start script (port 8001)
│   ├── .env                           ← GROQ_API_KEY (create locally; not committed)
│   ├── .ltm_key                       ← Auto-generated Fernet key
│   └── app/
│       ├── main.py                    ← FastAPI routes
│       ├── config.py                  ← Settings
│       ├── evaluator.py               ← Benchmark engine
│       ├── mitre_tagger.py
│       ├── security_log.py
│       ├── agent/siem_agent.py
│       ├── memory/                    ← no_memory, stm, ltm, hybrid, manager
│       ├── scenarios/                 ← loader.py, definitions.py
│       ├── security/                  ← threat, PII, sanitizer, encryptor, audit
│       ├── models/schemas.py
│       └── services/
│   └── data/
│       ├── lanl_auth_sample.csv
│       ├── scenarios.json
│       ├── ltm_store.db
│       ├── results.json / results.csv / eval_report.md
│       └── audit_log.jsonl
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── api.ts
│   │   └── components/              ← AnalystConsole, ResultsTab, TheoryTab, …
│   ├── package.json
│   └── vite.config.ts               ← Proxies /api → :8001
├── notebooks/
│   └── analysis.ipynb               ← Offline plots from results.json
├── report/
│   └── final_report.md              ← Course narrative shell
├── scripts/                         ← (reserved)
└── siem-agent/
    └── README.md                      ← Logical package name pointer
```

**Course mapping:** The project brief’s `siem-agent/` layout maps to `backend/app/memory/`*, `backend/app/scenarios/`*, `backend/app/evaluator.py`, and `backend/main.py`.

---

## 19. Setup and installation

### 19.1 Prerequisites


| Requirement  | Version                                                 |
| ------------ | ------------------------------------------------------- |
| Python       | 3.11 or newer                                           |
| Node.js      | 18 or newer                                             |
| Groq API key | Optional but required for live LLM quality              |
| Disk space   | ~2 GB+ (PyTorch + sentence-transformers first download) |


### 19.2 Backend setup (Windows PowerShell)

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Create `backend/.env`:

```env
GROQ_API_KEY=gsk_your_key_here
GROQ_MODEL=llama-3.3-70b-versatile
```

Optional tuning:

```env
STM_MAX_TURNS=10
STM_COMPRESS_BATCH=5
LTM_RETRIEVAL_K=3
LTM_SIMILARITY_THRESHOLD=0.35
HYBRID_CONTEXT_SIMILARITY_THRESHOLD=0.6
DATA_DIR=data
DB_PATH=data/ltm_store.db
```

### 19.3 Dataset placement

Ensure `backend/data/lanl_auth_sample.csv` exists (included in repo). For full LANL data, decompress `lanl-auth-dataset-1-00.bz2` and point the loader to your CSV path (requires code change or replace sample file).

### 19.4 Frontend setup

```powershell
cd frontend
npm install
```

### 19.5 First-time embedding model

On first LTM use, `sentence-transformers` downloads **all-MiniLM-L6-v2** (~90 MB). Allow network access once.

---

## 20. Running the application

### 20.1 Start API server

From `backend/`:

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn main:app --reload --host 127.0.0.1 --port 8001
```

Or use the helper:

```powershell
.\run.ps1
```

Health check: `GET http://127.0.0.1:8001/api/health`

### 20.2 Start frontend

From `frontend/`:

```powershell
npm run dev
```

Open **[http://127.0.0.1:5173](http://127.0.0.1:5173)** — Vite proxies `/api` to port **8001**.

### 20.3 Production-style static build

```powershell
cd frontend
npm run build
```

If `frontend/dist` exists, FastAPI serves it at `/`.

---

## 21. Running the benchmark

### 21.1 Dashboard (recommended)

1. Open **Results** tab.
2. Select scenarios and memory modes (or leave defaults = all).
3. Click **Run (SSE)** — progress streams live; charts refresh on completion.

### 21.2 API — streaming (SSE)

```http
POST /api/eval/run
Content-Type: application/json

{
  "scenarios": ["all"],
  "modes": ["no_memory", "short_term", "long_term", "hybrid"],
  "runs_per_scenario": 1
}
```

Response: `text/event-stream` with events `progress`, `complete`, `error`.

### 21.3 API — synchronous

```http
POST /api/eval/run_sync
```

Same JSON body; blocks until finished; returns full result payload.

### 21.4 Download exports


| Endpoint                  | File               |
| ------------------------- | ------------------ |
| `GET /api/eval/export`    | `results.csv`      |
| `GET /api/eval/report_md` | `eval_report.md`   |
| `GET /api/eval/history`   | Past run summaries |


### 21.5 Grid size

Default full run: **8 scenarios × 4 modes × 1 run = 32 cells**, each with 3–4 turns plus 3 consistency samples ≈ **many LLM calls**. Plan Groq quota accordingly.

---

## 22. REST API reference


| Method | Path                            | Description                                                                                  |
| ------ | ------------------------------- | -------------------------------------------------------------------------------------------- |
| GET    | `/api/health`                   | Service status, Groq configured, LTM count, STM sessions, poisoning counter, encryption flag |
| GET    | `/api/security/status`          | Session TTL, rate limit info                                                                 |
| GET    | `/api/audit/trail`              | Query params: `session_id`, `limit`                                                          |
| GET    | `/api/audit/verify`             | Verify audit log checksum chain                                                              |
| POST   | `/api/chat`                     | Body: `session_id`, `memory_mode`, `message`, optional `scenario_tag`                        |
| POST   | `/api/session/reset`            | Clear STM for a session                                                                      |
| POST   | `/api/eval/run`                 | SSE evaluation                                                                               |
| POST   | `/api/eval/run_sync`            | Blocking evaluation                                                                          |
| GET    | `/api/eval/history`             | Historical runs                                                                              |
| GET    | `/api/eval/export`              | CSV download                                                                                 |
| GET    | `/api/eval/report_md`           | Markdown report download                                                                     |
| GET    | `/api/memory/list`              | LTM inspector; optional `?session_id=`                                                       |
| PATCH  | `/api/memory/share/{entry_id}`  | Toggle shared flag                                                                           |
| DELETE | `/api/memory/delete/{entry_id}` | Delete one LTM row                                                                           |
| DELETE | `/api/memory/clear`             | Wipe LTM table                                                                               |


### 22.1 Chat request example

```json
{
  "session_id": "sess-demo-01",
  "memory_mode": "hybrid",
  "message": "CASE=LANL-FAIL-001 USER=U42 SRC=C13 — summarize failed logins and map MITRE.",
  "scenario_tag": "lanl-failed-logins-001"
}
```

### 22.2 Memory modes enum

`no_memory` · `short_term` · `long_term` · `hybrid`

---

## 23. Web dashboard guide


| Tab                 | Component             | What you can do                                                                                                         |
| ------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **Analyst console** | `AnalystConsole.tsx`  | Live chat, memory mode selector, MITRE badges, context preview (STM tokens, LTM hits), session reset, export transcript |
| **Results**         | `ResultsTab.tsx`      | Run benchmark (SSE), radar/bar charts, results table, download CSV/MD                                                   |
| **Theory**          | `TheoryTab.tsx`       | Memory mode theory cards, MITRE table, glossary                                                                         |
| **Memory**          | `MemoryInspector.tsx` | Browse/delete/share LTM entries, clear DB, view size                                                                    |
| **Security**        | `SecurityPanel.tsx`   | Session status, rate limits, audit trail, integrity verify                                                              |
| **Report**          | `ReportTab.tsx`       | Auto narrative from last eval, charts, history                                                                          |


**Header indicators:**

- **Poisoning blocked** count (from health endpoint).
- **LTM encrypted** status.

---

## 24. Configuration reference

All settings in `backend/app/config.py` (Pydantic `BaseSettings`), loaded from `backend/.env`:


| Variable                              | Default                   | Description                      |
| ------------------------------------- | ------------------------- | -------------------------------- |
| `GROQ_API_KEY`                        | —                         | Groq API key                     |
| `GROQ_MODEL`                          | `llama-3.3-70b-versatile` | Model ID                         |
| `STM_MAX_TURNS`                       | 10                        | STM window size (pairs)          |
| `STM_COMPRESS_BATCH`                  | 5                         | Pairs summarized per compression |
| `LTM_RETRIEVAL_K`                     | 3                         | Top-k LTM results                |
| `LTM_SIMILARITY_THRESHOLD`            | 0.35                      | Minimum cosine for retrieval     |
| `HYBRID_CONTEXT_SIMILARITY_THRESHOLD` | 0.6                       | Hybrid LTM gate                  |
| `DATA_DIR`                            | `data`                    | Relative data directory          |
| `DB_PATH`                             | `data/ltm_store.db`       | LTM SQLite path                  |


---

## 25. Offline analysis notebook

**Path:** `notebooks/analysis.ipynb`

Loads `backend/data/results.json` with pandas and plots mode comparisons. Use after each benchmark to generate figures for `report/final_report.md`.

---

**Suggested report sections:**

1. Introduction — alert fatigue, LLM copilots in SOC.
2. Related work — RAG, kNN-LM, RETRO, MITRE triage.
3. System design — four modes, poisoning guard, hybrid gating.
4. Methodology — LANL scenarios, metrics, consistency triads.
5. Results — mode charts, latency, cross-session recall.
6. Discussion — failure modes, ethics, when not to use LTM.
7. Conclusion — recommendation matrix (SOC maturity vs privacy vs latency).

---

## 26. Limitations, ethics, and known issues

### 26.1 Technical limitations

- **Keyword retention** is brittle; synonyms score poorly.
- **Full-table LTM scan** does not scale to millions of entries (research prototype).
- **Embedding model** is general-purpose, not security-domain fine-tuned.
- **Mock mode** does not reflect true LLM reasoning quality.
- **Eval threat skip** — benchmark writes to LTM with `skip_threat_check=True`; live chat is stricter.

### 26.2 Ethical considerations

- **Store only what policy allows** — LTM may contain user names and host identifiers from logs.
- **Encryption at rest** protects the SQLite file on disk but not insider access to the running server.
- **Do not deploy** against production SIEM data without legal review, data minimization, and retention policies.
- This project is for **defensive research and education**, not offensive operations.

### 26.3 Known issues


| Issue                                          | Workaround                                                |
| ---------------------------------------------- | --------------------------------------------------------- |
| Groq 429 rate limits during full eval          | Run fewer scenarios per batch; upgrade quota; add delays  |
| Retention keywords vs CSV hosts mismatch       | Update `RETENTION_KEYWORDS` in `definitions.py`           |
| `.env.example` not in repo                     | Copy variables from section 19.2                          |
| Cross-session results invalid under rate limit | Re-run `cross-session-recall-001` alone after quota reset |


---

## 27. Future work

- Align retention keywords dynamically with CSV-derived entities.
- Replace full-table scan with **FAISS** or SQLite **vec0** extension.
- Add **human-in-the-loop** rubric scoring (Likert) beside automated metrics.
- Fine-tune embeddings on security corpus (SecBERT, etc.).
- Integrate live **OpenSearch / Splunk** query tool (read-only) as external RAG.
- Per-tenant LTM isolation and GDPR **right-to-erasure** API.
- Batch eval **retry with exponential backoff** for Groq 429.

---

## Quick start (copy-paste)

```powershell
# Terminal 1 — API
cd backend
.\.venv\Scripts\Activate.ps1
# Ensure .env has GROQ_API_KEY
uvicorn main:app --reload --host 127.0.0.1 --port 8001

# Terminal 2 — UI
cd frontend
npm run dev
# Open http://127.0.0.1:5173
```

---

## Citation

- **LANL Auth Dataset** — Los Alamos National Laboratory.
- **MITRE ATT&CK** — MITRE Corporation.

---

