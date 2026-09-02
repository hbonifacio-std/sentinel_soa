# Requirements & Business Logic

## 1. Functional Requirements (FR)

| ID | Requirement | Implemented By |
|---|---|---|
| FR-01 | The system must ingest telemetry log events (single, batch, and raw formats) from authenticated external clients. | `POST /api/v1/telemetry/`, `/ingest/batch`, `/ingest/raw` (`telemetry.py`) |
| FR-02 | The system must authenticate telemetry clients using either HMAC-signed requests (log shippers) or Client ID/API Key headers, without relying solely on network trust. | `verify_api_key_header`, HMAC verification (`infrastructure/security`) |
| FR-03 | The system must group incoming log events into time/session-scoped windows per `source_id`/`source_ip` before analysis. | `TelemetryProcessingService`, `TelemetryWindow`, `redis_telemetry_window_cache.py` |
| FR-04 | The system must never discard a telemetry window solely because the AI analysis backend (MCP) is temporarily unavailable; it must queue and retry. | `AgentRunner` (`_analysis_queue`, exponential backoff retry, MCP reconnect loop) |
| FR-05 | The system must combine deterministic heuristic scoring with LLM-based reasoning to classify a window as a threat, and must express results using MITRE ATT&CK tactic/technique fields. | `ThreatHeuristics` + `analyze_web_activity` MCP tool, `AnalysisReportResponse` |
| FR-06 | When a threat is detected, the system must automatically enrich the verdict with historical alerts for the same source IP. | `OrchestratorAgent._enrich_with_historical_context`, `get_threat_context` MCP tool |
| FR-07 | The system must cache identical analysis results to avoid redundant LLM calls for the same telemetry payload. | `OrchestratorAgent._check_cache` / `_set_cache` (Redis, 1h TTL) |
| FR-08 | The system must expose paginated analytics endpoints for raw telemetry, analysis reports, and aggregate stats, and must support reviewing, annotating, and resolving reports. | `analytics.py` endpoints |
| FR-09 | The system must let analysts run ad-hoc, natural-language forensic queries that are translated into a bounded MongoDB filter, executed, and summarized into a markdown report with highlights. | `forensic.py`, `generate_mongo_query_from_nl`, `generate_forensic_report_from_logs` MCP tools |
| FR-10 | The system must persist a history of forensic analyses per source and allow retrieval by ID. | `ForensicService`, `GET /api/v1/forensic/history`, `/history/{analysis_id}` |
| FR-11 | The system must support CRUD and versioning of heuristic detection rules, with an auditable activation workflow (create → version → activate). | `rules.py`, `RulesEngineService`, `docs/rules/README.md` |
| FR-12 | The system must authenticate human users (username/password) via an OAuth2 password flow and issue JWTs carrying a role claim. | `auth.py` (`POST /api/v1/auth/token`), `AuthService` |
| FR-13 | The system must support instantaneous logout by revoking a specific JWT via a server-side blacklist (JTI), not merely by client-side token deletion. | `TokenBlacklistRepository`, `docs/JWT_BLACKLIST_AND_LOGOUT.md` |
| FR-14 | The system must enforce Role-Based Access Control (`admin`, `analyst`, `viewer`) on management and analytics endpoints. | `get_admin_user`, `get_analyst_user` dependencies |
| FR-15 | The frontend must present a real-time SOC dashboard (KPIs, threat-level and MITRE tactic charts, attack timeline), an alerts/investigation table, a log explorer, a rules manager, and an AI forensic chat workspace. | `frontend/src/features/*` |
| FR-16 | The system must support multiple, hot-swappable LLM providers (Ollama local models, Google Gemini, OpenAI, Groq) selectable per analysis call via a model catalog. | `mcp_servers/log_analysis_server/config.py`, `llm_providers/*` |
| FR-17 | A simulated victim application and traffic generator must produce labeled benign/malicious HTTP traffic for reproducible detection testing, without exposing the detection stack to that traffic. | `victim_app/main.py`, `pentesting/traffic_simulator.py` |

## 2. Non-Functional Requirements (NFR)

| ID | Requirement | Notes |
|---|---|---|
| NFR-01 | **Resilience:** the telemetry ingestion and analysis pipeline must survive MCP server restarts/outages without data loss, using bounded, backing-off retries. | `AgentRunner._mcp_reconnect_loop`, `_ANALYSIS_MAX_RETRIES` |
| NFR-02 | **Network Isolation:** the victim application and attacker simulator must be confined to a DMZ network segment with no direct route to MongoDB, Redis, or the MCP/LLM stack. | `docker-compose.yml` (`dmz_net`, `log_net`, `sentinel_net`) |
| NFR-03 | **Integrity & Anti-Replay:** telemetry ingestion must be protected against tampering and replay attacks via HMAC-SHA256 signatures and a bounded timestamp window. | `docs/SECURITY_IMPLEMENTATION.md` §2 |
| NFR-04 | **Confidentiality:** user passwords must never be stored in plaintext (bcrypt hashing) and provider API keys must not be exposed in logs (`SecretStr`). | `password_hasher.py`, `config.py` (`SecretStr`) |
| NFR-05 | **Modularity / Maintainability:** the Core Orchestrator must follow Hexagonal Architecture, keeping `domain` free of technical dependencies and `application` free of direct `infrastructure` imports. | `docs/PLAN_REFACTORIZACION_HEXAGONAL_CORE_ORCHESTRATOR.md`, `test/architecture/test_layering_rules.py` |
| NFR-06 | **Auditability:** every heuristic rule change and version activation must be recorded in an append-only audit log. | `mongo_audit_repository.py`, `RuleAuditEntry` |
| NFR-07 | **Extensibility:** adding a new LLM provider or model must not require changes to the analysis service or endpoints — only to the provider factory/catalog. | `llm_providers/base.py`, `create_llm_provider` factory |
| NFR-08 | **Performance:** repeated identical telemetry analyses must be served from cache rather than re-invoking the LLM. | Redis analysis cache (1h TTL) |
| NFR-09 | **Rate Limiting:** public-facing endpoints must be protected against abuse via request-rate limiting. | `slowapi`-based `RateLimitExceeded` handler, `rate_limiter.py` |
| NFR-10 | **Testability:** critical application services must be independently unit-testable via dependency injection through ports, with dedicated architecture-conformance tests. | `core_orchestrator/test/application/*`, `test/architecture/test_layering_rules.py` |

## 3. Critical Use Cases

### UC-01 — Ingesting and Detecting a Malicious Log Window

- **Actor:** `log_shipper` (Vector), acting on behalf of `victim_app`.
- **Preconditions:** the telemetry client is registered with a valid HMAC public/secret key pair; `core`, `mongo`, `redis`, and `mcp_server` are running.
- **Main Flow:**
  1. Vector batches recent victim-app log lines and POSTs them to `/api/v1/telemetry/ingest/batch` with `X-Public-Key`, `X-Signature`, and `X-Timestamp` headers.
  2. Core validates the HMAC signature and timestamp freshness, then accepts the batch (`202 Accepted`).
  3. Each event is appended to the active `TelemetryWindow` for its `source_id`/`source_ip`.
  4. Once the window closes (request threshold or TTL expiry), `AgentRunner` enqueues it for analysis.
  5. The `OrchestratorAgent` requests `analyze_web_activity` from the MCP server, which runs the heuristics engine and the configured LLM to produce a verdict (threat score, MITRE mapping, recommendation).
  6. If a threat is detected, historical context for the source IP is fetched and merged into the report.
  7. The final `AnalysisReportResponse` is persisted to MongoDB and cached in Redis.
- **Postconditions:** a new (or updated) analysis report exists in MongoDB and is visible in the Alerts view of the frontend; the result is cached for one hour to avoid duplicate LLM calls on identical payloads.

### UC-02 — AI-Powered Threat Investigation via Forensic Chat

- **Actor:** SOC Analyst (role `analyst` or `admin`), authenticated in the React frontend.
- **Preconditions:** the analyst holds a valid JWT with at least the `analyst` role; the MCP server and its configured LLM provider are reachable.
- **Main Flow:**
  1. The analyst types a natural-language question into the Forensic page (e.g., "show failed login bursts from 10.0.0.7 in admin endpoints").
  2. The frontend calls `POST /api/v1/forensic/analyze`, authenticated via `get_analyst_user`.
  3. `ForensicService` invokes the MCP tool `generate_mongo_query_from_nl`, which asks the LLM (or deterministic bounded parser) to translate the question into a safe MongoDB filter, scoped optionally to a `source_id`.
  4. The generated filter is executed against the telemetry repository in MongoDB, returning matching rows.
  5. `generate_forensic_report_from_logs` is invoked to produce a structured markdown report with `highlights` and risk framing from the matched rows.
  6. The resulting `ForensicAnalysisRecord` is persisted and returned to the frontend, which renders the markdown report and highlights.
- **Postconditions:** the forensic query and its generated report are stored and retrievable later via `GET /api/v1/forensic/history` and `/history/{analysis_id}`.

### UC-03 — Automated Mitigation / Alert Triage Trigger

- **Actor:** SOC Analyst.
- **Preconditions:** at least one unresolved `AnalysisReportResponse` with `threat_detected = true` exists.
- **Main Flow:**
  1. The analyst opens the Alerts view; the frontend fetches paginated reports from `GET /api/v1/analytics/reports`.
  2. The analyst reviews the reasoning breakdown, MITRE tactic/technique tags, and suggested mitigations rendered from the report.
  3. The analyst marks the report as reviewed (`PATCH /api/v1/analytics/reports/{id}/review`) and appends a mitigation action/comment (`POST /api/v1/analytics/reports/{id}/actions`).
  4. Once remediated, the analyst resolves the report (`PATCH /api/v1/analytics/reports/{id}/resolve`).
- **Postconditions:** the report's `reviewed`, `actions`, and `resolved` fields are updated in MongoDB and reflected immediately in the dashboard's KPIs and alert list.

### UC-04 — Heuristic Rule Lifecycle Management

- **Actor:** Administrator (role `admin`).
- **Preconditions:** the administrator is authenticated with an `admin`-role JWT.
- **Main Flow:**
  1. Admin creates or edits a heuristic rule (`POST`/`PATCH /api/v1/rules`), which is validated and persisted in the `heuristy` MongoDB database — this does **not** activate it automatically.
  2. Admin creates a new rule version bundle (`POST /api/v1/rules/versions`).
  3. Admin explicitly activates that version (`POST /api/v1/rules/versions/activate/{id}`), which refreshes the active `RulesBundle` cached in Redis DB 3.
  4. On the next telemetry analysis, the Core Orchestrator injects the newly active `rules_bundle` into the `analyze_web_activity` MCP call.
- **Postconditions:** the new/updated rule is reflected in subsequent analyses; the change is recorded in the rule audit log for traceability and rollback.

