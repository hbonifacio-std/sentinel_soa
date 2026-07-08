# System Architecture & Data Flow

## 1. Architectural Description

Sentinel SOA is a service-oriented system composed of seven runtime components, all orchestrated through `docker-compose.yml` and segmented across three isolated Docker bridge networks (`dmz_net`, `sentinel_net`, `log_net`).

### 1.1 Components

| Component | Container | Responsibility |
|---|---|---|
| `frontend` | `sentinel_frontend` | React/Vite SOC dashboard (alerts, logs, rules, forensic chat). Proxies API calls to `core`. |
| `core` (Core Orchestrator) | `sentinel_core` | FastAPI service: authentication, telemetry ingestion, windowing, AI-agent orchestration, persistence, REST API. |
| `mcp_server` (Log Analysis Server) | `sentinel_mcp_server` | FastMCP microservice exposing analysis tools; heuristics engine + LLM provider abstraction. |
| `ollama` | `sentinel_ollama` | Local LLM runtime, serves the `sentinel-analyst` and `sentinel-translator-mongodb` fine-tuned/prompted models. |
| `attacker` | `sentinel_attacker` | Traffic simulator that issues benign + OWASP Top 10-style requests against the victim app. |
| `victim_app` | `sentinel_victim_app` | Deliberately vulnerable FastAPI application (`Core-Banking-API` simulation) that is the sole monitored target. |
| `log_shipper` | `sentinel_log_shipper_vector` | Vector (`timberio/vector`) instance that tails the victim's log file and forwards it to the Core Orchestrator over HTTP. |
| `mongo` | `sentinel_mongodb` | Persistent store for telemetry, analysis reports, users, telemetry clients, heuristic rules and rule versions/audit log. |
| `redis` | `sentinel_redis` | Cache for telemetry windows, active rules bundle, analysis result cache, and JWT blacklist. |

### 1.2 End-to-End Data Flow

```
[INSERT DATA FLOW DIAGRAM HERE]

1. Attacker container (or benign users) send HTTP traffic to victim_app (dmz_net).
2. victim_app logs every request to a shared volume (/var/log/victim_app).
3. Vector (log_shipper) tails that file and forwards structured log batches,
   HMAC-signed, to POST /api/v1/telemetry/ingest/batch on the Core Orchestrator
   (core is reachable on both dmz_net and log_net; victim_app and log_shipper
   are NOT on sentinel_net, so they can never reach mongo, redis, or mcp_server
   directly).
4. Core Orchestrator (TelemetryProcessingService) buffers each LogEvent into a
   Redis-backed TelemetryWindow, keyed by source_id + source_ip + session.
5. AgentRunner's window-processor task detects windows that are "full"
   (request-count threshold) or "expiring" (TTL close to 0) and enqueues them
   for analysis in an in-memory asyncio.Queue — telemetry is never dropped
   even if the MCP server is temporarily unavailable.
6. The analysis-consumer task pulls a pending window and calls
   OrchestratorAgent.process_telemetry_window():
     a. Checks Redis cache for an identical prior analysis (dedup/perf).
     b. Calls AnalysisService -> MCPClientManager -> MCP tool
        'analyze_web_activity' over the FastMCP RPC channel (sentinel_net).
     c. The MCP Log Analysis Server runs ThreatHeuristics (deterministic
        rules bundle, injected by the core) to pre-score the window, then
        builds a prompt via PromptFactory and calls the configured LLM
        provider (Ollama / Gemini / OpenAI / Groq) to produce a structured
        JSON verdict (threat_score, MITRE ATT&CK mapping, recommendation).
     d. If a threat is detected, the orchestrator calls 'get_threat_context'
        to enrich the verdict with the IP's historical alerts from MongoDB.
     e. The final AnalysisReportResponse is persisted to MongoDB and cached
        in Redis (1 hour TTL).
7. The React frontend polls/queries the Core Orchestrator's REST API
   (Dashboard, Alerts, Logs, Rules) and lets analysts run ad-hoc forensic
   investigations, which invoke a second AI Agent pipeline (NL → Mongo
   filter → structured markdown report) through the same MCP server.
```

### 1.3 Architectural Diagram (Production View)

```
[INSERT ARCHITECTURE DIAGRAM HERE]

                          dmz_net                         log_net              sentinel_net
   ┌───────────┐     ┌─────────────┐     ┌──────────────┐          ┌────────────────────┐
   │ attacker  │────▶│ victim_app  │────▶│ log_shipper  │────HTTP──▶│   core (FastAPI)   │
   └───────────┘     └─────────────┘     │  (Vector)    │          │ (Core Orchestrator) │
                                          └──────────────┘          └─────────┬──────────┘
                                                                              │ FastMCP (RPC)
                                                                              ▼
                                                                    ┌────────────────────┐
                                                                    │   mcp_server        │
                                                                    │ (Log Analysis Srv)  │
                                                                    └─────────┬──────────┘
                                                                              │
                                                          ┌───────────────────┼───────────────────┐
                                                          ▼                   ▼                   ▼
                                                     ┌─────────┐        ┌───────────┐       ┌────────────┐
                                                     │  ollama │        │  gemini/  │       │  mongo /   │
                                                     │ (local) │        │ openai/   │       │  redis     │
                                                     └─────────┘        │  groq     │       │(sentinel_net)│
                                                                        └───────────┘       └────────────┘
                                                                              ▲
                                                                              │ REST (proxied)
                                                                    ┌────────────────────┐
                                                                    │   frontend (React)  │
                                                                    └────────────────────┘
```

## 2. Attacker vs. Victim Flow — Isolation Model

The environment models a realistic corporate network segmentation so the "attack surface" is contained and observable without endangering the analysis stack:

- **`dmz_net`**: contains only `attacker`, `victim_app`, `log_shipper`, and `frontend`/`core` (their public-facing edges). This is the network where exploitation traffic actually occurs.
- **`log_net`**: a narrow channel between `victim_app`/`log_shipper` and `core`, used exclusively to forward telemetry. It does not expose MongoDB, Redis, or the MCP server.
- **`sentinel_net`**: the "backend" network where `core`, `mcp_server`, `ollama`, `mongo`, and `redis` communicate. Neither `attacker` nor `victim_app` are attached to this network, so a successful compromise of the victim application cannot pivot directly into the detection stack, the database, or the LLM infrastructure.
- Telemetry ingestion from `victim_app`/`log_shipper` into `core` is authenticated via **HMAC-SHA256** signed requests (public key + signature + timestamp with a replay window), not by network trust alone.
- The AI reasoning stack (`mcp_server`, `ollama`) is only reachable from `core`, over the internal `sentinel_net`, via the MCP protocol — it has no route back to the DMZ.

This mirrors a real SOC pattern: the monitored/exposed estate (DMZ) is assumed to be attackable, while the detection, storage, and AI-analysis plane is kept on a private network segment reachable only through a narrow, authenticated ingestion path.

## 3. Component Communication Summary

| From | To | Protocol / Mechanism | Security Control |
|---|---|---|---|
| `attacker` | `victim_app` | Plain HTTP (simulated attack traffic) | None (intentionally vulnerable target) |
| `victim_app` | `log_shipper` (Vector) | Shared log file volume | Read-only volume mount |
| `log_shipper` | `core` | HTTP POST `/api/v1/telemetry/ingest/batch` | HMAC-SHA256 signature + timestamp replay window |
| `frontend` | `core` | REST over HTTP (Vite dev proxy) | JWT Bearer + RBAC |
| `core` | `mcp_server` | FastMCP RPC (HTTP or stdio transport) | Internal network isolation (`sentinel_net`) |
| `mcp_server` | `ollama` / `gemini` / `openai` / `groq` | HTTP (provider SDKs) | API keys (cloud providers), local-only (Ollama) |
| `core` | `mongo` | PyMongo (motor-style async driver) | Auth DB credentials |
| `core` | `redis` | `redis` async client | Password-protected (`requirepass`) |

