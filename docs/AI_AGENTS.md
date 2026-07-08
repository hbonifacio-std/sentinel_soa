# AI Agent Management & Configuration

## 1. Agent Architecture

Sentinel SOA implements two cooperating AI agents, both hosted logically inside the **MCP Log Analysis Server** and orchestrated by the **Core Orchestrator**, which never talks to an LLM directly — it always goes through the MCP protocol (FastMCP RPC, `fastmcp` on the server side / `mcp` client SDK on the core side).

```
Core Orchestrator                         MCP Log Analysis Server
┌─────────────────────┐                   ┌──────────────────────────────────┐
│ OrchestratorAgent    │  FastMCP RPC      │ FastMCP "log-analysis-server"     │
│ (agent/orchestrator)  │ ────────────────▶ │                                    │
│  - cache check         │                 │  Tool: analyze_web_activity         │
│  - calls analysis port  │                │    -> ThreatHeuristics (rules)        │
│  - enrich w/ history      │              │    -> PromptFactory + LLMProvider       │
│  - persist report            │           │                                            │
│                                │          Tool: get_threat_context                       │
│ ForensicService                 │        │    -> MongoDB historical alerts lookup         │
│  - calls forensic ports           │      │                                                  │
│                                     │     Tool: generate_mongo_query_from_nl                   │
│                                       │   │    -> TranslateMongo (NL -> bounded Mongo filter)    │
│                                         │ │                                                        │
│                                           Tool: generate_forensic_report_from_logs                    │
│                                             │  -> PromptFactory (forensic schema) + LLMProvider        │
└─────────────────────────────────────────────┘
```

`AgentRunner` (in `infrastructure/agent/runner.py`) is the resilience layer around the primary detection agent: it maintains an MCP reconnect loop with exponential backoff, an in-memory analysis queue that never silently drops a telemetry window, and a bounded retry policy (`_ANALYSIS_MAX_RETRIES`) before a window is finally discarded. `MCPClientManager` (in `infrastructure/agent/mcp_client.py`) owns the actual RPC session lifecycle to the MCP server.

## 2. Agent Catalog

| Agent / Tool | MCP Tool Name | Purpose | Primary Input | Primary Output |
|---|---|---|---|---|
| **Triage / Threat Detection Agent** | `analyze_web_activity` | Combines deterministic heuristics with LLM reasoning to classify a telemetry window as benign or malicious, mapped to MITRE ATT&CK. | `TelemetryWindow` fields (URIs, methods, response codes, payload features, rules bundle) | `threat_detected`, `threat_score`, `mitre_tactic(_id)`, `mitre_technique(_id)`, `reasoning_summary`, `recommendation` |
| **Threat Context Agent** | `get_threat_context` | Retrieves and summarizes historical alerts for a given source IP to enrich a fresh verdict. | `source_ip`, `limit` | `history` (list of prior alerts), `record_count` |
| **Forensics / NL-to-Query Agent** | `generate_mongo_query_from_nl` | Translates an analyst's natural-language question into a safe, bounded MongoDB filter (IPs, status codes, URI patterns, keywords). | `query` (free text), optional `source_id` | `mongo_filter`, `detected_terms`, `detected_ips`, `detected_status_codes` |
| **Forensics Report Agent** | `generate_forensic_report_from_logs` | Synthesizes matched telemetry rows into an analyst-facing markdown report with prioritized highlights. | `query`, `total_matches`, `rows`, optional `source_id`/`model_id` | `markdown_report`, `highlights`, risk metadata |
| **Model Introspection Tool** | `get_available_models` | Exposes the configured LLM model catalog and default model to callers. | — | `default_model_id`, `available_models` |

## 3. Configuration Guide

### 3.1 Model Catalog

Models available to the agents are declared centrally in `mcp_servers/log_analysis_server/config.py`, as a `Dict[str, ModelDefinition]` keyed by a short model ID:

```python
available_models: Dict[str, ModelDefinition] = {
    "qwen2_5_coder7": ModelDefinition(provider="ollama", model_name="qwen2.5-coder:7b"),
    "sentinel-analyst": ModelDefinition(provider="ollama", model_name="sentinel-analyst"),
    "sentinel-translator-mongodb": ModelDefinition(provider="ollama", model_name="sentinel-translator-mongodb", max_output_tokens=8192),
    "gemini-3.5-flash": ModelDefinition(provider="gemini", model_name="gemini-3.5-flash", max_output_tokens=8192),
    "gemini-3.2-flash": ModelDefinition(provider="gemini", model_name="gemini-3.2-flash", max_output_tokens=8192),
    "openai-gpt3_5-turbo": ModelDefinition(provider="openai", model_name="gpt-3.5-turbo-instruct-0914", max_output_tokens=8192),
    "groq-llama-3_3-70b-versatile": ModelDefinition(provider="groq", model_name="llama-3.3-70b-versatile", max_output_tokens=12000, max_input_tokens=8192),
}
default_model_id: str = "qwen2_5_coder7"  # overridable via DEFAULT_MODEL_ID env var
```

`sentinel-analyst` and `sentinel-translator-mongodb` are custom Ollama models built from the `ModelfileForensic` and `ModelfileMongoTranslate` files at the repository root, layered on top of a local base model (default `qwen2.5-coder:7b`).

### 3.2 Configuring System Prompts

System prompts and output schemas are centralized in `mcp_servers/log_analysis_server/services/prompt_factory.py`:

- `FULL_PROMPT_TEMPLATE` — used for API-based providers (Gemini/OpenAI/Groq); includes full SOC-analyst framing, OWASP Top 10 / MITRE ATT&CK grounding instructions, historical-correlation and scoring-band rules.
- `OPTIMIZED_PROMPT_TEMPLATE` — a lean variant used for Ollama, which relies on its `Modelfile`'s embedded system prompt instead of repeating full instructions per call.
- Per-task JSON schemas (`DEFAULT_WEB_ACTIVITY_SCHEMA`, `DEFAULT_FORENSIC_SCHEMA`, `DEFAULT_NLQ_MONGO_SCHEMA`) constrain each agent's output shape.

To change an agent's behavior, edit the relevant template/schema in `prompt_factory.py` (or the corresponding `Modelfile*` for a local Ollama model) — no changes to `server.py` or the Core Orchestrator are required.

### 3.3 Selecting/Configuring an LLM Provider

Provider selection and credentials flow from the Core Orchestrator's environment into the MCP server process (the MCP server does **not** read its own `.env`; it inherits the parent process environment):

| Variable | Applies to | Description |
|---|---|---|
| `LLM_PROVIDER` | Core → docker-compose | Default provider name (`ollama`, `gemini`, `openai`, `groq`) |
| `DEFAULT_MODEL_ID` | MCP server | Key into `available_models` used when a tool call doesn't specify `model_id` |
| `GEMINI_API_KEY`, `GEMINI_MODEL` | Gemini provider | Cloud credentials/model name |
| `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `OLLAMA_TIMEOUT_SECONDS` | Ollama provider | Local runtime endpoint/model/timeout |
| `OPENAI_API_KEY`, `OPENAI_MODEL`, `OPENAI_MAX_OUTPUT_TOKENS`, `OPENAI_TIMEOUT_SECONDS` | OpenAI provider | Cloud credentials/model/limits |
| `GROQ_API_KEY`, `GROQ_MODEL`, `GROQ_MAX_OUTPUT_TOKENS`, `GROQ_TIMEOUT_SECONDS` | Groq provider | Cloud credentials/model/limits |

All secrets are parsed as Pydantic `SecretStr` to prevent accidental logging.

### 3.4 Adding a New LLM Provider

1. Implement a new class in `mcp_servers/log_analysis_server/llm_providers/` conforming to `LLMProviderInterface` (`base.py`).
2. Register it in the provider factory (`create_llm_provider`) alongside the existing `gemini_provider.py`, `openai_provider.py`, `groq_provider.py`, `ollama_provider.py`.
3. Add any required credentials/settings fields to `LogAnalysisServerSettings` in `config.py`, and surface them through `get_provider_config()`.
4. Add one or more entries to `available_models` with the new `provider` value.
5. Wire the new environment variables into `docker-compose.yml` under the `mcp_server` service.

No changes are required in `core_orchestrator` — the Core Orchestrator only ever calls the MCP tool names (`analyze_web_activity`, `get_threat_context`, etc.), never a provider directly.

### 3.5 Registering a New Agent/Tool in the React Chat Interface

To surface a new MCP-backed capability (a new "agent") in the Forensic chat UI:

1. **Server-side:** register a new `@server.tool()` function in `mcp_servers/log_analysis_server/server.py`, backed by a service in `services/` and/or a tool module in `tools/`.
2. **Core Orchestrator:** expose a new REST endpoint under `infrastructure/api/v1/endpoints/forensic.py` (or a new router) that calls the tool through the existing `ForensicServicePort` / `MCPClientManager`, following the same pattern as `run_forensic_analysis`.
3. **Frontend API client:** add a typed call in `frontend/src/features/forensic/services/forensicApi.ts` and a corresponding React Query hook in `frontend/src/features/forensic/hooks/`.
4. **Frontend UI:** extend `frontend/src/features/forensic/ForensicPage.tsx` (or add a new feature folder) to expose the new interaction, reusing `MarkdownRenderer` for report rendering and `ForensicHighlights` for structured highlights.
5. **Types:** update `frontend/src/types/forensic.ts` to mirror the new response schema.

This mirrors how the existing `generate_mongo_query_from_nl` / `generate_forensic_report_from_logs` pair was wired end-to-end from MCP tool → Core endpoint → frontend hook → UI.
