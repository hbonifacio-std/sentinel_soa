# Technical Specifications & Stack

## 1. Component & Dependency Tables

### 1.1 Core Orchestrator (`core_orchestrator/requirements.txt`)

| Library | Version | Purpose |
|---|---|---|
| fastapi | 0.135.1 | Web framework / REST API |
| uvicorn[standard] | 0.49.0 | ASGI server |
| starlette | 1.3.1 | ASGI toolkit (FastAPI dependency) |
| python-multipart | 0.0.31 | Form/multipart parsing (OAuth2 password flow) |
| slowapi | 0.1.9 | Rate limiting |
| pymongo | 4.17.0 | MongoDB driver |
| redis | 5.2.1 | Redis client (cache, windows, blacklist) |
| mcp | 1.28.0 | Model Context Protocol client SDK |
| bcrypt | 4.0.1 | Password hashing |
| pyjwt[crypto] | 2.13.0 | JWT issuing/parsing |
| pydantic-settings | 2.6.1 | Typed environment configuration |
| email-validator | 2.1.0.post1 | Email format validation (user model) |
| langdetect | 1.0.9 | Language detection utility |

### 1.2 MCP Log Analysis Server (`mcp_servers/log_analysis_server/requirements.txt`)

| Library | Version | Purpose |
|---|---|---|
| fastmcp | 3.4.2 | FastMCP server framework (tool registration/RPC) |
| httpx | 0.28.1 | Async HTTP client (LLM provider calls) |
| google-generativeai | 0.7.2 | Google Gemini provider SDK |
| openai | 1.68.0 | OpenAI provider SDK |
| groq | 1.4.0 | Groq provider SDK |
| pydantic | 2.11.7 | Data validation / schemas |
| pydantic-settings | 2.6.1 | Typed environment configuration |

### 1.3 React Frontend (`frontend/package.json`, `sentinel-view` v2.0.0)

**Dependencies:**

| Library | Version | Purpose |
|---|---|---|
| react / react-dom | ^18.3.1 | UI framework |
| react-router-dom | ^6.30.1 | Client-side routing |
| @tanstack/react-query | ^5.101.2 | Server-state data fetching/caching |
| @tanstack/react-virtual | ^3.10.8 | Virtualized lists (large log tables) |
| zustand | ^5.0.8 | Global client state (auth, active source) |
| recharts | ^2.15.4 | Dashboard charts (MITRE tactics, threat levels, timelines) |
| react-markdown / remark-gfm | ^10.1.0 / ^4.0.1 | Rendering forensic markdown reports |
| lucide-react | ^0.525.0 | Icon set |
| date-fns | ^4.1.0 | Date formatting |
| clsx / tailwind-merge | ^2.1.1 / ^3.3.1 | Conditional/merged class names |

**Dev dependencies:** TypeScript ^5.8.3, Vite ^5.4.19, Tailwind CSS ^3.4.17 (+ `@tailwindcss/forms`, `tailwindcss-animate`), `@vitejs/plugin-react` ^4.7.0, PostCSS/Autoprefixer.

### 1.4 Supporting Services (docker-compose)

| Service | Image / Build | Version |
|---|---|---|
| MongoDB | `mongo:latest` | Latest |
| Redis | `redis:7.4-alpine` | 7.4 |
| Vector (log shipper) | `timberio/vector:0.38.0-alpine` | 0.38.0 |
| Ollama | Custom (`Dockerfile.ollama`) | Serves `qwen2.5-coder:7b`-derived custom models |

## 2. Code Architecture

### 2.1 Pattern: Hexagonal Architecture (Ports & Adapters) + DDD-flavored modules

`core_orchestrator` is organized in three strict layers:

```
core_orchestrator/
├── domain/            # Pure business rules — no framework/infra imports
│   ├── models/         # Pydantic domain models (telemetry, analysis, auth, rules, forensic)
│   └── ports/           # Abstract interfaces (repositories, services, caches)
├── application/        # Use cases, orchestrated exclusively through domain ports
│   └── modules/
│       ├── telemetry/
│       ├── analysis_reports/
│       ├── auth_clients/
│       └── forensic/
└── infrastructure/      # Concrete adapters: FastAPI routes, Mongo/Redis repos, MCP client, JWT/HMAC
    ├── api/              # Routers, dependency wiring, DI container
    ├── persistence/       # Mongo repository implementations
    ├── cache/              # Redis-backed cache/window/blacklist implementations
    ├── security/            # JWT, password hashing, HMAC signature verification
    └── agent/                # OrchestratorAgent, MCPClientManager, AgentRunner
```

**Rules enforced (and checked by `test/architecture/test_layering_rules.py`):**
- `domain` never imports from `application` or `infrastructure`.
- `application` never imports from `infrastructure` directly — all technical concerns (password hashing, JWT, MCP calls, Mongo/Redis specifics) are reached through a `domain/ports/*` interface, implemented by an adapter in `infrastructure`.
- `infrastructure/api/container.py` is the single composition root that wires concrete adapters into use cases (dependency injection), avoiding global singletons.

This structure was the target of an explicit refactor (see `docs/PLAN_REFACTORIZACION_HEXAGONAL_CORE_ORCHESTRATOR.md`), which progressively removed direct `infrastructure` imports from `application/modules/*` services (password hashing, JWT/token issuance, HMAC verification, MCP client access, and a rules-engine singleton).

### 2.2 MCP Log Analysis Server — Modular Service Design

```
mcp_servers/log_analysis_server/
├── server.py               # FastMCP tool registration (analyze_web_activity, get_threat_context, forensic tools)
├── config.py                # Typed settings: model catalog + provider credentials (inherited from core's env)
├── llm_providers/             # Provider abstraction: base.py + gemini/openai/groq/ollama implementations
├── services/
│   ├── heuristics_engine.py    # Deterministic scoring engine (ThreatHeuristics)
│   ├── prompt_builder.py         # Prompt assembly for the analysis task
│   ├── prompt_factory.py          # Centralized prompt templates + schemas for all tasks
│   └── translate_mongo.py          # NL → MongoDB filter translation service
├── tools/                     # Tool entry points invoked by FastMCP
├── models/                     # Pydantic I/O schemas per tool
└── store/alert_store.py         # In-process alert bookkeeping helper
```

### 2.3 Frontend — Feature-Sliced Architecture

```
frontend/src/
├── features/            # One folder per business capability
│   ├── dashboard/          # KPIs, MITRE tactics chart, kill-chain pie, attack timeline
│   ├── alerts/               # Alert table, drawer, mitigation timeline, reasoning breakdown
│   ├── logs/                  # Raw telemetry log explorer
│   ├── rules/                   # Heuristic rules management UI
│   ├── forensic/                 # AI-powered natural-language investigation chat
│   └── auth/                      # Login page
├── components/           # Shared, presentation-only UI components
├── hooks/                  # Cross-feature data hooks (react-query wrappers)
├── lib/                      # API clients, formatters, query keys
├── store/                      # Zustand stores (auth, active source/session)
└── types/                        # Shared TypeScript contracts mirrored from the API
```

## 3. Component-Level Security

| Control | Where Implemented | Description |
|---|---|---|
| HMAC-SHA256 request signing + replay window | `infrastructure/security` (`signature_verifier.py`, `sanitizer.py`) | Protects telemetry ingestion (`/api/v1/telemetry/*`) from tampering and replay; secret lookup via a Redis-backed secret store. |
| JWT authentication (HS256) | `infrastructure/security/jwt_utils.py`, `token_service.py` | Issued at `/api/v1/auth/token` (OAuth2 password flow); carries `sub`, `username`, `role`, `iat`, `exp`, and a unique `jti`. |
| JWT revocation / instant logout | `infrastructure/cache/redis_token_blacklist_repository.py`, `domain/ports/auth/token_blacklist_repository.py` | Adds a token's `jti` to a Redis blacklist on logout; `get_current_user` rejects blacklisted tokens even if not yet expired. |
| Role-Based Access Control (RBAC) | `infrastructure/security/dependencies.py` (`get_admin_user`, `get_analyst_user`) | Enforces `admin` / `analyst` / `viewer` role checks on rules, analytics, and forensic endpoints. |
| Password hashing | `infrastructure/security/password.py`, `password_hasher.py` | bcrypt hashing behind a `PasswordHasherPort`; plaintext passwords are never persisted. |
| API Key auth for telemetry clients | `infrastructure/security/dependencies.py` (`verify_api_key_header`) | Validates `X-Sentinel-Client-Id` / `X-Sentinel-Api-Key` headers against `TelemetryClientService`. |
| CORS restriction | `main.py`, `infrastructure/config/config.py` | Explicit allow-list of origins via `ALLOWED_CORS_ORIGINS`; only required methods/headers permitted. |
| Rate limiting | `infrastructure/api/rate_limiter.py`, `handlers/rate_limits.py` (slowapi) | Mitigates brute-force/abuse on public endpoints; returns `429` via `RateLimitExceeded` handler. |
| Input sanitization for logging | `infrastructure/security/sanitizer.py` (`redact_sensitive_data`) | Redacts sensitive fields before writing ingestion payloads to application logs. |
| Secret management | `infrastructure/config/config.py`, `mcp_servers/.../config.py` | Provider API keys wrapped in Pydantic `SecretStr` to avoid accidental leakage into logs. |
| Network segmentation | `docker-compose.yml` | `dmz_net` / `log_net` / `sentinel_net` isolate the vulnerable victim app and attacker simulator from MongoDB, Redis, and the MCP/LLM stack (see `docs/ARCHITECTURE.md` §2). |
| Rules audit trail | `infrastructure/persistence/mongo_audit_repository.py` | Append-only log of `CREATE/UPDATE/DELETE/ACTIVATE/ROLLBACK` actions on heuristic rules. |
