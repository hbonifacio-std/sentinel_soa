# Sentinel SOA

**Sentinel SOA** is an academic cybersecurity platform that demonstrates AI-driven threat detection in a fully isolated, service-oriented environment. It ingests HTTP telemetry from a monitored "victim" application, correlates it against deterministic heuristics and Large Language Model (LLM) reasoning, and surfaces the results through a React-based Security Operations Center (SOC) dashboard with an AI-assisted forensic investigation workspace.

The project's academic purpose is to provide a hands-on, reproducible lab for studying:
- Real-time telemetry ingestion and windowing.
- Hybrid detection (heuristic rules + LLM analysis) against OWASP Top 10 style attacks.
- Agentic orchestration between a core API and a dedicated analysis microservice via the **Model Context Protocol (MCP)**.
- Hexagonal / Clean Architecture applied to a production-grade FastAPI codebase.
- Safe, contained offensive-security experimentation (attacker vs. victim containers on isolated Docker networks).

## Core Value Proposition

Instead of relying purely on static, signature-based detection, Sentinel SOA groups incoming logs into contextual time/session windows and asks an LLM-backed analysis agent to reason about the *behavior* of a source IP — cross-referencing it with deterministic heuristics (SQLi/path traversal patterns, malicious User-Agents, sensitive URIs) and historical threat context stored in MongoDB. Analysts can then interrogate the data further through a natural-language forensic chat that translates questions into safe, bounded MongoDB queries and produces a structured markdown report.

## High-Level Architecture

```
Attacker (sim.) ──▶ Victim App ──▶ Vector (log shipper) ──▶ Core Orchestrator ──▶ MCP Log Analysis Server ──▶ LLM Provider
                                                               │      ▲                                        (Gemini / OpenAI /
                                                               ▼      │                                         Groq / Ollama)
                                                          MongoDB   Redis
                                                               ▲
                                                               │
                                                     React SOC Frontend (Dashboard, Alerts, Forensic Chat, Rules)
```

- **Victim App**: a deliberately vulnerable FastAPI service acting as the monitored asset.
- **Attacker / Traffic Simulator**: generates a mix of benign and OWASP-style malicious traffic against the victim, exclusively within an isolated Docker network (`dmz_net`).
- **Core Orchestrator**: hexagonal-architecture FastAPI service that authenticates telemetry clients, manages time windows, drives the AI analysis agent, persists reports, and exposes the REST API consumed by the frontend.
- **MCP Log Analysis Server**: a FastMCP-based microservice exposing analysis tools (`analyze_web_activity`, `get_threat_context`, forensic NL→Mongo translation) backed by a heuristics engine and pluggable LLM providers.
- **MongoDB / Redis**: persistent storage for telemetry, analysis reports, users, heuristic rules and versioning (MongoDB); caching, telemetry windows, rules bundle and JWT blacklist (Redis).
- **React Frontend**: threat dashboard, alert center, rules management, and an AI-powered forensic investigation chat.

See [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) for the full data-flow description.

## Documentation Map

| Document | Description |
|---|---|
| [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) | System architecture, component responsibilities, attacker/victim isolation model, and end-to-end data flow. |
| [`docs/REQUIREMENTS.md`](./docs/REQUIREMENTS.md) | Functional and non-functional requirements, and critical use cases (Given actor/preconditions/flow/postconditions). |
| [`docs/TECHNICAL_SPECIFICATIONS.md`](./docs/TECHNICAL_SPECIFICATIONS.md) | Dependency tables (frontend, core, MCP server), code architecture (Hexagonal/DDD), and component-level security controls. |
| [`docs/QA_TEST_PLAN.md`](./docs/QA_TEST_PLAN.md) | Gherkin/BDD test scenarios covering detection, AI chat, and resilience. |
| [`docs/AI_AGENTS.md`](./docs/AI_AGENTS.md) | AI agent architecture, agent/tool catalog, and configuration guide for models and providers. |
| [`docs/rules/README.md`](./docs/rules/README.md) | Deep-dive on the heuristic rules subsystem (MongoDB + Redis, versioning, CRUD). |

> **Note on legacy documentation:** `docs/architecture.md`, `docs/components.md` and `docs/information_flow.md` described an earlier version of the system (no MongoDB/Redis, no frontend, no attacker/victim simulation, no hexagonal layering). Their content has been investigated, superseded, and consolidated into `docs/ARCHITECTURE.md`, `docs/TECHNICAL_SPECIFICATIONS.md`, and `docs/AI_AGENTS.md`. They can be safely removed once this rewrite is merged.

## Quick Start

```bash
cp .env.example .env
docker-compose up --build
```

Further setup instructions and data-seeding scripts can be found by exploring the `scripts` directory.

---
*This documentation set was regenerated from a direct investigation of the codebase (core_orchestrator, mcp_servers, frontend, docker-compose.yml) to replace outdated material while preserving accurate legacy content.*
