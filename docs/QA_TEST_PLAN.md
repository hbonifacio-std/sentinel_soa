# QA & Test Plan (Gherkin / BDD)

This test plan defines behavior-driven scenarios for the three critical flows of Sentinel SOA: threat detection from log ingestion, AI chat-based forensic investigation, and resilience to database/service failures. Scenarios are written to be automatable against the Core Orchestrator API and MCP Log Analysis Server, complementing the existing unit tests in `core_orchestrator/test/application/*` and the architectural conformance tests in `core_orchestrator/test/architecture/test_layering_rules.py`.

```gherkin
Feature: Threat detection from telemetry log ingestion
  As a SOC platform
  I want to analyze windows of ingested telemetry
  So that malicious activity against the victim application is detected and reported

  Background:
    Given the Core Orchestrator, MongoDB, Redis, and the MCP Log Analysis Server are running
    And a telemetry client "victim-app-01" is registered with a valid HMAC key pair

  Scenario: Successful threat detection from a malicious log window
    Given the traffic simulator sends a burst of SQL-injection-pattern requests
      from IP "10.0.0.7" against the victim application
    And the log shipper forwards the corresponding batch of log events
      to "POST /api/v1/telemetry/ingest/batch" with a valid HMAC signature
    When the telemetry window for source IP "10.0.0.7" closes
      because the request-count threshold is reached
    Then the window is enqueued for analysis without being discarded
    And the MCP tool "analyze_web_activity" is invoked with the window payload
      and the currently active heuristic rules bundle
    And the heuristics engine flags at least one "injection" category indicator
    And the LLM-backed verdict reports "threat_detected" as true
      with a "threat_score" greater than or equal to 70
    And the verdict includes a MITRE ATT&CK tactic and technique mapping
    And an "AnalysisReportResponse" document is persisted in MongoDB
      with "reviewed" false and "resolved" false
    And the new report is retrievable via "GET /api/v1/analytics/reports"
      by a user with role "analyst" or "admin"

  Scenario: Identical telemetry payload is served from cache
    Given a telemetry window for source IP "10.0.0.7" was already analyzed
      and its result cached in Redis
    When an identical telemetry payload (same content, same key ordering)
      is submitted for analysis again
    Then the Orchestrator Agent returns the cached analysis result
    And the MCP tool "analyze_web_activity" is NOT invoked a second time


Feature: AI-powered forensic investigation via chat
  As a SOC analyst
  I want to ask natural-language questions about historical telemetry
  So that I can investigate incidents without writing raw database queries

  Background:
    Given I am authenticated as a user with role "analyst"
    And historical telemetry exists in MongoDB for source "victim-app-01"

  Scenario: User interaction with the AI forensic chat agent
    When I submit the forensic query
      "show failed login bursts from 10.0.0.7 in admin endpoints"
      via "POST /api/v1/forensic/analyze"
    Then the MCP tool "generate_mongo_query_from_nl" translates my query
      into a bounded MongoDB filter constrained to IP "10.0.0.7"
      and URI patterns containing "admin"
    And the filter is executed against the telemetry repository
    And the MCP tool "generate_forensic_report_from_logs" produces
      a markdown report containing a "highlights" section
    And a "ForensicAnalysisRecord" is created and returned with status 201
    And the record is later retrievable via
      "GET /api/v1/forensic/history/{analysis_id}"

  Scenario: Forensic chat is denied to unauthorized roles
    Given I am authenticated as a user with role "viewer"
    When I submit any query to "POST /api/v1/forensic/analyze"
    Then the API responds with status 403 Forbidden
    And no forensic analysis record is created


Feature: Resilience to database and AI-service connection failures
  As a SOC platform
  I want to remain operational and lose no data
  When the MCP server, MongoDB, or Redis become temporarily unavailable

  Scenario: Database connection failure and resilience handling
    Given the Core Orchestrator has an active connection to MongoDB and Redis
    And a telemetry window for source IP "10.0.0.7" is ready to be analyzed
    When the MongoDB connection becomes temporarily unavailable
    Then the health endpoint "GET /health" continues to respond
      with status "healthy" for the API process itself
    And in-flight telemetry ingestion requests are still accepted (202)
      and buffered rather than rejected
    And once the MongoDB connection is restored
      the pending analysis report is persisted successfully

  Scenario: MCP server unavailable at analysis time
    Given the MCP Log Analysis Server is stopped
    And a telemetry window for source IP "10.0.0.7" closes and is queued
    When the Analysis Consumer attempts to process the window
    Then the window is NOT discarded
    And the Orchestrator holds the window and retries
      with exponential backoff up to "_ANALYSIS_MAX_RETRIES" attempts
    And the MCP Reconnect Loop continues attempting to reconnect
      with a capped exponential backoff delay
    When the MCP server becomes available again before retries are exhausted
    Then the queued window is successfully analyzed
    And "GET /health" reports "mcp_status": "connected"

  Scenario: MCP server unavailable beyond the retry budget
    Given the MCP Log Analysis Server remains unavailable
      for longer than the configured maximum retry window
    When a queued window exhausts "_ANALYSIS_MAX_RETRIES" attempts
    Then the window is discarded to prevent unbounded queue growth
    And a warning is logged identifying the discarded window key
```

## Coverage Notes

| Scenario | Maps to Requirement(s) |
|---|---|
| Successful threat detection | FR-01, FR-02, FR-03, FR-05, FR-06, FR-08, NFR-03 |
| Identical payload cache hit | FR-07, NFR-08 |
| AI forensic chat interaction | FR-09, FR-10, NFR-07 |
| Forensic chat RBAC denial | FR-14, NFR-04 |
| MongoDB failure resilience | NFR-01, NFR-05 |
| MCP unavailable / recovers | FR-04, NFR-01 |
| MCP unavailable / retry budget exhausted | FR-04, NFR-01 |

## Existing Automated Coverage (pre-existing, retained)

- `core_orchestrator/test/application/test_analysis_service.py`
- `core_orchestrator/test/application/test_auth_service.py`
- `core_orchestrator/test/application/test_forensic_service.py`
- `core_orchestrator/test/application/test_rules_engine_service.py`
- `core_orchestrator/test/application/test_telemetry_client_service.py`
- `core_orchestrator/test/application/test_telemetry_processing_service.py`
- `core_orchestrator/test/application/test_user_service.py`
- `core_orchestrator/test/architecture/test_layering_rules.py`
- `mcp_servers/log_analysis_server/test/integration/test_forensic_nlq_tools.py`
- `mcp_servers/log_analysis_server/test/integration/test_historical_alerts_context.py`
- `mcp_servers/log_analysis_server/test/integration/test_llm_minimal_contract.py`

The Gherkin scenarios above are intended as acceptance/BDD-level tests that sit above this existing unit/integration suite, and should be automated with an HTTP-level test client (e.g. `httpx`/`pytest-bdd`) against a docker-compose test environment.
