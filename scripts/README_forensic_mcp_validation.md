# Forensic MCP Flow Validation

This harness validates the complete forensic flow:

1. MCP tool `generate_mongo_query_from_nl` creates `mongo_filter`.
2. The filter is executed against Mongo collection `raw_telemetry`.
3. MCP tool `generate_forensic_report_from_logs` analyzes DB results.
4. Optional: MCP tool `analyze_web_activity` validates LLM provider (Ollama/Modelfile).

## Script

- `scripts/validate_forensic_mcp_flow.py`

## Requirements

- MongoDB reachable with env variables (`MONGO_*`).
- MCP server reachable with env variables (`MCP_SERVER_HOST`, `MCP_SERVER_PORT`).
- If using Docker Compose default networking (hostnames `mongo`, `mcp_server`), run inside `core` container.

## Quick Run

```powershell
Set-Location "C:\Users\hanse\Documents\Documents\proyecto sentinela soa\sentinel_soa"
python scripts/validate_forensic_mcp_flow.py --source-id victim-app-01
```

## Run Without LLM Step

```powershell
Set-Location "C:\Users\hanse\Documents\Documents\proyecto sentinela soa\sentinel_soa"
python scripts/validate_forensic_mcp_flow.py --source-id victim-app-01 --skip-llm
```

## Docker Compose (inside core container)

```powershell
Set-Location "C:\Users\hanse\Documents\Documents\proyecto sentinela soa\sentinel_soa"
docker compose exec core python scripts/validate_forensic_mcp_flow.py --source-id victim-app-01
```

