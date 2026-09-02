"""Validate forensic NLQ -> Mongo -> MCP analysis flow using real services.

Run this script from the same environment where `core_orchestrator` can reach MongoDB
and the MCP server. In Docker Compose default networking, run it inside the `core`
container so hostnames like `mongo` and `mcp_server` resolve correctly.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from pymongo import MongoClient

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from core_orchestrator.infrastructure.adapters.mpc_server.mcp_client_adapter import MCPClientManagerAdapter


PAYLOAD_RECEIVED_LABEL = "Payload recibido:"


@dataclass
class ValidationConfig:
    query: str
    source_id: str | None
    mongo_db_name: str
    mongo_uri: str
    max_rows_for_report: int
    max_rows_for_llm: int
    llm_timeout_seconds: int
    run_llm_check: bool


def _load_env_file() -> None:
    env_path = Path(".env")
    if not env_path.exists():
        return

    for line in env_path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def _build_mongo_uri() -> tuple[str, str]:
    db_name = os.getenv("MONGO_DB_NAME", "sentinel_soa")
    host = os.getenv("MONGO_HOST", "localhost")
    port = os.getenv("MONGO_PORT", "27017")
    user = os.getenv("MONGO_USER")
    password = os.getenv("MONGO_PASSWORD")
    auth_db = os.getenv("MONGO_AUTH_DB", "admin")

    if user and password:
        uri = f"mongodb://{user}:{password}@{host}:{port}/{db_name}?authSource={auth_db}"
    else:
        uri = f"mongodb://{host}:{port}/{db_name}"

    return uri, db_name


def _extract_source_ip(query: str, rows: list[dict[str, Any]]) -> str:
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", query)
    if ip_match:
        return ip_match.group(0)

    for row in rows:
        source_ip = row.get("source_ip")
        if source_ip:
            return str(source_ip)

    return "0.0.0.0"


def _increment_status(status_counter: Counter, status_raw: Any) -> None:
    if isinstance(status_raw, int):
        status_counter[str(status_raw)] += 1
    elif isinstance(status_raw, str) and status_raw.isdigit():
        status_counter[status_raw] += 1


def _build_analysis_payload(query: str, source_id: str | None, rows: list[dict[str, Any]]) -> dict[str, Any]:
    capped_rows = rows[:500]
    source_ip = _extract_source_ip(query, capped_rows)

    uri_counter = Counter()
    method_counter = Counter()
    status_counter = Counter()
    user_agents: set[str] = set()

    for row in capped_rows:
        uri = str(row.get("request_uri") or row.get("http", {}).get("path") or "").strip()
        method = str(row.get("http_method") or row.get("method") or "GET").strip().upper()
        status_raw = row.get("response_code") or row.get("http", {}).get("status")
        user_agent = str(row.get("user_agent") or "").strip()

        if uri:
            uri_counter[uri] += 1
        if method:
            method_counter[method] += 1
        _increment_status(status_counter, status_raw)
        if user_agent:
            user_agents.add(user_agent)

    now = datetime.now(timezone.utc)
    total_requests = max(len(capped_rows), 1)
    requests_per_second_avg = round(total_requests / 60.0, 4)

    return {
        "window_id": str(uuid4()),
        "source_id": source_id or "unknown-source",
        "source_ip": source_ip,
        "window_start_utc": (now - timedelta(seconds=60)).isoformat(),
        "window_end_utc": now.isoformat(),
        "total_requests": total_requests,
        "unique_uris_requested": list(uri_counter.keys())[:200],
        "user_agents_observed": list(user_agents)[:100],
        "requests_per_second_avg": requests_per_second_avg,
        "http_methods_distribution": dict(method_counter),
        "response_codes_distribution": dict(status_counter),
        "critical_payload_features": [],
        "attempted_usernames": [],
        "invalid_token_requests_count": 0,
        "max_response_size_bytes": 0,
        "suspicious_samples": [],
        "infra_context": {},
        "security_state_features": {},
    }


def _normalize_tool_result(raw_result: Any) -> dict[str, Any]:
    if hasattr(raw_result, "content") and raw_result.content:
        return json.loads(raw_result.content[0].text)
    if isinstance(raw_result, dict):
        return raw_result
    return {}


async def run_validation(config: ValidationConfig) -> int:
    mcp_manager = MCPClientManagerAdapter()

    print("[1/5] Generando filtro Mongo via MCP tool 'generate_mongo_query_from_nl'...")
    raw_plan = await mcp_manager.call_tool(
        tool_name="generate_mongo_query_from_nl",
        arguments={"query": config.query, "source_id": config.source_id},
    )
    plan = _normalize_tool_result(raw_plan)

    mongo_filter = plan.get("mongo_filter")
    if not isinstance(mongo_filter, dict):
        print("ERROR: MCP no devolvio 'mongo_filter' valido.")
        print(PAYLOAD_RECEIVED_LABEL, plan)
        await mcp_manager.close()
        return 2

    print("Filtro generado:")
    print(json.dumps(mongo_filter, ensure_ascii=False, indent=2))

    print("[2/5] Consultando Mongo con el filtro generado...")
    mongo_client = MongoClient(config.mongo_uri, serverSelectionTimeoutMS=5000)
    db = mongo_client[config.mongo_db_name]
    telemetry_collection = db["raw_telemetry"]

    total_matches = telemetry_collection.count_documents(mongo_filter)
    raw_rows = list(telemetry_collection.find(mongo_filter).sort("_id", -1).limit(config.max_rows_for_report))
    rows: list[dict[str, Any]] = [dict(item) for item in raw_rows]

    for row in rows:
        if "_id" in row:
            row["id"] = str(row.pop("_id"))

    print(f"Coincidencias encontradas en raw_telemetry: {total_matches}")

    if total_matches == 0:
        print("ERROR: El flujo sigue devolviendo 0 matches con el filtro generado por MCP.")
        await mcp_manager.close()
        return 3

    print("[3/5] Generando reporte forense con resultados de base de datos...")
    raw_report = await mcp_manager.call_tool(
        tool_name="generate_forensic_report_from_logs",
        arguments={
            "query": config.query,
            "source_id": config.source_id,
            "total_matches": total_matches,
            "rows": rows,
        },
    )
    report = _normalize_tool_result(raw_report)

    markdown_report = report.get("markdown_report", "")
    if not isinstance(markdown_report, str) or not markdown_report.strip():
        print("ERROR: MCP no genero markdown_report valido.")
        print(PAYLOAD_RECEIVED_LABEL, report)
        await mcp_manager.close()
        return 4

    print("Reporte generado correctamente. Preview (primeras 12 lineas):")
    for line in markdown_report.splitlines()[:12]:
        print(line)

    if config.run_llm_check:
        print("[4/5] Validando analisis LLM real (Ollama/ModelfileForensic) con tool 'analyze_web_activity'...")
        analysis_payload = _build_analysis_payload(config.query, config.source_id, rows[: config.max_rows_for_llm])
        try:
            raw_assessment = await asyncio.wait_for(
                mcp_manager.call_tool(
                    tool_name="analyze_web_activity",
                    arguments=analysis_payload,
                ),
                timeout=float(config.llm_timeout_seconds),
            )
        except TimeoutError:
            print(
                "ERROR: analyze_web_activity supero el timeout de "
                f"{config.llm_timeout_seconds}s. Ajusta --llm-timeout o usa --skip-llm."
            )
            await mcp_manager.close()
            return 6
        assessment = _normalize_tool_result(raw_assessment)

        required_keys = ("threat_score", "reasoning_summary", "recommendation")
        missing = [key for key in required_keys if key not in assessment]
        if missing:
            print("ERROR: Respuesta de analyze_web_activity incompleta. Faltan:", missing)
            print(PAYLOAD_RECEIVED_LABEL, assessment)
            await mcp_manager.close()
            return 5

        print("LLM assessment OK:")
        print(json.dumps({k: assessment.get(k) for k in required_keys}, ensure_ascii=False, indent=2))

    print("[5/5] Cierre de sesion MCP.")
    await mcp_manager.close()
    return 0


def _parse_args() -> ValidationConfig:
    parser = argparse.ArgumentParser(description="Validate forensic MCP end-to-end flow")
    parser.add_argument(
        "--query",
        default="analiza la actividad de las ultimas 24 horas de la IP 172.18.0.2",
        help="Natural-language forensic query",
    )
    parser.add_argument("--source-id", default="victim-app-01", help="Telemetry source_id scope")
    parser.add_argument(
        "--max-rows",
        type=int,
        default=100,
        help="Max rows forwarded to generate_forensic_report_from_logs",
    )
    parser.add_argument(
        "--llm-max-rows",
        type=int,
        default=20,
        help="Max rows transformed into analyze_web_activity payload",
    )
    parser.add_argument(
        "--llm-timeout",
        type=int,
        default=180,
        help="Timeout seconds for analyze_web_activity validation",
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Skip analyze_web_activity validation step",
    )
    args = parser.parse_args()

    _load_env_file()
    mongo_uri, mongo_db_name = _build_mongo_uri()

    return ValidationConfig(
        query=args.query,
        source_id=args.source_id,
        mongo_db_name=mongo_db_name,
        mongo_uri=mongo_uri,
        max_rows_for_report=max(1, args.max_rows),
        max_rows_for_llm=max(1, args.llm_max_rows),
        llm_timeout_seconds=max(10, args.llm_timeout),
        run_llm_check=not args.skip_llm,
    )


def main() -> int:
    config = _parse_args()
    try:
        return asyncio.run(run_validation(config))
    except Exception as exc:
        print(f"ERROR: validation failed with unhandled exception: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

