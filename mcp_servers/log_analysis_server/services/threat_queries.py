"""Read-only Mongo querying and deterministic threat intelligence synthesis."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import re
from typing import Any

from pymongo import DESCENDING

from mcp_servers.log_analysis_server.database_manager import MongoDatabaseManager
from mcp_servers.log_analysis_server.models.threat_tools import (
    PotentialThreatAnalysisInput,
    RawTelemetryQueryInput,
    SourceTimelineInput,
    ThreatReportQueryInput,
)

_RAW_COLLECTION = "raw_telemetry"
_REPORTS_COLLECTION = "reports"
_RAW_TIME_FIELDS = ("timestamp_utc", "timestamp", "event_timestamp", "created_at", "window_start_utc")
_REPORT_TIME_FIELDS = ("created_at_utc", "created_at", "updated_at", "window_start_utc", "timestamp")
_SUSPICIOUS_PATH_TOKENS = ("/.env", "/.git", "/etc/passwd", "../", "%2e%2e", "/admin", "/wp-")
_SCANNER_TOKENS = ("sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "burp")
_RAW_SORT_CANDIDATES = ("timestamp_utc", "timestamp", "created_at")
_REPORT_SORT_CANDIDATES = ("created_at_utc", "created_at", "updated_at")


def _serialize_document(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _serialize_document(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize_document(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if value.__class__.__name__ == "ObjectId":
        return str(value)
    return value


def _build_time_filter(from_utc: datetime | None, to_utc: datetime | None, fields: tuple[str, ...]) -> dict[str, Any]:
    if not from_utc and not to_utc:
        return {}
    clauses: list[dict[str, Any]] = []
    for field in fields:
        condition: dict[str, Any] = {}
        if from_utc:
            condition["$gte"] = from_utc
        if to_utc:
            condition["$lte"] = to_utc
        clauses.append({field: condition})
    return {"$or": clauses}


def _build_multi_field_equals(fields: tuple[str, ...], value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if len(fields) == 1:
        return {fields[0]: value}
    return {"$or": [{field: value} for field in fields]}


def _build_case_insensitive_contains(fields: tuple[str, ...], value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    pattern = {"$regex": re.escape(value), "$options": "i"}
    return {"$or": [{field: pattern} for field in fields]}


def _merge_and_clauses(base_query: dict[str, Any], clause: dict[str, Any]) -> None:
    if not clause:
        return
    if not base_query:
        base_query.update(clause)
        return
    existing = base_query.pop("$and", [])
    if existing:
        existing.append(clause)
        base_query["$and"] = existing
        return
    base_snapshot = dict(base_query)
    base_query.clear()
    base_query["$and"] = [base_snapshot, clause]


def _pick_first_available_timestamp(row: dict[str, Any], candidates: tuple[str, ...]) -> str | None:
    for field in candidates:
        value = row.get(field)
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, str) and value:
            return value
    return None


def _normalize_raw_event(row: dict[str, Any]) -> dict[str, Any]:
    http_block = row.get("http") if isinstance(row.get("http"), dict) else {}
    network_block = row.get("network") if isinstance(row.get("network"), dict) else {}
    security_block = row.get("security") if isinstance(row.get("security"), dict) else {}
    host_block = row.get("host") if isinstance(row.get("host"), dict) else {}
    return {
        "id": str(row.get("_id")) if row.get("_id") is not None else row.get("id"),
        "timestamp_utc": _pick_first_available_timestamp(row, _RAW_SORT_CANDIDATES),
        "source_ip": row.get("source_ip") or network_block.get("client_ip"),
        "source_id": row.get("source_id"),
        "client_id": row.get("client_id"),
        "window_id": row.get("window_id"),
        "http_method": http_block.get("method") or row.get("http_method"),
        "http_path": http_block.get("path") or row.get("request_uri"),
        "http_status_code": http_block.get("status_code") or row.get("response_code"),
        "user_agent": http_block.get("user_agent") or row.get("user_agent"),
        "attempted_login_user": security_block.get("attempted_login_user"),
        "authenticated_user": security_block.get("authenticated_user"),
        "host_environment": host_block.get("environment"),
    }


def _normalize_report(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row.get("_id")) if row.get("_id") is not None else row.get("id"),
        "created_at_utc": _pick_first_available_timestamp(row, _REPORT_SORT_CANDIDATES),
        "source_ip": row.get("source_ip"),
        "source_id": row.get("source_id"),
        "client_id": row.get("client_id"),
        "window_id": row.get("window_id"),
        "threat_detected": row.get("threat_detected"),
        "threat_level": row.get("threat_level"),
        "threat_score": row.get("threat_score"),
        "reviewed": row.get("reviewed"),
        "resolved": row.get("resolved"),
        "kill_chain_phase": row.get("kill_chain_phase"),
        "mitre_tactic": row.get("mitre_tactic"),
        "mitre_technique": row.get("mitre_technique"),
        "indicators_found": row.get("indicators_found", []),
        "recommendation": row.get("recommendation"),
        "error": row.get("error"),
    }


def _extract_status(row: dict[str, Any]) -> int | None:
    status = row.get("response_code")
    if isinstance(status, int):
        return status
    http_block = row.get("http")
    if isinstance(http_block, dict):
        nested = http_block.get("status_code")
        if isinstance(nested, int):
            return nested
    return None


def _extract_path(row: dict[str, Any]) -> str:
    request_uri = row.get("request_uri")
    if isinstance(request_uri, str) and request_uri:
        return request_uri
    http_block = row.get("http")
    if isinstance(http_block, dict):
        path = http_block.get("path")
        if isinstance(path, str):
            return path
    return ""


def _extract_user_agent(row: dict[str, Any]) -> str:
    user_agent = row.get("user_agent")
    if isinstance(user_agent, str):
        return user_agent
    headers = row.get("headers")
    if isinstance(headers, dict):
        nested = headers.get("user-agent") or headers.get("User-Agent")
        if isinstance(nested, str):
            return nested
    return ""


class ThreatQueriesService:
    """Service with strictly whitelisted read operations over sentinel_soa collections."""

    def __init__(self, db_manager: MongoDatabaseManager) -> None:
        self._db_manager = db_manager

    async def get_raw_telemetry_events(self, payload: RawTelemetryQueryInput) -> dict[str, Any]:
        collection = self._db_manager.get_collection(_RAW_COLLECTION)
        query: dict[str, Any] = {}

        _merge_and_clauses(query, _build_multi_field_equals(("source_id", "extra_fields.source_id"), payload.source_id))
        _merge_and_clauses(
            query,
            _build_multi_field_equals(("source_ip", "network.client_ip", "network.proxy_real_ip"), payload.source_ip),
        )
        _merge_and_clauses(query, _build_multi_field_equals(("window_id",), payload.window_id))
        _merge_and_clauses(query, _build_multi_field_equals(("client_id",), payload.client_id))
        _merge_and_clauses(query, _build_multi_field_equals(("http.status_code",), payload.status_code))
        _merge_and_clauses(query, _build_multi_field_equals(("http.method",), payload.http_method))
        _merge_and_clauses(query, _build_case_insensitive_contains(("http.path", "request_uri"), payload.path_contains))
        _merge_and_clauses(
            query,
            _build_case_insensitive_contains(
                ("http.path", "http.query", "http.user_agent", "security.attempted_login_user", "source_ip", "source_id"),
                payload.query_text,
            ),
        )

        if payload.only_suspicious:
            suspicious_clause = {
                "$or": [
                    {"http.status_code": {"$gte": 400}},
                    {"security.attempted_login_user": {"$exists": True, "$ne": None}},
                ]
            }
            _merge_and_clauses(query, suspicious_clause)

        time_filter = _build_time_filter(payload.from_utc, payload.to_utc, _RAW_TIME_FIELDS)
        _merge_and_clauses(query, time_filter)

        cursor = collection.find(query).sort("timestamp_utc", DESCENDING).limit(payload.limit)
        raw_rows = [_serialize_document(row) for row in await cursor.to_list(length=payload.limit)]
        rows = [_normalize_raw_event(row) for row in raw_rows]
        status_counter = Counter(str(item["http_status_code"]) for item in rows if item.get("http_status_code") is not None)
        return {
            "collection": _RAW_COLLECTION,
            "query_applied": _serialize_document(query),
            "total_returned": len(rows),
            "filters_help": {
                "primary_keys": ["source_ip", "source_id", "window_id", "client_id"],
                "time_fields_supported": list(_RAW_TIME_FIELDS),
                "examples": [
                    {"source_ip": "10.0.0.1", "from_utc": "2026-08-11T00:00:00Z", "to_utc": "2026-08-11T23:59:59Z"},
                    {"status_code": 401, "only_suspicious": True, "limit": 200},
                    {"query_text": "admin login failed"},
                ],
            },
            "summary": {
                "unique_source_ips": len({item.get("source_ip") for item in rows if item.get("source_ip")}),
                "unique_source_ids": len({item.get("source_id") for item in rows if item.get("source_id")}),
                "status_distribution": dict(status_counter),
            },
            "rows": rows,
            "raw_rows": raw_rows,
        }

    async def get_threat_reports(self, payload: ThreatReportQueryInput) -> dict[str, Any]:
        collection = self._db_manager.get_collection(_REPORTS_COLLECTION)
        query: dict[str, Any] = {}

        _merge_and_clauses(query, _build_multi_field_equals(("source_id",), payload.source_id))
        _merge_and_clauses(query, _build_multi_field_equals(("source_ip",), payload.source_ip))
        _merge_and_clauses(query, _build_multi_field_equals(("window_id",), payload.window_id))
        _merge_and_clauses(query, _build_multi_field_equals(("client_id",), payload.client_id))
        _merge_and_clauses(query, _build_multi_field_equals(("threat_level",), payload.threat_level))
        _merge_and_clauses(query, _build_multi_field_equals(("reviewed",), payload.reviewed))
        _merge_and_clauses(query, _build_multi_field_equals(("resolved",), payload.resolved))
        _merge_and_clauses(query, _build_multi_field_equals(("threat_detected",), payload.threat_detected))
        if payload.min_threat_score is not None or payload.max_threat_score is not None:
            score_range: dict[str, Any] = {}
            if payload.min_threat_score is not None:
                score_range["$gte"] = payload.min_threat_score
            if payload.max_threat_score is not None:
                score_range["$lte"] = payload.max_threat_score
            _merge_and_clauses(query, {"threat_score": score_range})
        _merge_and_clauses(
            query,
            _build_case_insensitive_contains(
                ("reasoning_summary", "recommendation", "indicators_found", "error", "source_ip", "source_id"),
                payload.query_text,
            ),
        )

        time_filter = _build_time_filter(payload.from_utc, payload.to_utc, _REPORT_TIME_FIELDS)
        _merge_and_clauses(query, time_filter)

        cursor = collection.find(query).sort("created_at_utc", DESCENDING).limit(payload.limit)
        raw_rows = [_serialize_document(row) for row in await cursor.to_list(length=payload.limit)]
        rows = [_normalize_report(row) for row in raw_rows]
        threat_levels = Counter(str(item.get("threat_level")) for item in rows if item.get("threat_level"))
        return {
            "collection": _REPORTS_COLLECTION,
            "query_applied": _serialize_document(query),
            "total_returned": len(rows),
            "filters_help": {
                "primary_keys": ["source_ip", "source_id", "window_id", "client_id"],
                "severity_filters": ["threat_detected", "threat_level", "min_threat_score", "max_threat_score"],
                "time_fields_supported": list(_REPORT_TIME_FIELDS),
                "examples": [
                    {"threat_detected": True, "min_threat_score": 60, "resolved": False},
                    {"source_ip": "10.0.0.1", "threat_level": "HIGH", "limit": 50},
                    {"query_text": "sql injection"},
                ],
            },
            "summary": {
                "threat_levels": dict(threat_levels),
                "unresolved_count": sum(1 for item in rows if item.get("resolved") is False),
                "reviewed_count": sum(1 for item in rows if item.get("reviewed") is True),
            },
            "rows": rows,
            "raw_rows": raw_rows,
        }

    async def get_source_threat_timeline(self, payload: SourceTimelineInput) -> dict[str, Any]:
        raw_payload = RawTelemetryQueryInput(
            source_id=payload.source_id,
            source_ip=payload.source_ip,
            window_id=payload.window_id,
            client_id=payload.client_id,
            query_text=payload.query_text,
            from_utc=payload.from_utc,
            to_utc=payload.to_utc,
            limit=payload.limit_raw_events,
        )
        report_payload = ThreatReportQueryInput(
            source_id=payload.source_id,
            source_ip=payload.source_ip,
            window_id=payload.window_id,
            client_id=payload.client_id,
            query_text=payload.query_text,
            from_utc=payload.from_utc,
            to_utc=payload.to_utc,
            limit=payload.limit_reports,
        )
        raw = await self.get_raw_telemetry_events(raw_payload)
        reports = await self.get_threat_reports(report_payload)
        return {
            "source_ip": payload.source_ip,
            "source_id": payload.source_id,
            "window_id": payload.window_id,
            "client_id": payload.client_id,
            "time_range": {
                "from_utc": payload.from_utc.isoformat() if payload.from_utc else None,
                "to_utc": payload.to_utc.isoformat() if payload.to_utc else None,
            },
            "raw_events": raw,
            "reports": reports,
        }

    async def analyze_potential_threat(self, payload: PotentialThreatAnalysisInput) -> dict[str, Any]:
        timeline = await self.get_source_threat_timeline(payload)
        raw_rows = timeline["raw_events"]["rows"]
        report_rows = timeline["reports"]["rows"]

        status_counter = Counter()
        path_counter = Counter()
        user_agent_counter = Counter()
        suspicious_path_hits = 0
        scanner_user_agent_hits = 0

        for row in raw_rows:
            status = _extract_status(row)
            if status is not None:
                status_counter[str(status)] += 1

            path = _extract_path(row)
            if path:
                path_counter[path] += 1
                path_lower = path.lower()
                if any(token in path_lower for token in _SUSPICIOUS_PATH_TOKENS):
                    suspicious_path_hits += 1

            user_agent = _extract_user_agent(row)
            if user_agent:
                user_agent_counter[user_agent] += 1
                ua_lower = user_agent.lower()
                if any(token in ua_lower for token in _SCANNER_TOKENS):
                    scanner_user_agent_hits += 1

        total_events = len(raw_rows)
        status_4xx = sum(count for code, count in status_counter.items() if code.startswith("4"))
        status_5xx = sum(count for code, count in status_counter.items() if code.startswith("5"))
        ratio_4xx = (status_4xx / total_events) if total_events else 0.0
        ratio_5xx = (status_5xx / total_events) if total_events else 0.0

        unresolved_reports = [
            report for report in report_rows if not bool(report.get("resolved", False))
        ]
        high_reports = [
            report
            for report in report_rows
            if str(report.get("threat_level", "")).upper() in {"HIGH", "CRITICAL"}
        ]

        indicators: list[str] = []
        score = 0
        if scanner_user_agent_hits > 0:
            indicators.append("scanner_user_agent_detected")
            score += 30
        if suspicious_path_hits > 0:
            indicators.append("sensitive_path_probing_detected")
            score += 25
        if ratio_4xx >= 0.4 and total_events >= 20:
            indicators.append("high_4xx_ratio_detected")
            score += 20
        if ratio_5xx >= 0.2 and total_events >= 20:
            indicators.append("high_5xx_ratio_detected")
            score += 10
        if unresolved_reports:
            indicators.append("unresolved_threat_reports_detected")
            score += 15
        if high_reports:
            indicators.append("high_severity_reports_detected")
            score += 25
        if len(path_counter) >= 50:
            indicators.append("broad_path_enumeration_detected")
            score += 15

        score = min(score, 100)
        if score >= 80:
            severity = "CRITICAL"
        elif score >= 60:
            severity = "HIGH"
        elif score >= 40:
            severity = "MEDIUM"
        elif score >= 20:
            severity = "LOW"
        else:
            severity = "NONE"

        recommendations: list[str] = []
        if "scanner_user_agent_detected" in indicators:
            recommendations.append("Apply temporary WAF/IP block and tighten rate limits for the source.")
        if "sensitive_path_probing_detected" in indicators:
            recommendations.append("Audit exposed endpoints and verify hardening for sensitive files/routes.")
        if "high_4xx_ratio_detected" in indicators:
            recommendations.append("Review authentication defenses for brute-force or token misuse attempts.")
        if "high_severity_reports_detected" in indicators:
            recommendations.append("Escalate to incident response and prioritize unresolved high-severity reports.")
        if not recommendations:
            recommendations.append("Continue monitoring; no high-confidence threat pattern detected in current window.")

        return {
            "source_ip": payload.source_ip,
            "source_id": payload.source_id,
            "window_id": payload.window_id,
            "client_id": payload.client_id,
            "threat_detected": severity not in {"NONE", "LOW"},
            "threat_score": score,
            "threat_level": severity,
            "indicators_found": indicators,
            "summary": {
                "total_raw_events": total_events,
                "total_reports": len(report_rows),
                "total_unresolved_reports": len(unresolved_reports),
                "status_distribution": dict(status_counter),
                "top_requested_paths": path_counter.most_common(10),
                "top_user_agents": user_agent_counter.most_common(10),
                "suspicious_path_hits": suspicious_path_hits,
                "scanner_user_agent_hits": scanner_user_agent_hits,
                "ratio_4xx": round(ratio_4xx, 4),
                "ratio_5xx": round(ratio_5xx, 4),
            },
            "recommended_actions": recommendations,
            "evidence": timeline,
        }
