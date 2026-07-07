"""Forensic NLQ tooling for query planning and markdown intelligence reports."""

import asyncio
import json
import logging
import re
from collections import Counter
from typing import Any, Optional, List, Tuple

from mcp_servers.log_analysis_server.config import server_settings
from mcp_servers.log_analysis_server.llm_providers import create_llm_provider
from mcp_servers.log_analysis_server.models.forensic_input import ForensicReportInput, ForensicQueryPlannerInput
from mcp_servers.log_analysis_server.services.prompt_factory import build_forensic_prompt
from mcp_servers.log_analysis_server.services.translate_mongo import TranslateMongo

_SUSPICIOUS_PATH_TOKENS = ("/.env", "/.git", "/etc/passwd", "../", "%2e%2e", "/admin", "/wp-")
_SCANNER_TOKENS = ("sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "burp")
_REGEX_OPERATOR = "$regex"
_OPTIONS_OPERATOR = "$options"
_HTTP_PATH_FIELD = "http.path"
_DEFAULT_FORENSIC_REPORT_TIMEOUT_SECONDS = 1800

# Constants for Triage and Sampling
_LOW_VOLUME_LOG_THRESHOLD = 150
_SAMPLED_LOG_COUNT = 250

logger = logging.getLogger(__name__)


_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_STATUS_PATTERN = re.compile(r"\b[1-5]\d\d\b")
_URI_PATTERN = re.compile(r"/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]|%[0-9A-Fa-f]{2})+")
_WORD_PATTERN = re.compile(r"[A-Za-z0-9_.:%-]{3,}")


def _extract_status_codes(query_text: str, ip_matches: list[str]) -> list[int]:
    text_without_ips = query_text
    for ip in ip_matches:
        text_without_ips = text_without_ips.replace(ip, " ")
    return sorted({int(code) for code in _STATUS_PATTERN.findall(text_without_ips)})


def _extract_keyword_terms(query_text: str) -> list[str]:
    stopwords = {
        "analiza",
        "analizar",
        "actividad",
        "buscar",
        "consulta",
        "forense",
        "logs",
        "log",
        "entre",
        "desde",
        "hasta",
        "para",
        "con",
        "que",
        "del",
        "los",
        "las",
        "http",
        "https",
        "ip",
        "ultima",
        "ultimas",
        "horas",
        "hora",
        "dias",
        "dia",
    }

    terms: list[str] = []
    for token in _WORD_PATTERN.findall(query_text):
        normalized = token.lower()
        if normalized in stopwords or normalized.isdigit():
            continue
        if _IP_PATTERN.fullmatch(normalized) or _STATUS_PATTERN.fullmatch(normalized):
            continue
        terms.append(normalized)
    return terms


def _extract_json_object(raw_text: str) -> dict[str, Any]:
    stripped = str(raw_text or "").strip()
    if not stripped:
        return {}

    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        pass

    fenced = re.search(r"```(?:json)?\s*(\{.*})\s*```", stripped, re.DOTALL | re.IGNORECASE)
    if fenced:
        try:
            parsed = json.loads(fenced.group(1).strip())
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start >= 0 and end > start:
        try:
            parsed = json.loads(stripped[start : end + 1])
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}

    return {}


def _run_intelligent_sampling(rows: List[dict[str, Any]], query: str) -> Tuple[List[dict[str, Any]], str]:
    """
    Selects a high-relevance sample from a large volume of logs.
    """
    logger.info(f"Running intelligent sampling on {len(rows)} logs.")
    
    # 1. Programmatic Analysis to find points of interest
    ip_counter = Counter(str(row.get("source_ip") or "N/A") for row in rows if row.get("source_ip"))
    top_ips = {ip for ip, count in ip_counter.most_common(5)}

    high_interest_logs = []
    normal_logs = []
    
    query_keywords = set(_extract_keyword_terms(query.lower()))

    for row in rows:
        is_high_interest = False
        
        # Interest based on IP activity
        if row.get("source_ip") in top_ips:
            is_high_interest = True
            
        # Interest based on critical status codes
        status = row.get("response_code") or row.get("http", {}).get("status_code")
        if status in {401, 403, 500}:
            is_high_interest = True

        # Interest based on sensitive path access
        uri = str(row.get("request_uri") or row.get("http", {}).get("path") or "").lower()
        if any(token in uri for token in _SUSPICIOUS_PATH_TOKENS):
            is_high_interest = True

        # Interest based on scanner signatures
        user_agent = str(row.get("user_agent") or "").lower()
        if any(token in user_agent for token in _SCANNER_TOKENS):
            is_high_interest = True
            
        # Interest based on keywords from user prompt
        row_text = json.dumps(row).lower()
        if any(keyword in row_text for keyword in query_keywords):
            is_high_interest = True

        if is_high_interest:
            high_interest_logs.append(row)
        else:
            normal_logs.append(row)

    # 2. Build the sample
    sampled_rows = high_interest_logs
    
    # Add normal logs to provide baseline context if there's space
    remaining_space = _SAMPLED_LOG_COUNT - len(sampled_rows)
    if remaining_space > 0 and normal_logs:
        # Prioritize taking normal logs from the beginning and end of the timeframe
        slice_size = min(remaining_space, len(normal_logs)) // 2
        sampled_rows.extend(normal_logs[:slice_size])
        sampled_rows.extend(normal_logs[-slice_size:])

    # Ensure the final sample size is within the limit
    sampled_rows = sampled_rows[:_SAMPLED_LOG_COUNT]
    
    # 3. Create context note
    top_ip_str = ip_counter.most_common(1)[0][0] if ip_counter else "N/A"
    context_note = (
        f"Note: The original query returned {len(rows)} logs. "
        f"An intelligent sample of the {len(sampled_rows)} most relevant events is presented below for analysis. "
        f"Key findings from the full set include unusual activity from IP {top_ip_str} and "
        f"{len(high_interest_logs)} high-interest events."
    )
    
    logger.info(f"Sampling complete. Selected {len(sampled_rows)} logs. Context note created.")
    
    return sampled_rows, context_note


async def _generate_llm_forensic_report(
    payload: ForensicReportInput,
    rows: list[dict[str, Any]],
    system_context_note: Optional[str] = None
) -> dict[str, Any]:
    model_id_to_use = server_settings.default_model_id
    
    model_def = server_settings.available_models.get(model_id_to_use)
    if not model_def:
        raise ValueError(f"Model ID '{model_id_to_use}' not found in the available models catalog.")

    provider = create_llm_provider(
        provider_name=model_def.provider,
        model_name=model_def.model_name,
        max_output_tokens=model_def.max_output_tokens,
        config=server_settings.get_provider_config(),
        max_input_tokens=model_def.max_input_tokens,
    )
    
    prompt = build_forensic_prompt(
        payload,
        rows,
        provider_name=provider.provider_name,
        system_context_note=system_context_note,
        max_input_tokens=model_def.max_input_tokens,
    )
    
    response_text = await asyncio.wait_for(
        provider.call_model(prompt),
        timeout=float(_DEFAULT_FORENSIC_REPORT_TIMEOUT_SECONDS),
    )
    parsed = _extract_json_object(response_text)
    return parsed


async def build_forensic_mongo_query(arguments: dict[str, Any]) -> dict[str, Any]:
    """Build a safe MongoDB filter from natural-language forensic intent using an LLM."""
    payload = ForensicQueryPlannerInput(**arguments)
    
    if not payload.query:
        return {
            "mongo_filter": {},
            "detected_terms": [],
            "detected_ips": [],
            "detected_status_codes": [],
        }

    default_model_info = server_settings.available_models.get(server_settings.default_model_id)
    active_provider = default_model_info.provider if default_model_info else 'ollama'

    if active_provider == 'ollama':
        translator_model_id = "sentinel-translator-mongodb"
    else:
        translator_model_id = server_settings.default_model_id
    
    logger.info(f"Using translator model: {translator_model_id} (determined by active provider: {active_provider})")

    translator = TranslateMongo(model_id=translator_model_id)
    
    result = await translator.translate_query(
        query=payload.query,
        source_id=payload.source_id
    )

    if "error" in result:
        logger.error(f"Translation failed for query '{payload.query}': {result.get('details')}")
        return result

    if "mongo_filter" not in result or not isinstance(result["mongo_filter"], dict):
        logger.warning(f"Malformed success response for query: '{payload.query}'. LLM response: {result}")
        return {
            "error": "Malformed translation.",
            "details": "LLM response did not contain a valid 'mongo_filter' dictionary.",
            "llm_response": result
        }

    return result


async def generate_forensic_report(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Generate high-signal forensic markdown report from telemetry result rows.
    This tool implements a smart triage system:
    - For a low volume of logs, it performs a direct, in-depth analysis.
    - For a high volume of logs, it uses an intelligent sampling technique to distill
      the most critical events, ensuring an efficient and relevant analysis.
    """
    payload = ForensicReportInput(**arguments)
    rows = payload.rows
    system_context_note = None

    # Triage based on the number of logs
    if len(rows) > _LOW_VOLUME_LOG_THRESHOLD:
        # High volume -> Use intelligent sampling
        rows, system_context_note = _run_intelligent_sampling(payload.rows, payload.query)
    
    # For both low volume and sampled high volume, generate the report
    try:
        llm_result = await _generate_llm_forensic_report(payload, rows, system_context_note)
        
        # Basic validation of the LLM output
        if llm_result.get("markdown_report") and llm_result.get("highlights"):
            return llm_result
        else:
            logger.error("LLM output was missing 'markdown_report' or 'highlights'.")
            # Return a structured error if the output is malformed
            return {
                "error": "Malformed report from LLM.",
                "details": "The AI model's response did not follow the expected format.",
                "llm_response": llm_result
            }
            
    except Exception as exc:
        logger.error(f"Forensic report generation failed: {exc}", exc_info=True)
        # Propagate a clear error to the orchestrator in case of any failure
        return {
            "error": "Forensic report generation failed.",
            "details": f"The AI model could not generate a report. Reason: {str(exc)}"
        }

