import re
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID
from typing import List, Dict, Any, Optional, Tuple, Set

from core_orchestrator.domain.entities.telemetry.logs_event import LogEvent

SQLI_PATTERN = re.compile(r"UNION|SELECT|DROP|--|' OR '", re.IGNORECASE)
PATH_TRAVERSAL_PATTERN = re.compile(r"(\.\./|%2e%2e%2f|/etc/passwd|/etc/shadow)", re.IGNORECASE)
SENSITIVE_FILES_PATTERN = re.compile(r"\.(zip|bak|env|git|conf|ini|log)$", re.IGNORECASE)

"""
Aggregated Telemetry Model Module (TelemetryWindow).

Defines the data schema that consolidates the behavioral metrics
of an IP address during a specific time interval.
"""
"""
Aggregated Telemetry Model Module (TelemetryWindow).

Defines the data schema that consolidates the behavioral metrics
of an IP address during a specific time interval with matrix correlation.
"""


@dataclass
class SuspiciousPayloadSample:
    """
    Represents a sample of suspicious payload detected in network traffic.

    This class encapsulates details about potentially harmful HTTP requests
    or responses, including the URI, HTTP method, payload, and the reason
    for classifying the interaction as suspicious. It supports storing
    additional metadata, such as the HTTP status code, response size, and
    associated log ID.
    """

    uri: str
    method: str
    payload_preview: str
    reason: str
    status_code: str = ""
    response_size_bytes: int = 0
    log_id: str = ""


@dataclass
class CorrelatedTrafficEntry:
    """
    Represents a single entry of correlated traffic data.

    This class is used to encapsulate information about specific HTTP traffic
    correlations with attributes describing the request path, method, status
    code, count of occurrences, and the primary user agents associated with the
    traffic. It is particularly useful for analysis and tracking of repeated
    patterns in web traffic.
    """

    path: str
    method: str
    status_code: str
    count: int
    primary_user_agents: List[str] = field(default_factory=list)


@dataclass
class SecurityStateFeatures:
    """
    Represents features associated with the security state of a user account or system.

    This class is used to analyze and encapsulate security-related data,
    including information about compromised accounts, successful login attempts,
    and internal network requests made after authentication. It provides
    a structured way to store and access these details for security monitoring
    purposes or integration with other systems.
    """

    compromised_accounts: List[str] = field(default_factory=list)
    successful_logins_count: int = 0
    post_auth_internal_requests: int = 0


@dataclass
class TelemetryWindow:
    """
    Represents a telemetry data window containing various statistical and analytical
    data points gathered within a specific time frame.

    This class is used to aggregate and analyze telemetry data associated with a specific
    unique window, providing insights into request patterns, security details, and other
    stateful monitoring features. It is particularly helpful in monitoring system
    performance, identifying threats, and analyzing user behavior over the specified window.

    Attributes:
        window_id (UUID): Unique identifier for the telemetry window.
        source_id (str): Identifier for the source of telemetry data.
        source_ip (str): IP address of the telemetry data source.
        window_start_utc (datetime): Start timestamp of the telemetry window in UTC.
        window_end_utc (datetime): End timestamp of the telemetry window in UTC.
        total_requests (int): Total number of HTTP requests observed during the window.
        unique_uris_requested (List[str]): List of unique URIs requested in the telemetry window.
        requests_per_second_avg (float): Average number of requests per second during the window.
        client_id (Optional[str]): Identifier for the client associated with the telemetry data.
        correlated_traffic_matrix (List[CorrelatedTrafficEntry]): List of correlated traffic
            entries for advanced traffic analysis.
        http_methods_distribution (Dict[str, int]): Distribution of HTTP methods with
            request counts.
        response_codes_distribution (Dict[str, int]): Distribution of HTTP response status
            codes with counts.
        user_agents_observed (List[str]): List of user-agent strings observed during the window.
        attempted_usernames (List[str]): List of usernames attempted during the window.
        invalid_token_requests_count (int): Count of requests with invalid tokens observed.
        max_response_size_bytes (int): Maximum response size in bytes recorded during the
            telemetry window.
        suspicious_samples (List[SuspiciousPayloadSample]): List of suspicious payload
            samples detected during this telemetry window.
        critical_payload_features (List[str]): List of critical payload features flagged
            during the analysis.
        security_state_features (SecurityStateFeatures): Security state and features
            observed within the window.
    """

    window_id: str
    source_id: str
    source_ip: str
    window_start_utc: datetime
    window_end_utc: datetime
    total_requests: int
    unique_uris_requested: List[str]
    requests_per_second_avg: float
    client_id: Optional[str] = None
    correlated_traffic_matrix: List[CorrelatedTrafficEntry] = field(
        default_factory=list
    )
    http_methods_distribution: Dict[str, int] = field(default_factory=dict)
    response_codes_distribution: Dict[str, int] = field(default_factory=dict)
    user_agents_observed: List[str] = field(default_factory=list)
    attempted_usernames: List[str] = field(default_factory=list)
    invalid_token_requests_count: int = 0
    max_response_size_bytes: int = 0
    suspicious_samples: List[SuspiciousPayloadSample] = field(
        default_factory=list
    )
    critical_payload_features: List[str] = field(default_factory=list)
    security_state_features: SecurityStateFeatures = field(
        default_factory=SecurityStateFeatures
    )


def _extract_log_id(log: Any) -> str:
    """
    Extracts the log ID from a given log object.

    This function attempts to retrieve a unique identifier ("_id") from the provided
    log object. It checks for the presence of the ID in attributes named
    'model_extra' or 'extra_fields'. If the '_id' is in dictionary format and
    contains a "$oid" key, the corresponding value is returned as a string.
    Otherwise, the '_id' itself is converted to a string and returned. If no
    applicable '_id' is found, an empty string is returned.

    Parameters:
    log (Any): The log object from which the ID will be extracted.

    Returns:
    str: The extracted log ID as a string. Returns an empty string if no ID
    is found.
    """
    model_extra = getattr(log, "model_extra", None) or {}
    raw_id = model_extra.get("_id") if isinstance(model_extra, dict) else None

    if raw_id is None:
        extra_fields = getattr(log, "extra_fields", None) or {}
        raw_id = extra_fields.get("_id") if isinstance(extra_fields, dict) else None

    if isinstance(raw_id, dict):
        return str(raw_id.get("$oid", ""))
    return str(raw_id) if raw_id is not None else ""


def _extract_auth_identity(log: Any, extra: Dict[str, Any]) -> Optional[str]:
    """

    """
    if isinstance(extra, dict):
        user_data = extra.get("user")
        if isinstance(user_data, dict):
            auth_id = user_data.get("authenticated_id") or user_data.get("authenticated_user")
            if auth_id:
                return str(auth_id)

        for key in ("authenticated_id", "authenticated_user"):
            if extra.get(key):
                return str(extra.get(key))

    model_extra = getattr(log, "model_extra", None)
    if isinstance(model_extra, dict):
        for key in ("authenticated_id", "authenticated_user"):
            if model_extra.get(key):
                return str(model_extra.get(key))

    return None

def build_web_activity_window(raw_logs: List[LogEvent], window_id: Optional[str] = None) -> TelemetryWindow:
    """
    Toma una lista de logs crudos, calcula métricas avanzadas correlacionando el tráfico
    en un formato matricial de (Path, Method, Status, UA) para no romper la historia,
    y detecta de manera determinista estados de intrusión/Account Takeover.
    """

    if not raw_logs:
        raise ValueError("La lista de logs no puede estar vacía.")

        # Identificadores iniciales
    first_log = raw_logs[0]
    source_id = getattr(first_log, "source_id", None) or "unknown-service"

    source_ip = "0.0.0.0"
    network = getattr(first_log, "network", None)
    if network and getattr(network, "client_ip", None):
        source_ip = network.client_ip
    elif getattr(first_log, "source_ip", None):
        source_ip = first_log.source_ip

    # Recolectores
    matrix_counters: Dict[Tuple[str, str, str], int] = Counter()
    matrix_agents: Dict[Tuple[str, str, str], Set[str]] = defaultdict(set)

    method_counters: Dict[str, int] = Counter()
    status_counters: Dict[str, int] = Counter()

    uris_set: Set[str] = set()
    user_agents_set: Set[str] = set()
    attempted_usernames_set: Set[str] = set()
    extracted_critical_payloads: Set[str] = set()

    # Variables de estado de seguridad
    compromised_accounts_set: Set[str] = set()
    successful_logins_count = 0
    post_auth_internal_requests = 0
    invalid_token_requests_count = 0

    max_response_size_bytes = 0

    # Reducción de timestamps en tiempo real en vez de guardar todos en memoria
    min_timestamp: Optional[datetime] = None
    max_timestamp: Optional[datetime] = None

    # Muestras sospechosas optimizadas por peso
    best_candidate_samples: Dict[str, Tuple[int, SuspiciousPayloadSample]] = {}

    for log in raw_logs:
        # 1. Manejo de Timestamps O(1) en memoria
        ts = getattr(log, "timestamp_utc", None)
        if ts:
            if not isinstance(ts, datetime):
                ts = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))

            if min_timestamp is None or ts < min_timestamp:
                min_timestamp = ts
            if max_timestamp is None or ts > max_timestamp:
                max_timestamp = ts

        # 2. Extracción defensiva del bloque HTTP
        http_data = getattr(log, "http", None)
        if http_data:
            path_str = getattr(http_data, "path", None) or "/"
            method_str = getattr(http_data, "method", None) or "UNKNOWN"
            status_int = getattr(http_data, "status_code", None)
            ua_str = getattr(http_data, "user_agent", None) or "Unknown-Agent"
            res_size = int(getattr(http_data, "response_size_bytes", 0) or 0)
            payload = getattr(http_data, "payload", "") or ""
            query_params = getattr(http_data, "query", "") or ""
        else:
            path_str, method_str, ua_str = "/", "UNKNOWN", "Unknown-Agent"
            status_int, res_size, payload, query_params = None, 0, "", ""

        status_str = str(status_int) if status_int is not None else "000"

        # Métricas generales
        if path_str != "/":
            uris_set.add(path_str)
        method_counters[method_str] += 1
        status_counters[status_str] += 1

        if ua_str != "Unknown-Agent":
            user_agents_set.add(ua_str)

        # Matriz correlacionada
        matrix_key = (path_str, method_str, status_str)
        matrix_counters[matrix_key] += 1
        matrix_agents[matrix_key].add(ua_str)

        if res_size > max_response_size_bytes:
            max_response_size_bytes = res_size

        # 3. Contexto de Autenticación
        extra = getattr(log, "extra_fields", None) or {}
        user_data = extra.get("user") if isinstance(extra, dict) else None
        username = user_data.get("attempted_username") if isinstance(user_data, dict) else None
        auth_id = _extract_auth_identity(log, extra)

        is_200 = status_int == 200
        is_success_status = status_int is not None and 200 <= status_int < 300

        if username:
            attempted_usernames_set.add(username)

        # Detección de Account Takeover
        if path_str == "/auth/login" and method_str == "POST" and is_200:
            successful_logins_count += 1
            if username:
                compromised_accounts_set.add(username)

        has_valid_auth = bool(auth_id and auth_id != "invalid_token")
        if path_str.startswith("/api/"):
            if is_success_status and (has_valid_auth or successful_logins_count > 0):
                post_auth_internal_requests += 1
            if auth_id is None or auth_id == "invalid_token":
                invalid_token_requests_count += 1

        # 4. Evaluación de Heurísticas Sospechosas
        full_payload_text = f"{payload} {query_params} {username or ''}"
        uri_with_context = f"{path_str}?{query_params}" if query_params and method_str == "GET" else path_str
        uri_key = uri_with_context.lower()

        weight = 0
        reason = ""
        preview = ""

        if SQLI_PATTERN.search(full_payload_text):
            weight = 100 if is_200 else 80
            reason = "SQL Injection signatures matched in payload or username syntax."
            preview = f"User: {username or 'anonymous'} | Payload: {payload[:100]}"
            if payload:
                extracted_critical_payloads.add(str(payload)[:120])
            elif query_params:
                extracted_critical_payloads.add(str(query_params)[:120])

        elif PATH_TRAVERSAL_PATTERN.search(path_str) or PATH_TRAVERSAL_PATTERN.search(full_payload_text):
            weight = 90 if is_200 else 70
            reason = "Path traversal or sensitive file access attempt detected."
            preview = f"URI Context: {path_str[:120]}"
            if query_params:
                extracted_critical_payloads.add(str(query_params)[:120])

        elif SENSITIVE_FILES_PATTERN.search(path_str):
            weight = 50
            reason = "Targeting sensitive server extensions or backup configurations."
            preview = ""

        # Registrar la muestra únicamente si supera la puntuación existente para esa URI
        if weight > 0:
            existing_weight = best_candidate_samples.get(uri_key, (-1, None))[0]
            if weight > existing_weight:
                log_id = _extract_log_id(log)
                sample = SuspiciousPayloadSample(
                    uri=uri_with_context,
                    method=method_str,
                    payload_preview=preview,
                    reason=reason,
                    status_code=status_str,
                    response_size_bytes=res_size,
                    log_id=log_id,
                )
                best_candidate_samples[uri_key] = (weight, sample)

    # 5. Muestras finales ordenadas ($O(K \log K)$ donde $K \ll N$)
    sorted_samples = sorted(best_candidate_samples.values(), key=lambda x: x[0], reverse=True)
    detected_samples = [sample for _, sample in sorted_samples]

    # 6. Cálculo de Tiempos y RPS sin sort()
    if min_timestamp and max_timestamp:
        window_start, window_end = min_timestamp, max_timestamp
        duration_seconds = max((window_end - window_start).total_seconds(), 1.0)
    else:
        window_start = window_end = datetime.now(timezone.utc)
        duration_seconds = 1.0

    total_requests = len(raw_logs)
    rps_avg = round(total_requests / duration_seconds, 2)

    # 7. Matriz Correlacionada
    traffic_matrix_entries = [
        CorrelatedTrafficEntry(
            path=p,
            method=m,
            status_code=s,
            count=count,
            primary_user_agents=list(matrix_agents[(p, m, s)])[:3],
        )
        for (p, m, s), count in matrix_counters.items()
    ]

    # Priorización de URIs en $O(N)$ usando dict.fromkeys()
    critical_attack_uris = [sample.uri for sample in detected_samples if sample.uri]
    prioritized_uris = list(dict.fromkeys(critical_attack_uris + list(uris_set)))

    resolved_window_id = str(window_id or getattr(first_log, "window_id", None) or uuid.uuid4())

    return TelemetryWindow(
        window_id=resolved_window_id,
        source_id=source_id,
        client_id=getattr(first_log, "client_id", None),
        source_ip=source_ip,
        window_start_utc=window_start,
        window_end_utc=window_end,
        total_requests=total_requests,
        correlated_traffic_matrix=traffic_matrix_entries,
        unique_uris_requested=prioritized_uris,
        http_methods_distribution=dict(method_counters),
        response_codes_distribution=dict(status_counters),
        user_agents_observed=list(user_agents_set),
        requests_per_second_avg=rps_avg,
        attempted_usernames=list(attempted_usernames_set),
        invalid_token_requests_count=invalid_token_requests_count,
        max_response_size_bytes=max_response_size_bytes,
        suspicious_samples=detected_samples[:5],
        critical_payload_features=sorted(extracted_critical_payloads)[:5],
        security_state_features=SecurityStateFeatures(
            compromised_accounts=list(compromised_accounts_set),
            successful_logins_count=successful_logins_count,
            post_auth_internal_requests=post_auth_internal_requests,
        ),
    )