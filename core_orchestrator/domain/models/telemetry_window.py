import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from uuid import UUID
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from core_orchestrator.domain.models.log_event import LogEvent, InfrastructureContext
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

class SuspiciousPayloadSample(BaseModel):
    """Representa una muestra de tráfico sospechoso detectado por el backend."""
    uri: str = Field(..., description="The URI path where the suspicious payload was sent.")
    method: str = Field(..., description="HTTP Method used (POST, GET, etc.).")
    payload_preview: str = Field(..., description="Sanitized preview of the payload, query parameters, or body.")
    reason: str = Field(..., description="Heuristic reason why this sample was included.")
    status_code: str = Field("", description="HTTP status code returned for this specific sample.")
    response_size_bytes: int = Field(0, ge=0, description="Response size for this specific sample.")
    log_id: str = Field("", description="The database OID (_id) of the original raw log.")


class CorrelatedTrafficEntry(BaseModel):
    """Representa una fila correlacionada en la matriz de distribución de tráfico."""
    path: str = Field(..., description="The endpoint or resource URI.")
    method: str = Field(..., description="HTTP Method used.")
    status_code: str = Field(..., description="HTTP Status code returned.")
    count: int = Field(..., ge=1, description="Number of identical events matching this composite key.")
    primary_user_agents: List[str] = Field(default_factory=list,
                                           description="Unique User-Agents matching this matrix intersection.")


class SecurityStateFeatures(BaseModel):
    """Atributos condicionales sobre el estado de la autenticación detectados en la ventana."""
    compromised_accounts: List[str] = Field(default_factory=list,
                                            description="User accounts targeted with concurrent successful codes (200).")
    successful_logins_count: int = Field(default=0, ge=0,
                                         description="Count of status code 200 on authentication checkpoints.")
    post_auth_internal_requests: int = Field(default=0, ge=0,
                                             description="Volume of standard application API requests following authorization signatures.")


class TelemetryWindow(BaseModel):
    """
    Perimeter aggregation contract formally sent to the Orchestrator Agent.
    """
    window_id: UUID = Field(..., description="Universal unique identifier (UUID v4) of the analysis window.")
    source_id: str = Field(..., description="Unique identifier of the server or application that originates the log.")
    source_ip: str = Field(..., description="Source IP address under analysis.")
    window_start_utc: datetime = Field(..., description="Time window start timestamp in ISO 8601 UTC format.")
    window_end_utc: datetime = Field(..., description="Time window end timestamp in ISO 8601 UTC format.")
    total_requests: int = Field(..., gt=0, description="Total number of requests recorded within the window.")

    correlated_traffic_matrix: List[CorrelatedTrafficEntry] = Field(
        default_factory=list,
        description="Matrix correlating Paths, Methods, Status Codes, and User-Agents to prevent story breakdown."
    )

    # Mantenido por retrocompatibilidad/slicing perimetral rápido
    unique_uris_requested: List[str] = Field(...,
                                             description="Consolidated list of unique resource paths (URIs) requested.")
    http_methods_distribution: Dict[str, int] = Field(
        default_factory=dict,
        description="Frequency distribution by HTTP method (e.g., {'GET': 15, 'POST': 5})."
    )
    response_codes_distribution: Dict[str, int] = Field(
        default_factory=dict,
        description="Frequency distribution of HTTP response codes (e.g., {'200': 10, '404': 10})."
    )
    user_agents_observed: List[str] = Field(default_factory=list,
                                            description="List of unique User-Agent strings identified.")
    requests_per_second_avg: float = Field(..., ge=0.0,
                                           description="Average requests per second processed within the time block.")
    attempted_usernames: List[str] = Field(default_factory=list,
                                           description="Distinct usernames targeted during authentication.")
    invalid_token_requests_count: int = Field(default=0, ge=0,
                                              description="Number of requests with token/validation anomalies.")
    max_response_size_bytes: int = Field(default=0, ge=0, description="The maximum response size observed.")

    suspicious_samples: List[SuspiciousPayloadSample] = Field(default_factory=list,
                                                              description="Structural log samples.")
    critical_payload_features: List[str] = Field(default_factory=list,
                                                 description="Sanitized high-signal payload fragments.")
    infra_context: Optional[InfrastructureContext] = Field(default=None, description="Compact infrastructure summary.")

    security_state_features: SecurityStateFeatures = Field(
        default_factory=SecurityStateFeatures,
        description="State machine features detecting session compromise or multi-stage behavior."
    )


def _extract_infra_context(raw_logs: List[LogEvent]) -> Optional[InfrastructureContext]:
    """Returns the first available infrastructure context from the raw logs."""
    for log in raw_logs:
        if getattr(log, "infra_context", None):
            return log.infra_context
        host = getattr(log, "host", None)
        network = getattr(log, "network", None)
        if host or network:
            return InfrastructureContext(
                environment=getattr(host, "environment", None),
                process_name=getattr(host, "process_name", None),
                server_port=getattr(network, "server_port", None),
                proxy_real_ip=getattr(network, "proxy_real_ip", None),
                proxy_forwarded_for=getattr(network, "proxy_forwarded_for", None),
            )
    return None


def build_web_activity_window(raw_logs: List[LogEvent]) -> TelemetryWindow:
    """
    Toma una lista de logs crudos, calcula métricas avanzadas correlacionando el tráfico
    en un formato matricial de (Path, Method, Status, UA) para no romper la historia,
    y detecta de manera determinista estados de intrusión/Account Takeover.
    """
    if not raw_logs:
        raise ValueError("La lista de logs no puede estar vacía.")

    # 1. Extraer metadatos comunes e identificadores de la ventana
    window_id = uuid.uuid4()
    first_log = raw_logs[0]
    source_id = first_log.source_id or "unknown-service"

    source_ip = "0.0.0.0"
    if first_log.network and hasattr(first_log.network, "client_ip") and first_log.network.client_ip:
        source_ip = first_log.network.client_ip
    elif first_log.source_ip:
        source_ip = first_log.source_ip

    # 2. Inicializar recolectores y el nuevo Mapa Matricial
    # El diccionario tendrá como clave la tupla composta (path, method, status) -> set(user_agents)
    matrix_counters: Dict[tuple, int] = Counter()
    matrix_agents: Dict[tuple, set] = {}

    uris_list = []
    method_counters: Dict[str, int] = Counter()
    status_counters: Dict[str, int] = Counter()
    user_agents_set = set()
    attempted_usernames_set = set()
    extracted_critical_payloads = set()

    # Variables de estado de seguridad
    compromised_accounts_set = set()
    successful_logins_count = 0
    post_auth_internal_requests = 0
    invalid_token_requests_count = 0

    max_response_size_bytes = 0
    timestamps = []

    _candidate_samples: List[tuple] = []
    _uri_best_weight: Dict[str, int] = {}

    # Expresiones regulares básicas
    sqli_pattern = re.compile(r"UNION|SELECT|DROP|--|' OR '", re.IGNORECASE)
    path_traversal_pattern = re.compile(r"(\.\./|%2e%2e%2f|/etc/passwd|/etc/shadow)", re.IGNORECASE)
    sensitive_files_pattern = re.compile(r"\.(zip|bak|env|git|conf|ini|log)$", re.IGNORECASE)

    def _extract_log_id(log: Any) -> str:
        raw_id = None
        if hasattr(log, "model_extra") and log.model_extra:
            raw_id = log.model_extra.get("_id")
        if raw_id is None:
            raw_id = (log.extra_fields or {}).get("_id") if hasattr(log, "extra_fields") else None
        return str(raw_id.get("$oid") if isinstance(raw_id, dict) else (raw_id or ""))

    def _register_sample(weight: int, sample: SuspiciousPayloadSample) -> None:
        uri_key = sample.uri.lower()
        existing_best = _uri_best_weight.get(uri_key, -1)
        if weight > existing_best:
            _uri_best_weight[uri_key] = weight
            nonlocal _candidate_samples
            _candidate_samples = [(w, k, s) for w, k, s in _candidate_samples if k != uri_key]
            _candidate_samples.append((weight, uri_key, sample))

    def _extract_auth_identity(log: Any, extra: Dict[str, Any]) -> Optional[str]:
        """Best-effort extraction of authenticated user id across log variants."""
        user_data = extra.get("user", {}) if isinstance(extra, dict) else {}
        if isinstance(user_data, dict):
            auth_id = user_data.get("authenticated_id") or user_data.get("authenticated_user")
            if auth_id:
                return str(auth_id)

        # Fallbacks seen in flattened telemetry formats.
        for key in ("authenticated_id", "authenticated_user"):
            if isinstance(extra, dict) and extra.get(key):
                return str(extra.get(key))

        model_extra = getattr(log, "model_extra", {}) or {}
        for key in ("authenticated_id", "authenticated_user"):
            if isinstance(model_extra, dict) and model_extra.get(key):
                return str(model_extra.get(key))

        return None

    # 3. Iterar los logs de la ventana
    for log in raw_logs:
        if log.timestamp_utc:
            if isinstance(log.timestamp_utc, datetime):
                timestamps.append(log.timestamp_utc)
            else:
                timestamps.append(datetime.fromisoformat(str(log.timestamp_utc).replace("Z", "+00:00")))

        http_data = log.http
        uri = getattr(http_data, "path", None) if http_data else None
        method = getattr(http_data, "method", None) if http_data else None
        status_int = getattr(http_data, "status_code", None) if http_data else None
        status = str(status_int) if status_int is not None else ""
        user_agent = getattr(http_data, "user_agent", None) if http_data else None
        res_size = int(getattr(http_data, "response_size_bytes", 0) or 0) if http_data else 0

        # Rellenar datos bizarros o nulos de forma segura
        path_str = uri or "/"
        method_str = method or "UNKNOWN"
        status_str = status or "000"
        ua_str = user_agent or "Unknown-Agent"

        if uri:
            uris_list.append(uri)
        method_counters[method_str] += 1
        status_counters[status_str] += 1
        if user_agent:
            user_agents_set.add(user_agent)

        # 🔥 ALIMENTAR MATRIZ CORRELACIONADA
        matrix_key = (path_str, method_str, status_str)
        matrix_counters[matrix_key] += 1
        if matrix_key not in matrix_agents:
            matrix_agents[matrix_key] = set()
        matrix_agents[matrix_key].add(ua_str)

        if res_size > max_response_size_bytes:
            max_response_size_bytes = res_size

        # Extraer campos extendidos de autenticación
        extra = log.extra_fields or {}
        user_data = extra.get("user", {}) if isinstance(extra, dict) else {}
        username = user_data.get("attempted_username") if isinstance(user_data, dict) else None
        auth_id = _extract_auth_identity(log, extra)
        is_200 = status_int == 200
        is_success_status = status_int is not None and 200 <= status_int < 300

        if username:
            attempted_usernames_set.add(username)

        # 🔥 LÓGICA DE DETECCIÓN DE ACCOUNT TAKEOVER (ESTADO DE LA SESIÓN)
        if path_str == "/auth/login" and method_str == "POST" and is_200:
            successful_logins_count += 1
            if username:
                compromised_accounts_set.add(username)

        # Contar actividad interna si ya posee tokens o accesos válidos a APIs internas
        has_valid_auth_context = bool(auth_id and auth_id != "invalid_token")
        if path_str.startswith("/api/") and is_success_status:
            # Fallback: if backend did not propagate auth_id but login success exists in this window,
            # treat it as likely post-auth internal activity.
            if has_valid_auth_context or successful_logins_count > 0:
                post_auth_internal_requests += 1

        if path_str.startswith("/api/") and (auth_id is None or auth_id == "invalid_token"):
            invalid_token_requests_count += 1

        log_id = _extract_log_id(log)
        payload = getattr(http_data, "payload", "") or "" if http_data else ""
        query_params = getattr(http_data, "query", "") or "" if http_data else ""
        full_payload_text = f"{payload} {query_params} {username if username else ''}"

        uri_with_context = f"{path_str}?{query_params}" if query_params and method_str == "GET" else path_str

        # Heurísticas de Muestras Sospechosas y Extracción de fragmentos de payloads
        if sqli_pattern.search(full_payload_text):
            weight = 100 if is_200 else 80
            if payload:
                extracted_critical_payloads.add(str(payload)[:120])
            elif query_params:
                extracted_critical_payloads.add(str(query_params)[:120])

            _register_sample(weight, SuspiciousPayloadSample(
                uri=uri_with_context,
                method=method_str,
                payload_preview=f"User: {username or 'anonymous'} | Payload: {payload[:100]}",
                reason="SQL Injection signatures matched in payload or username syntax.",
                status_code=status_str, response_size_bytes=res_size, log_id=log_id,
            ))

        elif path_traversal_pattern.search(path_str) or path_traversal_pattern.search(full_payload_text):
            weight = 90 if is_200 else 70
            if query_params:
                extracted_critical_payloads.add(str(query_params)[:120])

            _register_sample(weight, SuspiciousPayloadSample(
                uri=uri_with_context,
                method=method_str,
                payload_preview=f"URI Context: {path_str[:120]}",
                reason="Path traversal or sensitive file access attempt detected.",
                status_code=status_str, response_size_bytes=res_size, log_id=log_id,
            ))

        elif uri and sensitive_files_pattern.search(path_str):
            _register_sample(50, SuspiciousPayloadSample(
                uri=path_str, method=method_str, payload_preview="",
                reason="Targeting sensitive server extensions or backup configurations.",
                status_code=status_str, response_size_bytes=res_size, log_id=log_id,
            ))

    # Ordenar las muestras detectadas
    _candidate_samples.sort(key=lambda t: t[0], reverse=True)
    detected_samples: List[SuspiciousPayloadSample] = [s for _, _, s in _candidate_samples]

    # 4. Cálculos cronológicos y de rendimiento (RPS)
    if timestamps:
        timestamps.sort()
        window_start, window_end = timestamps[0], timestamps[-1]
        duration_seconds = (window_end - window_start).total_seconds()
    else:
        window_start = window_end = datetime.now(timezone.utc)
        duration_seconds = 1.0

    total_requests = len(raw_logs)
    rps_avg = round(total_requests / duration_seconds, 2) if duration_seconds > 0 else float(total_requests)

    # 5. CONSTRUCCIÓN DE LA MATRIZ FORMATEADA FINAL
    traffic_matrix_entries: List[CorrelatedTrafficEntry] = []
    for (p, m, s), count in matrix_counters.items():
        traffic_matrix_entries.append(CorrelatedTrafficEntry(
            path=p,
            method=m,
            status_code=s,
            count=count,
            primary_user_agents=list(matrix_agents[(p, m, s)])[:3]  # Limitado a 3 agentes para no saturar tokens
        ))

    # Reordenamiento determinista de rutas críticas
    critical_attack_uris = [sample.uri for sample in detected_samples if sample.uri]
    global_unique_uris = list(set(uris_list))

    prioritized_uris = []
    for uri_path in (critical_attack_uris + global_unique_uris):
        if uri_path not in prioritized_uris:
            prioritized_uris.append(uri_path)

    # Retornamos el contrato Pydantic estructurado listo para la IA analítica
    return TelemetryWindow(
        window_id=window_id,
        source_id=source_id,
        source_ip=source_ip,
        window_start_utc=window_start,
        window_end_utc=window_end,
        total_requests=total_requests,
        correlated_traffic_matrix=traffic_matrix_entries,  # Matriz inyectada
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
        infra_context=_extract_infra_context(raw_logs),
        security_state_features=SecurityStateFeatures(
            compromised_accounts=list(compromised_accounts_set),
            successful_logins_count=successful_logins_count,
            post_auth_internal_requests=post_auth_internal_requests
        )
    )