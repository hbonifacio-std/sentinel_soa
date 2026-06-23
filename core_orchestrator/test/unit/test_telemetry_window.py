from datetime import datetime, timezone, timedelta

from core_orchestrator.models.log_event import LogEvent, HttpContext, NetworkContext
from core_orchestrator.models.telemetry_window import build_web_activity_window


def _build_log(
    *,
    ts: datetime,
    method: str,
    path: str,
    status_code: int,
    extra_fields: dict | None = None,
    query: str | None = None,
) -> LogEvent:
    return LogEvent(
        source_id="victim-app-01",
        source_ip="172.18.0.3",
        timestamp_utc=ts,
        network=NetworkContext(client_ip="172.18.0.3"),
        http=HttpContext(
            method=method,
            path=path,
            query=query,
            status_code=status_code,
            user_agent="pytest-agent",
            response_size_bytes=123,
            payload=None,
        ),
        extra_fields=extra_fields or {},
    )


def test_build_web_activity_window_populates_http_distributions():
    base = datetime.now(timezone.utc)
    logs = [
        _build_log(ts=base, method="GET", path="/", status_code=200),
        _build_log(
            ts=base + timedelta(seconds=1),
            method="POST",
            path="/auth/login",
            status_code=200,
            extra_fields={"user": {"attempted_username": "alice", "authenticated_id": "alice"}},
        ),
        _build_log(
            ts=base + timedelta(seconds=2),
            method="GET",
            path="/api/users/me",
            status_code=200,
            extra_fields={"user": {"authenticated_id": "alice"}},
        ),
        _build_log(
            ts=base + timedelta(seconds=3),
            method="POST",
            path="/api/products",
            status_code=201,
            extra_fields={"user": {"authenticated_id": "alice"}},
        ),
    ]

    window = build_web_activity_window(logs)

    assert window.http_methods_distribution == {"GET": 2, "POST": 2}
    assert window.response_codes_distribution == {"200": 3, "201": 1}
    assert window.security_state_features.post_auth_internal_requests == 2


def test_build_web_activity_window_counts_post_auth_after_login_when_auth_id_missing():
    base = datetime.now(timezone.utc)
    logs = [
        _build_log(
            ts=base,
            method="POST",
            path="/auth/login",
            status_code=200,
            extra_fields={"user": {"attempted_username": "bob"}},
        ),
        _build_log(
            ts=base + timedelta(seconds=1),
            method="GET",
            path="/api/users/me",
            status_code=200,
            extra_fields={},
        ),
    ]

    window = build_web_activity_window(logs)

    assert window.security_state_features.successful_logins_count == 1
    assert window.security_state_features.post_auth_internal_requests == 1

