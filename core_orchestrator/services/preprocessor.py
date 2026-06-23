"""
HTTP Telemetry Preprocessing and Parsing Module.

Contains the analytical logic to transform raw text strings
(Common Log Format or similar) into structured Pydantic data models.
"""

import logging
import re
import json
from datetime import datetime, timezone
from typing import Optional

from core_orchestrator.models.log_event import (
    LogEvent as LogLine,
    HttpContext,
    NetworkContext,
    HostContext,
    InfrastructureContext,
)


logger = logging.getLogger("core_orchestrator.services.preprocessor")


class LogPreprocessor:
    """
    Service responsible for strict parsing and sanitization of web access records.
    """

    # Robust regular expression to parse the Nginx / Apache Combined Log Format standard
    LOG_REGEX = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>.+?)\]\s+'
        r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+[^"]*"\s+'
        r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s*'
        r'"?(?P<referer>[^"]*)"?\s*"?(?P<user_agent>[^"]*)"?'
    )

    @staticmethod
    def _build_json_log_line(data: dict) -> LogLine:
        network_data = data.get("network", {}) if isinstance(data.get("network"), dict) else {}
        host_data = data.get("host", {}) if isinstance(data.get("host"), dict) else {}

        return LogLine(
            source_id=data["source_id"],
            source_ip=data["source_ip"],
            timestamp_utc=datetime.fromisoformat(data["timestamp"]),
            network=NetworkContext(
                client_ip=data["source_ip"],
                client_port=network_data.get("client_port"),
                server_port=network_data.get("server_port"),
                proxy_forwarded_for=network_data.get("proxy_forwarded_for"),
                proxy_real_ip=network_data.get("proxy_real_ip"),
            ),
            host=HostContext(
                pid=host_data.get("pid"),
                process_name=host_data.get("process_name"),
                process_time_ms=host_data.get("process_time_ms"),
                environment=host_data.get("environment"),
            ),
            infra_context=InfrastructureContext(
                environment=host_data.get("environment"),
                process_name=host_data.get("process_name"),
                server_port=network_data.get("server_port"),
                proxy_real_ip=network_data.get("proxy_real_ip"),
                proxy_forwarded_for=network_data.get("proxy_forwarded_for"),
            ),
            http=HttpContext(
                method=data["request_method"],
                path=data.get("request_path", "/"),
                query=data.get("request_query"),
                status_code=data["status_code"],
                user_agent=data.get("user_agent"),
                response_size_bytes=None,
                referrer=None,
            ),
            extra_fields=data.get("extra_fields", {}) if isinstance(data.get("extra_fields"), dict) else {},
        )

    @staticmethod
    def _build_combined_log_line(data: dict) -> LogLine:
        return LogLine(
            source_id="unknown-source",
            source_ip=data["ip"],
            timestamp_utc=data["parsed_dt"].astimezone(timezone.utc),
            network=NetworkContext(
                client_ip=data["ip"],
            ),
            infra_context=InfrastructureContext(
                environment=None,
                process_name=None,
                server_port=None,
                proxy_forwarded_for=None,
                proxy_real_ip=None,
            ),
            http=HttpContext(
                method=data["method"].upper(),
                path=data["uri_path"],
                query=data["uri_query"],
                status_code=int(data["status"]),
                response_size_bytes=0 if data["bytes"] == "-" else int(data["bytes"]),
                user_agent=data.get("user_agent") if data.get("user_agent") else None,
                referrer=data.get("referer") if data.get("referer") != "-" else None,
            ),
            extra_fields={},
        )

    @classmethod
    def parse_raw_line(cls, raw_line: str) -> Optional[LogLine]:
        """
        Parses a raw web server log line and transforms it into a LogLine object.
        Supports JSON format and Combined Log Format.
        """
        if not raw_line or not raw_line.strip():
            return None

        # Try parsing as JSON first
        try:
            data = json.loads(raw_line)
            return cls._build_json_log_line(data)
        except (json.JSONDecodeError, KeyError):
            # If it fails, try with the combined log format (regex)
            logger.debug("Failed to parse as JSON, trying classic log format.")

        match = cls.LOG_REGEX.match(raw_line.strip())
        if not match:
            logger.debug(
                f"Log line skipped for not matching the standard pattern: {raw_line[:50]}...")
            return None

        data = match.groupdict()

        try:
            # Timestamp parsing with web server standard format: "08/Jun/2026:10:11:00 -0500"
            ts_str = data["timestamp"]
            parts = ts_str.split(' ', 1)
            datetime_part = parts[0]
            timezone_part = parts[1] if len(parts) > 1 else "+0000"

            first_colon = datetime_part.find(':')
            if first_colon != -1:
                dt_clean = datetime_part[:first_colon] + \
                    " " + datetime_part[first_colon+1:]
                parsed_dt = datetime.strptime(
                    f"{dt_clean} {timezone_part}", "%d/%b/%Y %H:%M:%S %z")
            else:
                parsed_dt = datetime.now(timezone.utc)
            full_uri = data["uri"]
            uri_parts = full_uri.split("?", 1)
            return cls._build_combined_log_line({
                "ip": data["ip"],
                "parsed_dt": parsed_dt,
                "method": data["method"],
                "uri_path": uri_parts[0],
                "uri_query": uri_parts[1] if len(uri_parts) > 1 else None,
                "status": data["status"],
                "bytes": data["bytes"],
                "user_agent": data.get("user_agent"),
                "referer": data.get("referer"),
            })

        except Exception as exc:
            logger.warning(
                f"Error processing fields of the regex-parsed log line: {str(exc)}")
            return None
