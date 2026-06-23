"""
Módulo de Pruebas Unitarias para el Preprocesador de Logs.

Prueba el comportamiento del parser frente a entradas válidas, 
entradas malformadas y casos de borde.
"""

import pytest
from datetime import datetime, timezone
from core_orchestrator.services.preprocessor import LogPreprocessor
from core_orchestrator.models.log_event import LogEvent as LogLine


def test_parse_valid_combined_log_line():
    """
    Verifica que una línea estándar de Nginx/Apache Combined Log
    sea parseada correctamente extrayendo con precisión sus atributos.
    """
    raw_line = (
        '192.168.1.50 - - [10/Jun/2026:13:55:36 +0000] '
        '"GET /api/v1/users?id=99 HTTP/1.1" 200 1024 '
        '"http://referer.com" "Mozilla/5.0 (Windows NT 10.0)"'
    )

    result = LogPreprocessor.parse_raw_line(raw_line)

    assert result is not None
    assert isinstance(result, LogLine)
    assert result.source_ip == "192.168.1.50"
    assert result.http is not None
    assert result.http.method == "GET"
    assert result.http.path == "/api/v1/users"   # Path sin query string
    assert result.http.query == "id=99"           # Query separada
    assert result.http.status_code == 200
    assert result.http.response_size_bytes == 1024
    assert result.http.user_agent == "Mozilla/5.0 (Windows NT 10.0)"
    assert result.timestamp_utc.tzinfo == timezone.utc


def test_parse_malformed_log_line():
    """
    Garantiza que el preprocesador descarte limpiamente líneas corruptas
    o que no coincidan con la firma esperada, retornando None.
    """
    malformed_line = "ESTO NO ES UN LOG WEB VALIDO 404 GET"

    result = LogPreprocessor.parse_raw_line(malformed_line)

    assert result is None


def test_parse_empty_or_whitespace_line():
    """
    Verifica la resiliencia del parser ante strings vacíos o espacios en blanco.
    """
    assert LogPreprocessor.parse_raw_line("") is None
    assert LogPreprocessor.parse_raw_line("    \n") is None
