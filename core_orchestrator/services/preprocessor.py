"""
Módulo de Preprocesamiento y Parsing de Telemetría HTTP.

Contiene la lógica analítica para transformar cadenas de texto crudas
(formato Common Log Format o similar) en modelos de datos estructurados Pydantic.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from core_orchestrator.models.log_event import LogEvent as LogLine


logger = logging.getLogger("core_orchestrator.services.preprocessor")


class LogPreprocessor:
    """
    Servicio encargado del parsing estricto y sanitización de registros de acceso web.
    """

    # Expresión regular robusta para parsear el estándar Combined Log Format de Nginx / Apache
    LOG_REGEX = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+[^"]*"\s+'
        r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s*'
        r'"?(?P<referer>[^"]*)"?\s*"?(?P<user_agent>[^"]*)"?'
    )

    @classmethod
    def parse_raw_line(cls, raw_line: str) -> Optional[LogLine]:
        """
        Parsea una línea cruda de log de servidor web y la transforma en un objeto LogLine.

        Args:
            raw_line (str): Línea de texto proveniente del log de acceso.

        Returns:
            Optional[LogLine]: Instancia validada si el parseo fue exitoso; None si es una línea malformada.
        """
        if not raw_line or not raw_line.strip():
            return None

        match = cls.LOG_REGEX.match(raw_line.strip())
        if not match:
            logger.debug(
                f"Línea de log omitida por no cumplir con el patrón estándar: {raw_line[:50]}...")
            return None

        data = match.groupdict()

        try:
            # Parseo de timestamp con formato estándar de servidores web: "08/Jun/2026:10:11:00 -0500"
            # Nota: Reemplazamos los dos puntos divisorios intermedios para facilitar el parseo nativo
            ts_str = data["timestamp"]
            # Formato típico: %d/%b/%Y:%H:%M:%S %z
            # Ejemplo: 10/Oct/2024:13:55:36 +0000
            parts = ts_str.split(' ', 1)
            datetime_part = parts[0]
            timezone_part = parts[1] if len(parts) > 1 else "+0000"

            # Ajustamos el formato de los dos puntos de Nginx/Apache
            first_colon = datetime_part.find(':')
            if first_colon != -1:
                dt_clean = datetime_part[:first_colon] + \
                    " " + datetime_part[first_colon+1:]
                parsed_dt = datetime.strptime(
                    f"{dt_clean} {timezone_part}", "%d/%b/%Y %H:%M:%S %z")
            else:
                parsed_dt = datetime.now(timezone.utc)

            # ✅ MEJORA: Preservar URI completa con parámetros para detección de inyecciones
            # Se mantienen los parámetros intactos ya que las heurísticas necesitan analizarlos
            full_uri = data["uri"]

            # Instanciación y validación automática mediante Pydantic v2
            return LogLine(
                source_ip=data["ip"],
                timestamp_utc=parsed_dt.astimezone(timezone.utc),
                http_method=data["method"].upper(),
                request_uri=full_uri,
                response_code=int(data["status"]),
                response_size_bytes=0 if data["bytes"] == "-" else int(
                    data["bytes"]),
                user_agent=data["user_agent"] if data["user_agent"] else "Unknown"
            )

        except Exception as exc:
            logger.warning(
                f"Error al procesar los campos de la línea de log parseada: {str(exc)}")
            return None

    @classmethod
    def preprocess_json_payload(cls, payload: Dict[str, Any]) -> Optional[LogLine]:
        """
        Valida y preprocesa eventos que ya vienen estructurados como objetos JSON desde agentes externos.
        """
        try:
            # Reutiliza el validador estático de Pydantic pasándole el diccionario crudo
            return LogLine(**payload)
        except Exception as err:
            logger.error(
                f"Estructura JSON inválida para el modelo LogLine: {str(err)}")
            return None
