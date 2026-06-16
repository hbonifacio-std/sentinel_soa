"""Módulo de definición del modelo de salida para el veredicto del Agente MCP.

Este módulo contiene el esquema estricto de Pydantic que mapea la evaluación
de amenazas de ciberseguridad, alineado con el modelo Cyber Kill Chain.
"""

from enum import Enum
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class ThreatLevelEnum(str, Enum):
    """Enumeración de los niveles de severidad de la amenaza detectada."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class KillChainPhaseEnum(str, Enum):
    """Enumeración de las fases del modelo Cyber Kill Chain aplicables a telemetría web."""
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"


class ThreatAssessment(BaseModel):
    """Modelo Pydantic que encapsula el análisis e indicadores dictaminados por el LLM.
    
    Este objeto representa la fuente de verdad que la herramienta MCP devuelve al 
    Core Orchestrator tras el procesamiento heurístico de los logs de la ventana.
    """

    window_id: UUID = Field(
        ...,
        description="Identificador único universal (UUID v4) coincidente con la ventana analizada."
    )
    threat_detected: bool = Field(
        ...,
        description="Flag booleano que indica si el comportamiento constituye una anomalía o ataque."
    )
    threat_level: ThreatLevelEnum = Field(
        ...,
        description="Severidad cualitativa asignada a la actividad observada."
    )
    threat_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Puntuación numérica de riesgo del 0 al 100% que cuantifica la probabilidad de amenaza."
    )
    kill_chain_phase: Optional[KillChainPhaseEnum] = Field(
        default=None,
        description="Fase del Cyber Kill Chain identificada. Nulo si threat_detected es falso."
    )
    indicators_found: List[str] = Field(
        default_factory=list,
        description="Listado conciso de patrones específicos encontrados (ej. 'Inyección SQL detectada')."
    )
    reasoning_summary: str = Field(
        ...,
        max_length=700,
        description="Síntesis del razonamiento heurístico del agente de IA en un máximo de 100 palabras."
    )
    recommendation: str = Field(
        ...,
        description="Acción mitigatoria explícita y priorizada sugerida para administradores del sistema."
    )

    model_config = {
        "use_enum_values": True,  # Facilita la serialización directa a cadenas JSON nativas
        "json_schema_extra": {
            "example": {
                "window_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
                "threat_detected": True,
                "threat_level": "HIGH",
                "threat_score": 87,
                "kill_chain_phase": "Reconnaissance",
                "indicators_found": [
                    "Presencia del User-Agent automatizado Nikto-Scanner/2.1",
                    "Ratio de respuestas 404 del 88% (8 de 9 requests)",
                    "Patrón sistemático de solicitud a rutas sensibles: /etc/passwd, /admin, /.git/config",
                    "RPS de 0.15 desde una única IP dentro de ventana de 60 segundos"
                ],
                "reasoning_summary": "La IP 10.0.0.66 ejecuta una campaña de reconocimiento activo siguiendo patrones típicos de herramientas de scanning (Nikto). Los indicadores múltiples convergen: User-Agent conocido, URIs objetivo sensibles, tasa de errores anómala. Confianza heurística de 87%.",
                "recommendation": "Nivel 1: Bloquear la IP 10.0.0.66 en el WAF/Firewall perimetral de inmediato. Nivel 2: Auditar logs históricos de los últimos 24h para identificar patrones correlacionados. Nivel 3: Verificar si endpoints administrativos están protegidos con autenticación y rate-limiting."
            }
        }
    }