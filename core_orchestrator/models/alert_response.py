from pydantic import BaseModel, Field

class AlertResponseSchema(BaseModel):
    """Esquema Pydantic para forzar la estructura de salida JSON en la API de Gemini."""
    
    threat_detected: bool = Field(
        ..., 
        description="Boolean: true si hay evidencia de escaneo, ataque o herramientas maliciosas, false si es 100% benigno."
    )
    risk_level: str = Field(
        ..., 
        description="Nivel de riesgo determinado. Valores permitidos: BAJO, MEDIO, ALTO, CRÍTICO"
    )
    kill_chain_phase: str = Field(
        ..., 
        description="Fase detectada del modelo Cyber Kill Chain o 'N/A' si es benigno."
    )
    report_summary: str = Field(
        ..., 
        description="Reporte analítico detallado en formato Markdown que contiene secciones de Diagnóstico y Recomendaciones."
    )