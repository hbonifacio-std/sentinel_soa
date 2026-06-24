# Plan de Alineación con MITRE ATT&CK y NIST

Este documento detalla las recomendaciones para alinear el proyecto de análisis de telemetría con los frameworks MITRE ATT&CK y NIST Cybersecurity Framework (CSF), aumentando así su relevancia y robustez en el ámbito de la ciberseguridad.

## 1. Integración con MITRE ATT&CK

El objetivo es mapear las detecciones del sistema a las tácticas y técnicas específicas usadas por los adversarios, proporcionando un contexto invaluable a los analistas de seguridad.

### Acciones recomendadas:

1.  **Modificar el Modelo de Salida del Análisis:**
    *   **Archivo:** `mcp_servers/log_analysis_server/models/analysis_output.py`
    *   **Acción:** Extender el modelo `LLMResponse` (o el que se use para la salida final) para incluir campos que almacenen la información de ATT&CK.
    *   **Ejemplo de código a añadir/modificar:**
        ```python
        from typing import List, Optional
        from pydantic import BaseModel, Field

        class LLMResponse(BaseModel):
            # ... otros campos existentes ...
            mitre_tactic: Optional[str] = Field(None, description="MITRE ATT&CK Tactic name (e.g., 'Initial Access')")
            mitre_tactic_id: Optional[str] = Field(None, description="MITRE ATT&CK Tactic ID (e.g., 'TA0001')")
            mitre_technique: Optional[str] = Field(None, description="MITRE ATT&CK Technique name (e.g., 'Exploit Public-Facing Application')")
            mitre_technique_id: Optional[str] = Field(None, description="MITRE ATT&CK Technique ID (e.g., 'T1190')")
            mitre_sub_technique: Optional[str] = Field(None, description="MITRE ATT&CK Sub-Technique name (e.g., 'SQL Injection')")
            mitre_sub_technique_id: Optional[str] = Field(None, description="MITRE ATT&CK Sub-Technique ID (e.g., 'T1190.002')")
        ```
    *   **Nota:** Se añaden `mitre_sub_technique` y `mitre_sub_technique_id` para mayor granularidad, ya que muchas detecciones específicas suelen ser sub-técnicas.

2.  **Actualizar el Motor de Heurísticas:**
    *   **Archivo:** `mcp_servers/log_analysis_server/services/heuristics_engine.py`
    *   **Acción:** Cuando una heurística detecta una amenaza (ej. SQLi, Path Traversal), además de un puntaje de riesgo, debería devolver los IDs y nombres de la Táctica, Técnica y Sub-Técnica de ATT&CK correspondientes.
    *   **Ejemplo:**
        *   Detección de Inyección SQL: Mapear a **T1190.002** (Exploit Public-Facing Application: SQL Injection).
        *   Detección de Path Traversal: Mapear a **T1083** (File and Directory Discovery) o **T1203** (Exploitation for Client Execution).

3.  **Mejorar el Prompt del LLM:**
    *   **Archivo:** `mcp_servers/log_analysis_server/services/prompt_builder.py`
    *   **Acción:** Modificar el prompt para instruir explícitamente al LLM que su análisis debe incluir la identificación de tácticas, técnicas y sub-técnicas de MITRE ATT&CK y devolverlas en los nuevos campos definidos en el modelo de respuesta. Se debe reemplazar o complementar la referencia a la "Cyber Kill Chain" con el framework ATT&CK, que es más detallado para la atribución de técnicas.
    *   **Ejemplo de instrucción para el prompt:**
        `"Analyze the provided log data for malicious activity. Identify the specific MITRE ATT&CK Tactic, Technique, and Sub-Technique that best describe the observed activity. Provide their full names and IDs in the 'mitre_tactic', 'mitre_tactic_id', 'mitre_technique', 'mitre_technique_id', 'mitre_sub_technique', and 'mitre_sub_technique_id' fields of the structured JSON output."`

4.  **Visualizar en el Frontend:**
    *   **Archivo:** `frontend/src/App.js` y componentes relacionados.
    *   **Acción:** Modificar los componentes de la interfaz de usuario que muestran los detalles de las alertas para que presenten de manera clara la nueva información de MITRE ATT&CK. Se pueden incluir enlaces directos a las páginas de las técnicas en el sitio web oficial de MITRE ATT&CK para proporcionar contexto adicional al analista.

## 2. Alineación con el NIST Cybersecurity Framework (CSF)

El proyecto se enfoca principalmente en la función de **Detección (DE)**. Las siguientes acciones buscan fortalecer esta función y empezar a dar soporte a la función de **Respuesta (RS)**.

### Acciones recomendadas:

1.  **Mejorar el Proceso de Detección (DE.DP - Detection Processes are Improved):**
    *   **Acción:** Implementar un **mecanismo de retroalimentación de alertas**. Añadir un endpoint en la API del `core_orchestrator` que permita al frontend enviar feedback sobre la precisión de una alerta (ej. "Falso Positivo", "Verdadero Positivo Confirmado", "Necesita más investigación").
    *   **Impacto:** Esta retroalimentación es crucial para la mejora continua del sistema, permitiendo afinar heurísticas, ajustar prompts del LLM o incluso entrenar modelos de machine learning con datos más precisos.

2.  **Habilitar una Respuesta más Rápida y Estructurada (RS.AN - Analysis, RS.MI - Mitigation):**
    *   **Acción:** Añadir un campo `suggested_mitigations` al modelo de salida del análisis (`analysis_output.py`). Este campo contendría una lista de objetos estructurados con acciones de mitigación recomendadas.
    *   **Ejemplo de código a añadir/modificar:**
        ```python
        class SuggestedMitigation(BaseModel):
            action: str = Field(..., description="Type of mitigation action (e.g., 'block_ip', 'rate_limit_user', 'isolate_host')")
            target: str = Field(..., description="The entity to which the action applies (e.g., IP address, username, host ID)")
            reason: str = Field(..., description="Brief explanation for the suggested mitigation")
            severity: Optional[str] = Field("medium", description="Severity of the suggested action (low, medium, high, critical)")
            automation_ready: bool = Field(False, description="Indicates if the action is ready for automated execution by a SOAR platform")

        class LLMResponse(BaseModel):
            # ... otros campos existentes ...
            suggested_mitigations: List[SuggestedMitigation] = []
        ```
    *   **Impacto:** Transforma las recomendaciones del LLM de texto libre a datos estructurados que pueden ser consumidos y potencialmente automatizados por plataformas SOAR (Security Orchestration, Automation, and Response), agilizando el tiempo de respuesta ante incidentes.

3.  **Facilitar la Comunicación de Incidentes (RS.CO - Communications):**
    *   **Acción:** Desarrollar un nuevo servicio o módulo de "Notificación de Alertas" dentro del `core_orchestrator`. Este servicio se encargaría de enviar alertas de alta severidad a sistemas externos.
    *   **Implementación:**
        *   Integración con Webhooks: Para notificar a herramientas como Slack, Microsoft Teams o sistemas de ticketing.
        *   Integración con Message Brokers: Publicar eventos de alerta en colas de mensajes (ej. Kafka, RabbitMQ) para que otros sistemas (ej. SIEM, SOAR) puedan suscribirse y procesarlos de forma asíncrona.
    *   **Impacto:** Asegura que los equipos de seguridad sean alertados de forma oportuna y que la información del incidente se propague eficientemente a través de la infraestructura de seguridad existente.

Este plan ofrece un camino claro para mejorar las capacidades de tu sistema y su interoperabilidad con los estándares y herramientas de ciberseguridad modernos.