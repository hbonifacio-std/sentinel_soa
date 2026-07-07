# Forensic Module

## Scope
Aplicacion de analisis forense para consultas ad-hoc sobre telemetria y persistencia de reportes historicos.

## Flow
1. API recibe `ForensicAnalyzeRequest`.
2. `ForensicService` consulta telemetria via `ForensicAnalysisRepositoryPort`.
3. Se genera un reporte Markdown resumido y se persiste en `forensic_analysis`.
4. Frontend consulta historial y detalle por `analysis_id`.

## Ports
- `ForensicServicePort`
- `ForensicAnalysisRepositoryPort`

## Adapter
- `MongoForensicAnalysisRepository`

