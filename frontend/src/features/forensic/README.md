# Forensic Feature

## Scope
UI de investigacion forense con:
- ejecucion de consultas ad-hoc
- historial paginado de reportes
- detalle con render Markdown

## Main Files
- `ForensicPage.tsx`
- `services/forensicApi.ts`
- `hooks/useForensicHistory.ts`
- `hooks/useForensicAnalysis.ts`

## API Endpoints
- `POST /api/v1/forensic/analyze`
- `GET /api/v1/forensic/history`
- `GET /api/v1/forensic/history/{analysis_id}`

