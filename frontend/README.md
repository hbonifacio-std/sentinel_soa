# Sentinel SOA Frontend v2

Frontend migrado a Vite + React 18 + TypeScript + Tailwind + Zustand.

## Scripts

- `npm run dev`: inicia el servidor de desarrollo.
- `npm run build`: compila TypeScript y genera `build/` para Docker/Nginx.
- `npm run preview`: sirve localmente el build generado.

## Variables de entorno

Revisar `.env.example`:

- `VITE_API_BASE_URL`
- `VITE_POLLING_INTERVAL_MS`
- `VITE_MOCK_DATA`

## Vistas

- `/`: Dashboard
- `/alerts`: Alert Center
- `/logs`: Log Viewer

