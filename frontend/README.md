# Sentinel SOA Frontend v2

Frontend migrado a Vite + React 18 + TypeScript + Tailwind + Zustand.

## Scripts

- `npm run dev`: inicia el servidor de desarrollo.
- `npm run build`: compila TypeScript y genera `build/` para Docker/Nginx.
- `npm run preview`: sirve localmente el build generado.

## Variables de entorno

Revisar `.env.example`:

- `VITE_API_BASE_URL`
- `VITE_MOCK_DATA`
- `VITE_AUTH_PERSIST_SESSION`: `true` para respaldar token en `sessionStorage` (por pestaña), `false` para memoria-only.

## Autenticacion OAuth2

- Login en `/login` contra `POST /api/v1/auth/token` (`application/x-www-form-urlencoded`).
- El frontend envia `Authorization: Bearer <token>` automaticamente en endpoints protegidos.
- Bootstrap de sesion con `GET /api/v1/auth/me` al iniciar la app.
- Logout con `POST /api/v1/auth/logout` + limpieza local inmediata.
- 401 invalida sesion y redirige a login; 403 se muestra como falta de permisos.

## Vistas

- `/`: Dashboard (requiere rol `admin` o `analyst`)
- `/alerts`: Alert Center (requiere rol `admin` o `analyst`)
- `/logs`: Log Viewer (requiere rol `admin` o `analyst`)
- `/rules`: Rules Management (lectura para analyst; escritura para admin)
