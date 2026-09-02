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

## Autenticacion OAuth2

- Login en `/login` contra `POST /api/v1/auth/token` (`application/x-www-form-urlencoded`).
- El frontend envia `Authorization: Bearer <token>` automaticamente en endpoints protegidos.
- Bootstrap de sesion con `POST /api/v1/auth/refresh` usando cookie HttpOnly (`credentials: include`).
- Reintento automatico una sola vez ante `401` mediante refresh token.
- Logout con `POST /api/v1/auth/logout`, revocacion server-side y limpieza local inmediata.
- Los tokens de acceso se mantienen solo en memoria (sin `localStorage/sessionStorage`).
- 401 invalida sesion y redirige a login; 403 se muestra como falta de permisos.

## Vistas

- `/`: Dashboard (requiere rol `admin` o `analyst`)
- `/alerts`: Alert Center (requiere rol `admin` o `analyst`)
- `/logs`: Log Viewer (requiere rol `admin` o `analyst`)
- `/rules`: Rules Management (lectura para analyst; escritura para admin)
