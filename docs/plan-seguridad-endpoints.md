# Plan de seguridad por endpoint (`core_orchestrator`)

## Objetivo
Aplicar controles de seguridad por capa para proteger la ingesta de telemetria, el acceso de la aplicacion web y la administracion de reglas.

## Checklist de implementacion

- [ ] **Configurar parametros de seguridad**
  - [ ] Definir variables de entorno para CORS, JWT y ventana de replay HMAC.
  - [ ] Exponer defaults seguros para desarrollo local y pruebas.

- [ ] **Implementar seguridad HMAC para `/ingest/`**
  - [ ] Crear dependencia `verify_hmac_signature`.
  - [ ] Validar cabeceras: `X-Public-Key`, `X-Signature`, `X-Timestamp`.
  - [ ] Verificar diferencia de timestamp <= 5 minutos.
  - [ ] Recuperar secreto desde Redis (cliente real o simulado).
  - [ ] Calcular HMAC-SHA256 del body crudo y comparar con `secrets.compare_digest`.
  - [ ] Aplicar dependencia a endpoints de ingesta de telemetria.

- [ ] **Implementar autenticacion JWT para `/analytics/` y `/rules/`**
  - [ ] Crear utilidades JWT (emitir, validar expiracion, validar firma HS256).
  - [ ] Implementar `OAuth2PasswordBearer` y dependencia `get_current_user`.
  - [ ] Proteger todos los endpoints de analytics con token valido.
  - [ ] Proteger endpoints de reglas con token valido.
  - [ ] Aplicar RBAC `admin` en endpoints de modificacion de reglas.

- [ ] **Agregar endpoint de autenticacion para frontend**
  - [ ] Crear `/api/v1/auth/token` para login (flujo OAuth2 password).
  - [ ] Crear `/api/v1/auth/me` para resolver usuario autenticado.
  - [ ] Usar repositorio de usuarios simulado para entorno inicial.

- [ ] **Restringir CORS por dominio**
  - [ ] Configurar `CORSMiddleware` con dominios permitidos especificos.
  - [ ] Incluir `https://mi-app-web.com` y `http://localhost:3000` como ejemplo.

- [ ] **Gestionar usuarios en MongoDB**
  - [ ] Crear modelo de usuario (Pydantic) con campos: `user_id`, `username`, `email`, `hashed_password`, `role`, `is_active`, `created_at`.
  - [ ] Implementar hash y verificacion de contraseñas con `bcrypt`.
  - [ ] Crear servicio `UserService` para CRUD de usuarios.
  - [ ] Crear seed de usuarios iniciales (admin, analyst) en archivo JSON.
  - [ ] Agregar script de migracion para insertar usuarios desde seed en MongoDB.
  - [ ] Indexar `username` como unico en coleccion `users`.

- [ ] **Implementar autenticacion en frontend**
  - [ ] Crear capa `authApi` (login y perfil).
  - [ ] Guardar token y perfil en store (persistencia local).
  - [ ] Adjuntar `Authorization: Bearer ...` en `apiFetch`.
  - [ ] Crear vista de login y rutas protegidas.
  - [ ] Restringir acceso a vistas de reglas si el rol no es `admin`.

- [ ] **Pruebas y validacion**
  - [ ] Agregar pruebas de HMAC validando 401/403 y replay.
  - [ ] Agregar pruebas JWT/RBAC para analytics y rules.
  - [ ] Agregar pruebas de autenticacion de usuario (login fallido, token expirado).
  - [ ] Ejecutar pytest de seguridad e integracion critica.

## Notas de arquitectura
- La verificacion HMAC se separa como dependencia reutilizable para mantener los endpoints limpios.
- JWT y RBAC se centralizan en modulo `security` para evitar logica duplicada.
- El cliente Redis simulado permite desarrollo local y testing sin infraestructura completa.
- CORS limita origenes web, pero no reemplaza autenticacion/autorizacion.

