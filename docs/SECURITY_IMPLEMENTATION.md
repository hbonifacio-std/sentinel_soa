# Security Implementation - Sentinel SOA

## Descripción General

Este documento detalla la implementación de seguridad por capas en la API del Core Orchestrator, incluyendo:

1. **Seguridad HMAC** para ingesta de telemetría
2. **Autenticación JWT** para analytics y rules
3. **Control de Acceso Basado en Roles (RBAC)** para endpoints administrativos
4. **CORS configurado** con orígenes permitidos específicos
5. **Gestión de Usuarios** en MongoDB

---

## 1. Configuración de Seguridad

### Variables de Entorno

```env
# HMAC Replay Attack Prevention
HMAC_REPLAY_WINDOW_SECONDS=300

# JWT Configuration
JWT_SECRET_KEY=your-secret-key-change-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRATION_MINUTES=60

# CORS Configuration
ALLOWED_CORS_ORIGINS=http://localhost:3000,http://localhost:8000,https://mi-app-web.com
```

**Valores por defecto seguros** se definen en `core_orchestrator/config.py` para desarrollo local.

---

## 2. Seguridad HMAC para `/api/v1/telemetry/`

### Objetivo

Proteger endpoints de ingesta de telemetría contra:
- Modificaciones en tránsito (integridad)
- Ataques de replay (repetición de solicitudes)
- Acceso no autorizado

### Flujo de Verificación

1. **Extracción de Headers:**
   - `X-Public-Key`: Identificador público del cliente
   - `X-Signature`: Firma HMAC-SHA256 del body
   - `X-Timestamp`: Timestamp Unix de la solicitud

2. **Validación de Timestamp:**
   ```python
   abs(now - timestamp) <= HMAC_REPLAY_WINDOW_SECONDS  # 5 minutos por defecto
   ```

3. **Recuperación de Secreto:**
   - Desde RedisSecretStore simulado (desarrollo)
   - Desde Redis real (producción)
   - Mapeo: `public_key -> secret`

4. **Cálculo de HMAC:**
   ```python
   message = f"{timestamp}:{raw_body}"
   expected = HMAC-SHA256(secret, message)
   ```

5. **Comparación Segura:**
   - Uso de `secrets.compare_digest()` para evitar timing attacks

### Endpoints Protegidos

- `POST /api/v1/telemetry/` - Evento singular
- `POST /api/v1/telemetry/ingest/batch` - Lote de eventos
- `POST /api/v1/telemetry/ingest/raw` - Logs en formato raw

### Ejemplo de Cliente

```python
import hmac
import hashlib
from datetime import datetime

public_key = "test-public-key-1"
secret = "test-secret-key-1-sha256-hmac"
timestamp = int(datetime.utcnow().timestamp())
body = b'{"ip_address": "192.168.1.1"}'

# Calcular firma
message = f"{timestamp}:{body.decode()}".encode()
signature = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()

# Enviar solicitud
headers = {
    "X-Public-Key": public_key,
    "X-Signature": signature,
    "X-Timestamp": str(timestamp)
}

response = requests.post("http://localhost:8000/api/v1/telemetry/", 
                         json={"...": "..."}, 
                         headers=headers)
```

---

## 3. Autenticación JWT para `/api/v1/auth/` y Endpoints Protegidos

### Objetivo

Autenticar usuarios y proteger acceso a analytics y rules management.

### Tokens JWT

**Estructura:**
```python
{
    "sub": "user-id-uuid",
    "username": "john_doe",
    "role": "admin",
    "exp": 1234567890,  # Expiration timestamp
    "iat": 1234567800   # Issued at timestamp
}
```

**Algoritmo:** HS256 (HMAC-SHA256)

### Endpoints de Autenticación

#### 1. Login (OAuth2 Password Flow)

```
POST /api/v1/auth/token

Request (x-www-form-urlencoded):
  username=admin
  password=AdminPassword123!

Response (200 OK):
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "user": {
    "user_id": "uuid",
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "is_active": true,
    "created_at": "2024-01-01T00:00:00+00:00",
    "updated_at": "2024-01-01T00:00:00+00:00"
  }
}

Errores:
  401: Credenciales incorrectas
  422: Campos faltantes o inválidos
```

#### 2. Perfil de Usuario

```
GET /api/v1/auth/me

Headers:
  Authorization: Bearer <access_token>

Response (200 OK):
{
  "user_id": "uuid",
  "username": "admin",
  "email": "admin@example.com",
  "role": "admin",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00+00:00",
  "updated_at": "2024-01-01T00:00:00+00:00"
}

Errores:
  401: Token inválido o expirado
  403: No autenticado
```

### Endpoints Protegidos

Todos requieren header `Authorization: Bearer <token>`:

**Analytics (Analyst/Admin):**
- `GET /api/v1/analytics/logs_row_telemetry`
- `GET /api/v1/analytics/reports`
- `GET /api/v1/analytics/stats`
- `PATCH /api/v1/analytics/reports/{id}/review`
- `POST /api/v1/analytics/reports/{id}/actions`
- `PATCH /api/v1/analytics/reports/{id}/resolve`

**Rules (Varies by operation):**
- `GET /api/v1/rules` - Analyst/Admin
- `GET /api/v1/rules/{id}` - Analyst/Admin
- `POST /api/v1/rules` - Admin only
- `PATCH /api/v1/rules/{id}` - Admin only
- `DELETE /api/v1/rules/{id}` - Admin only
- `POST /api/v1/rules/versions` - Admin only
- `POST /api/v1/rules/versions/activate/{id}` - Admin only

---

## 4. Role-Based Access Control (RBAC)

### Roles Definidos

#### **admin**
- Crear, actualizar, eliminar reglas
- Crear y activar versiones de reglas
- Ver analytics y reportes
- Ver usuarios

#### **analyst**
- Ver reglas y analytics
- Revisar y comentar en reportes
- Marcar reportes como resueltos

#### **viewer**
- Ver analytics y reportes de forma limitada
- Sin permisos de modificación

### Flujo de Autorización

```
Request con JWT
            ↓
Extraer token del header Authorization
            ↓
Validar firma y expiración
            ↓
Extraer role del payload
            ↓
Verificar role contra requisitos del endpoint
            ↓
Autorizar o denegar (403 Forbidden)
```

### Dependencias FastAPI para RBAC

```python
# Require authentication
@app.get("/protected")
async def protected(user: UserInDB = Depends(get_current_user)):
    return {"message": f"Hello {user.username}"}

# Require analyst or admin
@app.get("/analytics")
async def analytics(user: UserInDB = Depends(get_analyst_user)):
    return {"data": "..."}

# Require admin only
@app.post("/rules")
async def create_rule(user: UserInDB = Depends(get_admin_user)):
    return {"rule_id": "..."}
```

---

## 5. Gestión de Usuarios

### Modelo de Usuario

```python
{
  "_id": ObjectId(...),
  "user_id": "uuid",
  "username": "admin",
  "email": "admin@example.com",
  "hashed_password": "$2b$12$...",  # bcrypt hash
  "role": "admin",
  "is_active": true,
  "created_at": datetime(...),
  "updated_at": datetime(...)
}
```

**Índices MongoDB:**
- `username` (unique)
- `email` (recomendado para búsqueda rápida)

### Contraseñas

- **Algoritmo:** bcrypt
- **Rondas:** 12 (defecto de passlib)
- **Nunca se almacenan en texto plano**

### Seed de Usuarios Inicial

Archivo: `data/users_seed.json`

```json
[
  {
    "username": "admin",
    "email": "admin@example.com",
    "password": "AdminPassword123!",
    "role": "admin",
    "is_active": true
  },
  {
    "username": "analyst",
    "email": "analyst@example.com",
    "password": "AnalystPassword123!",
    "role": "analyst",
    "is_active": true
  },
  {
    "username": "viewer",
    "email": "viewer@example.com",
    "password": "ViewerPassword123!",
    "role": "viewer",
    "is_active": true
  }
]
```

### Migración de Usuarios

Ejecutar script para inicializar usuarios en MongoDB:

```bash
python scripts/migrate_users_to_mongodb.py
```

**Lo que hace:**
1. Lee `data/users_seed.json`
2. Conecta a MongoDB
3. Crea usuarios si no existen
4. Crea índice único en `username`
5. Desconecta de MongoDB

---

## 6. CORS (Cross-Origin Resource Sharing)

### Configuración

```python
ALLOWED_CORS_ORIGINS=http://localhost:3000,https://mi-app-web.com
```

Se convierte en:
```python
cors_origins = ["http://localhost:3000", "https://mi-app-web.com"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"]
)
```

**Nota:** CORS solo limita acceso desde el navegador. No reemplaza autenticación/autorización en la API.

---

## 7. RedisSecretStore Simulado

Para desarrollo local sin Redis real:

```python
# core_orchestrator/security/redis_secret_store.py
redis_secrets = RedisSecretStore()

# Test secrets
{
    "test-public-key-1": "test-secret-key-1-sha256-hmac",
    "test-public-key-2": "test-secret-key-2-for-batch-ingestion",
    "victim-app-key": "victim-app-secret-for-telemetry",
}
```

En producción, reemplazar con cliente Redis real.

---

## 8. Testing

### Pruebas de Seguridad

#### HMAC (`test_hmac_security.py`)
- ✅ Validación de firma válida
- ✅ Rechazo de firma inválida
- ✅ Prevención de replay attacks (timestamp antiguo)
- ✅ Rechazo de public_key desconocido
- ✅ Detección de body modificado
- ✅ Comparación constante de tiempo

#### JWT (`test_jwt_security.py`)
- ✅ Creación de token
- ✅ Decodificación exitosa
- ✅ Expiración de token
- ✅ Rechazo de token inválido
- ✅ Detección de token alterado
- ✅ Claims requeridos presentes

#### RBAC (`test_rbac_security.py`)
- ✅ Hash y verificación de contraseña
- ✅ Unicidad de hash de contraseña
- ✅ Jerarquía de roles
- ✅ Permisos por rol
- ✅ Token contiene role

#### Autenticación (`test_auth_endpoints.py`)
- ✅ Login con credenciales válidas
- ✅ Rechazo con credenciales inválidas
- ✅ GET /me requiere autenticación
- ✅ Endpoints protegidos requieren JWT
- ✅ Tokens inválidos rechazados

Ejecutar tests:
```bash
pytest core_orchestrator/test/unit/ -v
pytest core_orchestrator/test/integration/ -v
```

---

## 9. Arquitectura de Seguridad

```
Request HTTP
    ↓
┌─────────────────────────────────────┐
│ 1. CORS Middleware                  │ ← Valida origen
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│ 2. Seleccionar vía ruta              │
├─────────────────────────────────────┤
│ /telemetry/*  → HMAC verification   │
│ /auth/*       → Login/Profile        │
│ /analytics/*  → JWT + Analyst role   │
│ /rules/*      → JWT + role (var)     │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│ 3. Ejecutar lógica de endpoint       │
└─────────────────────────────────────┘
    ↓
Response
```

---

## 10. Mejores Prácticas

### En Desarrollo
1. Use `ALLOWED_CORS_ORIGINS=http://localhost:3000`
2. Use `JWT_SECRET_KEY=dev-secret-key-...`
3. Ejecute `python scripts/migrate_users_to_mongodb.py`
4. Use RedisSecretStore simulado (no hay cambios necesarios)

### En Producción
1. **CORS:** Configure solo orígenes permitidos en `.env`
2. **JWT Secret:** Genere una clave fuerte y única
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```
3. **Redis Real:** Reemplace RedisSecretStore con cliente Redis autenticado
4. **HTTPS/TLS:** Requiera HTTPS en producc
5. **Auditoría:** Registre accesos a endpoints sensibles
6. **Rotación de Secretos:** Implemente rotación periódica de JWT_SECRET_KEY

---

## 11. Resolución de Problemas

### Token expirado
```
Error: 401 Unauthorized - Could not validate credentials

Solución:
- Vuelva a iniciar sesión
- Aumente JWT_EXPIRATION_MINUTES si es necesario
```

### HMAC signature mismatch
```
Error: 401 Unauthorized - Invalid HMAC signature

Causas:
- Public key no registrado
- Body modificado en tránsito
- Secret key incorrecto
- Timestamp fuera de ventana de replay

Solución:
- Verifique X-Public-Key y secret en RedisSecretStore
- Verifique firma HMAC localmente
- Sincronice reloj con servidor (NTP)
```

### Acceso denegado (403)
```
Error: 403 Forbidden - Admin role required

Solución:
- Verifique role del usuario en base de datos
- Token codifica role correcto
- Actualice usuario con role apropiado
```

---

## 12. Referencias

- [JWT.io - JWT Debugger](https://jwt.io)
- [OWASP - Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
- [HMAC-SHA256 Signature](https://en.wikipedia.org/wiki/HMAC)

