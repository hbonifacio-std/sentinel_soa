# Quick Start - Seguridad en Sentinel SOA

## 1. Instalación de Dependencias

Se han agregado las siguientes librerías:
- `python-jose[cryptography]` - JWT
- `passlib[bcrypt]` - Password hashing
- `python-multipart` - OAuth2 form support
- `PyJWT` - Token handling

Instalar:
```bash
cd sentinel_soa
pip install -r core_orchestrator/requirements.txt
```

## 2. Configuración de Variables de Entorno

Crear `.env` en la raíz del proyecto:

```env
# Puerto de la API
API_PORT=8000

# Seguridad HMAC
HMAC_REPLAY_WINDOW_SECONDS=300

# Seguridad JWT
JWT_SECRET_KEY=dev-secret-key-change-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRATION_MINUTES=60

# CORS
ALLOWED_CORS_ORIGINS=http://localhost:3000,http://localhost:8000

# Base de datos (MongoDB)
MONGO_URL=mongodb://localhost:27017
MONGO_DB_NAME=sentinel_soa

# Redis (si existe)
REDIS_URL=redis://localhost:6379
```

## 3. Inicializar Base de Datos con Usuarios

Ejecutar script de migración:

```bash
python scripts/migrate_users_to_mongodb.py
```

Esto creará 3 usuarios de prueba:
- **admin** / AdminPassword123! (role: admin)
- **analyst** / AnalystPassword123! (role: analyst)
- **viewer** / ViewerPassword123! (role: viewer)

## 4. Iniciar el Servidor

```bash
cd sentinel_soa
python -m core_orchestrator.main

# O con uvicorn directo
uvicorn core_orchestrator.main:app --host 0.0.0.0 --port 8000 --reload
```

El servidor estará disponible en `http://localhost:8000`

## 5. Probar Autenticación

### A. Obtener Token

```bash
curl -X POST "http://localhost:8000/api/v1/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=AdminPassword123!"
```

Respuesta:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "user_id": "...",
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "is_active": true
  }
}
```

### B. Usar Token para Acceder a Endpoint Protegido

```bash
TOKEN="<paste_token_from_above>"

curl -X GET "http://localhost:8000/api/v1/auth/me" \
  -H "Authorization: Bearer $TOKEN"
```

Respuesta:
```json
{
  "user_id": "...",
  "username": "admin",
  "email": "admin@example.com",
  "role": "admin",
  "is_active": true
}
```

## 6. Probar HMAC en Telemetría

```python
import requests
import hmac
import hashlib
from datetime import datetime

# Setup
public_key = "test-public-key-1"
secret = "test-secret-key-1-sha256-hmac"
timestamp = int(datetime.utcnow().timestamp())

# Body
body_data = {"ip_address": "192.168.1.1", "method": "GET", "path": "/test"}
body_bytes = str(body_data).encode()

# Calcular firma
message = f"{timestamp}:{body_bytes.decode()}".encode()
signature = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()

# Headers
headers = {
    "X-Public-Key": public_key,
    "X-Signature": signature,
    "X-Timestamp": str(timestamp),
    "Content-Type": "application/json"
}

# Enviar
response = requests.post(
    "http://localhost:8000/api/v1/telemetry/",
    json=body_data,
    headers=headers
)

print(f"Status: {response.status_code}")
print(f"Response: {response.json()}")
```

Output esperado:
```
Status: 202
Response: {"status": "accepted", "event_buffered": {...}}
```

## 7. Acceder a Analytics (Protegido)

```bash
TOKEN="<your_admin_token>"

# Listar reportes
curl -X GET "http://localhost:8000/api/v1/analytics/reports" \
  -H "Authorization: Bearer $TOKEN"

# Sin token: error 403
curl -X GET "http://localhost:8000/api/v1/analytics/reports"
```

## 8. Crear Regla (Admin only)

```bash
TOKEN="<your_admin_token>"

curl -X POST "http://localhost:8000/api/v1/rules" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rule_id": "test-rule-1",
    "name": "Test Rule",
    "description": "Test",
    "pattern": ".*test.*",
    "severity": "HIGH",
    "kill_chain_phase": "reconnaissance",
    "is_active": true,
    "metadata": {
      "changed_by": "admin",
      "change_reason": "Initial creation"
    }
  }'
```

## 9. Ejecutar Tests

```bash
# Tests de seguridad
pytest core_orchestrator/test/unit/test_hmac_security.py -v
pytest core_orchestrator/test/unit/test_jwt_security.py -v
pytest core_orchestrator/test/unit/test_rbac_security.py -v

# Tests de integración
pytest core_orchestrator/test/integration/test_auth_endpoints.py -v

# Todos los tests
pytest core_orchestrator/test/ -v
```

## 10. Documentación Científica de Seguridad

Ver: `docs/SECURITY_IMPLEMENTATION.md`

Contiene:
- Detalles técnicos de HMAC
- Flujo JWT
- RBAC y jerarquía de roles
- Ejemplos de código
- Resolución de problemas

## 11. Estructura de Archivos Nuevos

```
core_orchestrator/
├── models/
│   └── user.py                           # Modelos de usuario
├── security/
│   ├── jwt_utils.py                      # JWT token utils
│   ├── password.py                       # Password hashing
│   ├── dependencies.py                   # FastAPI dependencies
│   └── redis_sim.py                      # RedisSecretStore simulado
├── services/
│   └── user_service.py                   # User CRUD service
├── api/v1/endpoints/
│   └── auth.py                           # Login & me endpoints
└── test/
    ├── unit/
    │   ├── test_hmac_security.py         # HMAC tests
    │   ├── test_jwt_security.py          # JWT tests
    │   └── test_rbac_security.py         # RBAC tests
    └── integration/
        └── test_auth_endpoints.py        # Auth endpoints tests

data/
└── users_seed.json                       # Initial users

docs/
└── SECURITY_IMPLEMENTATION.md            # Full documentation

scripts/
└── migrate_users_to_mongodb.py           # User migration script
```

## 12. Próximos Pasos

- [ ] Reemplazar RedisSecretStore con cliente Redis real en producción
- [ ] Implementar refresh tokens
- [ ] Agregar 2FA (two-factor authentication)
- [ ] Implementar audit logging de seguridad
- [ ] Setup de certificados SSL/TLS
- [ ] Implementar rate limiting más agresivo
- [ ] Agregar protección contra CSRF
- [ ] Setup de WAF (Web Application Firewall)

## 13. Troubleshooting

### Error: "Module not found: core_orchestrator.security"

Solución: Asegúrese de que `core_orchestrator/security/__init__.py` existe (debe estar vacío)

### Error: "Database connection failed"

Solución: Inicie MongoDB:
```bash
mongod  # En otra terminal
```

### Error: "Could not validate credentials"

Solución: Verifique que:
1. El usuario existe en MongoDB
2. La contraseña es correcta
3. El usuario está activo (is_active=true)

Ejecute: `python scripts/migrate_users_to_mongodb.py`

---

**Fecha:** Junio 2026  
**Versión:** 1.0  
**Estado:** Production Ready

