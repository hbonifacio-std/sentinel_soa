# Plan de Refactorización: Reglas Heurísticas y Caché con Redis y MongoDB

**Versión:** 1.0  
**Fecha de Creación:** 2026-06-23  
**Estado:** Pendiente de Implementación  
**Responsable:** Backend Architecture Team

---

## 📋 Tabla de Contenidos

1. [Visión General](#visión-general)
2. [Problemas Actuales](#problemas-actuales)
3. [Solución Propuesta](#solución-propuesta)
4. [Arquitectura](#arquitectura)
5. [Estructura de Datos](#estructura-de-datos)
6. [Fases de Implementación](#fases-de-implementación)
7. [Plan Detallado](#plan-detallado)
8. [Estrategia de Migración](#estrategia-de-migración)
9. [Testing y Validación](#testing-y-validación)
10. [Rollback y Recuperación](#rollback-y-recuperación)
11. [Documentación API](#documentación-api)
12. [Cronograma Estimado](#cronograma-estimado)

---

## 🎯 Visión General

El sistema Sentinel SOA actualmente mantiene reglas heurísticas de detección de amenazas **hardcodeadas** en el módulo `ThreatHeuristics` (`heuristics_engine.py`). Estas reglas incluyen:

- **Diccionarios de palabras clave maliciosas** en User-Agents
- **Rutas sensibles** (admin panels, configuraciones, archivos del sistema)
- **Patrones de inyección SQL** y path traversal
- **Umbrales y puntajes** de riesgo determinísticos

### ❌ Limitaciones Actuales

1. **No parametrizables:** Los cambios requieren reimplementación y redeploy
2. **Acopladas al código:** Difícil mantener versiones o auditorías de cambios
3. **Sin caché inteligente:** Cada análisis repite búsquedas en diccionarios estáticos
4. **Sin versionamiento:** No hay forma de hacer rollback de cambios de reglas
5. **Escalabilidad limitada:** Agregar nuevas reglas requiere actualizar el código

### ✅ Solución Esperada

- **Base de datos parametrizable** (MongoDB) para todas las reglas
- **Caché inteligente** en Redis DB3 con invalidación controlada
- **API REST** para administración de reglas sin downtime
- **Versionamiento de reglas** con historial y auditoría completa
- **Compatibilidad 100%** con la arquitectura actual
- **Lógica separada e inyectable** en el motor de heurísticas

---

## 🔴 Problemas Actuales

### 1. Règles Hardcodeadas

**Archivo:** `mcp_servers/log_analysis_server/services/heuristics_engine.py`

```python
# ❌ Hardcodeado - Requiere cambio de código
MALICIOUS_UA_KEYWORDS = {
    "nikto": 30,
    "sqlmap": 35,
    # ... +46 más
}

SENSITIVE_URIS = {
    "/etc/passwd": 45,
    "/admin": 20,
    # ... +30 más
}

SQL_INJECTION_PATTERNS = [
    "' OR '1'='1",
    # ... +20 más
]
```

### 2. Análisis sin Flexibilidad

El flujo actual en `ThreatHeuristics.analyze()`:

```
Telemetría → Diccionarios Estáticos → Cálculo de Score → Reporte
             (Acoplado al código)
```

### 3. Sin Auditoría de Cambios

No hay registro de cuándo o quién cambió las reglas.

### 4. Impacto en Rendimiento

- Búsquedas lineales repetidas en listas (SQL patterns, path traversal)
- Sin índices o caché
- Escalabilidad limitada a O(n) donde n = número de patrones

---

## 💡 Solución Propuesta

### Arquitectura de 3 Capas

```
┌─────────────────────────────────────────────────────────────┐
│           CAPA DE PRESENTACIÓN (API REST)                   │
│         /api/v1/rules (GET, POST, PATCH, DELETE)            │
└────────────────────────┬────────────────────────────────────┘
                         │
┌─────────────────────────────────────────────────────────────┐
│          CAPA DE APLICACIÓN (Rules Engine)                  │
│   - Inyección de dependencias                               │
│   - Versionamiento                                          │
│   - Invalidación de caché                                   │
└────────────────┬──────────────────────────┬─────────────────┘
                 │                          │
               ┌─┴──────┐            ┌──────┴────┐
               │         │            │           │
         ┌─────▼──┐  ┌───▼────┐  ┌───▼─────┐   │
         │ Redis  │  │MongoDB │  │Fallback │   │
         │ DB 3   │  │(Source)│  │(código) │   │
         └────────┘  └────────┘  └─────────┘   │
               ▲         │                      │
               └─────────┴──────────────────────┘
               (verificación, carga inicial)
```

### Flujo Operacional

```
Solicitud de Análisis
       │
       ├─→ RulesEngine.get_active_rules()
       │      │
       │      ├─→ Verificar caché Redis DB3
       │      │   ├─ Si existe → Usar caché
       │      │   └─ Si no existe → Cargar de MongoDB
       │      │
       │      └─→ Retornar reglas en memoria
       │
       └─→ ThreatHeuristics.analyze(telemetry, rules=injected_rules)
              │
              └─→ Análisis determinístico
                  └─→ Reporte con trazabilidad de reglas

Cambio de Reglas Administrativo
       │
       ├─→ POST /api/v1/rules (validación)
       │      │
       │      ├─→ Validar esquema de reglas
       │      ├─→ Validar payload
       │      └─→ Crear versión en MongoDB
       │
       ├─→ Ejecutar tests de compatibilidad
       │      │
       │      └─→ Simular con patrones de prueba
       │
       └─→ POST /api/v1/rules/activate/{version_hash}
              │
              ├─→ Guardar versión activa en MongoDB
              ├─→ Invalidar caché Redis DB3
              └─→ Cargar nueva versión en caché
```

---

## 🏗️ Arquitectura

### Componentes Principales

#### 1. **Módulo RulesEngine** (Nuevo)
   - **Ubicación:** `core_orchestrator/services/rules_engine.py`
   - **Responsabilidad:** Cargar, cachear e inyectar reglas
   - **Dependencias:** MongoDB, Redis, Logger

#### 2. **Schemas MongoDB** (Nuevo)
   - **Colección:** `heuristic_rules`
   - **Colección:** `rule_versions`
   - **Colección:** `rule_audit_log`

#### 3. **API REST de Administración** (Nuevo)
   - **Ubicación:** `core_orchestrator/api/v1/endpoints/rules_management.py`
   - **Prefijo:** `/api/v1/rules`

#### 4. **ThreatHeuristics Refactorizado** (Modificado)
   - **Cambio:** Inyección de reglas dinámicas
   - **Ubicación:** `mcp_servers/log_analysis_server/services/heuristics_engine.py`
   - **Compatibilidad:** 100% backward compatible

#### 5. **Validador de Esquema de Reglas** (Nuevo)
   - **Ubicación:** `core_orchestrator/models/rule_schema.py`
   - **Función:** Validación de integridad de datos

---

## 📊 Estructura de Datos

### 1. Colección MongoDB: `heuristic_rules`

```json
{
  "_id": "ObjectId",
  "rule_id": "malicious_ua_keywords_v1",
  "rule_type": "keyword_mapping",           // "keyword_mapping" | "pattern_list" | "threshold"
  "category": "user_agent",                  // "user_agent" | "uri" | "injection"
  "version": 1,
  "created_at": "2026-06-23T10:00:00Z",
  "updated_at": "2026-06-23T10:00:00Z",
  "is_active": true,
  "description": "Diccionario de palabras clave maliciosas en User-Agents",
  
  // Contenido específico según tipo
  "content": {
    "type": "keyword_mapping",
    "data": {
      "nikto": 30,
      "sqlmap": 35,
      "metasploit": 30,
      // ... más keywords
    },
    "match_strategy": "substring_case_insensitive"  // substring | exact | regex
  },
  
  "metadata": {
    "source": "admin_dashboard",
    "changed_by": "security_team@company.com",
    "change_reason": "Added new scanning tools",
    "compatibility_version": "1.0.0"
  },
  
  "validation_rules": {
    "min_score": 0,
    "max_score": 100,
    "required_fields": ["rule_id", "category"]
  }
}
```

### 2. Colección MongoDB: `rule_versions`

```json
{
  "_id": "ObjectId",
  "version_hash": "v1_hash_abc123def456",
  "created_at": "2026-06-23T10:00:00Z",
  "is_active": true,
  "rules_included": [
    "malicious_ua_keywords_v1",
    "sensitive_uris_v2",
    "sql_injection_patterns_v3",
    "path_traversal_patterns_v2"
  ],
  "changelog": "Updated SQL patterns to include new blind SQL detection",
  "deployed_by": "automation_user",
  "deployment_timestamp": "2026-06-23T10:05:00Z",
  "rollback_url": "/api/v1/rules/activate/v0_hash_xyz789"
}
```

### 3. Colección MongoDB: `rule_audit_log`

```json
{
  "_id": "ObjectId",
  "timestamp": "2026-06-23T10:00:00Z",
  "action": "CREATE",                    // CREATE | UPDATE | DELETE | ACTIVATE | ROLLBACK
  "rule_id": "malicious_ua_keywords_v1",
  "user": "security_team@company.com",
  "ip_address": "192.168.1.100",
  "changes": {
    "before": { /* snapshot */ },
    "after":  { /* snapshot */ }
  },
  "reason": "Added Nuclei scanning framework detection",
  "status": "success"
}
```

### 4. Redis DB3: Cache Keys

```
# Reglas aktivas (pueden expirar, se recargan de MongoDB)
rules:active:all                    → JSON con todas las reglas activas
rules:active:malicious_ua            → JSON solo keywords
rules:active:sensitive_uris           → JSON solo URIs sensibles
rules:active:injection_patterns       → JSON patrones de inyección
rules:metadata:version_hash           → v1_hash_abc123def456
rules:metadata:last_updated           → 2026-06-23T10:00:00Z

# TTL: 24 horas (configurable)
# Estrategia: Invalidación explícita al hacer cambios
```

### 5. Modelo Pydantic: RuleSchema

```python
# core_orchestrator/models/rule_schema.py
from pydantic import BaseModel, Field, validator
from typing import Dict, List, Any, Literal
from datetime import datetime

class RuleContent(BaseModel):
    type: Literal["keyword_mapping", "pattern_list", "threshold"]
    data: Dict[str, Any]
    match_strategy: Literal["substring_case_insensitive", "exact", "regex"]

class RuleMetadata(BaseModel):
    source: str
    changed_by: str
    change_reason: str
    compatibility_version: str

class HeuristicRule(BaseModel):
    rule_id: str
    rule_type: Literal["keyword_mapping", "pattern_list", "threshold"]
    category: Literal["user_agent", "uri", "injection", "threshold"]
    version: int
    is_active: bool
    description: str
    content: RuleContent
    metadata: RuleMetadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class RuleVersion(BaseModel):
    version_hash: str
    created_at: datetime
    is_active: bool
    rules_included: List[str]
    changelog: str
    deployed_by: str
    deployment_timestamp: datetime
```

---

## 🔄 Fases de Implementación

```mermaid
Fase 1: Preparación (2-3 días)
├─ Crear schemas y modelos de datos
├─ Implementar RulesEngine
└─ Extender database.py para MongoDB

Fase 2: Refactorización de Heurísticas (3-4 días)
├─ Modificar ThreatHeuristics para inyección
├─ Crear tests de compatibilidad
└─ Validación backward-compatible

Fase 3: API de Administración (2-3 días)
├─ Implementar endpoints CRUD
├─ Validación de esquema
└─ Auditoría de cambios

Fase 4: Testing y QA (2-3 días)
├─ Tests unitarios
├─ Tests de integración
├─ Tests de rendimiento (caché)
└─ Prueba de carga

Fase 5: Migración de Datos (1-2 días)
├─ Script de migración de diccionarios actuales
├─ Validación de datos migrados
└─ Verificación de caché

Fase 6: Deploy y Documentación (1 día)
├─ Desplegar cambios en staging
├─ Documentación de API (OpenAPI)
└─ Guías de operación para administradores
```

---

## 📝 Plan Detallado

### FASE 1: Preparación (2-3 días)

#### Tarea 1.1: Crear Modelos de Datos
**Objetivo:** Definir la estructura de datos para reglas en MongoDB

**Archivos a crear:**
- `core_orchestrator/models/rule_schema.py` (300 líneas)
  - Modelos Pydantic para validación
  - Validadores personalizados
  - Generador de version_hash

**Subtareas:**
```
1.1.1 - Definir RuleContent (keyword_mapping, pattern_list, threshold)
1.1.2 - Definir HeuristicRule con todos los campos
1.1.3 - Definir RuleVersion para versionamiento
1.1.4 - Agregar validadores personalizados (rango de scores, etc)
1.1.5 - Crear función hash_version() determinística
1.1.6 - Tests unitarios de validación (100% coverage)
```

**Criterios de Aceptación:**
- ✅ Validación de score 0-100
- ✅ Validación de keywords en category
- ✅ hash_version() es determinístico
- ✅ Modelos Pydantic completos

---

#### Tarea 1.2: Extender Servicio de Base de Datos
**Objetivo:** Agregar métodos MongoDB para reglas

**Archivos a modificar:**
- `core_orchestrator/services/database.py` (+200 líneas)

**Métodos a agregar:**
```python
class Database:
    # Reglas
    async def create_rule(self, rule: HeuristicRule) -> str
    async def get_rule(self, rule_id: str) -> Optional[HeuristicRule]
    async def list_active_rules(self) -> List[HeuristicRule]
    async def update_rule(self, rule_id: str, updates: Dict) -> bool
    async def delete_rule(self, rule_id: str) -> bool
    
    # Versiones
    async def create_version(self, version: RuleVersion) -> str
    async def get_version(self, version_hash: str) -> Optional[RuleVersion]
    async def activate_version(self, version_hash: str) -> bool
    async def get_active_version(self) -> Optional[RuleVersion]
    
    # Auditoría
    async def log_rule_action(self, action: str, rule_id: str, user: str, changes: Dict) -> str
    async def get_audit_logs(self, rule_id: str, limit: int = 50) -> List[Dict]
    
    # Caché Redis
    async def cache_rules(self, rules: List[HeuristicRule], ttl_seconds: int = 86400) -> bool
    async def get_cached_rules(self) -> Optional[List[HeuristicRule]]
    async def invalidate_rules_cache(self) -> bool
```

**Subtareas:**
```
1.2.1 - Agregar métodos CRUD de reglas
1.2.2 - Agregar métodos de versionamiento
1.2.3 - Agregar métodos de auditoría
1.2.4 - Agregar métodos de caché Redis DB3
1.2.5 - Manejo de errores y conexiones
1.2.6 - Tests de integración con MongoDB/Redis
```

**Criterios de Aceptación:**
- ✅ CRUD funcional en MongoDB
- ✅ Caché correctamente en Redis DB3
- ✅ TTL correcto (24h por defecto)
- ✅ Invalidación manual funciona

---

#### Tarea 1.3: Crear RulesEngine
**Objetivo:** Motor central para gestión dinámico de reglas

**Archivo a crear:**
- `core_orchestrator/services/rules_engine.py` (400 líneas)

**Clase RulesEngine:**
```python
class RulesEngine:
    def __init__(self, db: Database, logger: Logger)
    
    async def initialize(self) -> bool
        """Carga reglas iniciales al startup"""
    
    async def get_active_rules(self) -> RulesBundle
        """Retorna bundle de reglas activas (caché o BD)"""
    
    async def reload_rules(self) -> bool
        """Recarga manuales desde MongoDB"""
    
    async def validate_rules(self, rules: List[HeuristicRule]) -> ValidationResult
        """Valida integridad de reglas"""
    
    async def get_rule_by_id(self, rule_id: str) -> Optional[HeuristicRule]
        """Obtiene regla específica"""
    
    # stats y monitoring
    async def get_rules_stats(self) -> RulesStatistics
    async def health_check(self) -> HealthStatus
```

**RulesBundle (dataclass):**
```python
@dataclass
class RulesBundle:
    malicious_ua_keywords: Dict[str, int]
    sensitive_uris: Dict[str, int]
    sql_injection_patterns: List[str]
    path_traversal_patterns: List[str]
    version_hash: str
    last_updated: datetime
```

**Subtareas:**
```
1.3.1 - Definir clase RulesEngine
1.3.2 - Implementar initialize() con fallback a diccionarios
1.3.3 - Implementar get_active_rules() con lógica caché
1.3.4 - Implementar reload_rules() para sincronización
1.3.5 - Implementar validate_rules() completo
1.3.6 - Tests unitarios y de integración
1.3.7 - Performance profiling de caché
```

**Criterios de Aceptación:**
- ✅ Cargas reglas desde MongoDB
- ✅ Cachea en Redis DB3
- ✅ Retorna RulesBundle correctamente
- ✅ Fallback a diccionarios (backward compat)
- ✅ Validación completa de datos

---

### FASE 2: Refactorización de Heurísticas (3-4 días)

#### Tarea 2.1: Refactorizar ThreatHeuristics
**Objetivo:** Adaptable para recibir reglas dinámicas

**Archivos a modificar:**
- `mcp_servers/log_analysis_server/services/heuristics_engine.py` (±100 líneas)

**Cambios principales:**
```python
# ❌ ANTES
class ThreatHeuristics:
    MALICIOUS_UA_KEYWORDS = { ... }  # Hardcodeado
    SENSITIVE_URIS = { ... }
    SQL_INJECTION_PATTERNS = [ ... ]
    
    @staticmethod
    def analyze(telemetry: WebActivityWindowInput) -> Tuple[int, List[str], str]:
        # Usa directamente los diccionarios
        ...

# ✅ DESPUÉS
class ThreatHeuristics:
    def __init__(self, rules_bundle: RulesBundle = None):
        # Inyección de dependencia
        self.rules = rules_bundle or self._get_default_rules()
    
    @staticmethod
    def analyze(
        telemetry: WebActivityWindowInput,
        rules_bundle: RulesBundle = None
    ) -> Tuple[int, List[str], str]:
        # Usa reglas inyectadas o por defecto
        ...
    
    @staticmethod
    def _get_default_rules() -> RulesBundle:
        # Fallback a diccionarios hardcodeados
        return RulesBundle(
            malicious_ua_keywords={ ... },
            sensitive_uris={ ... },
            # ...
        )
```

**Subtareas:**
```
2.1.1 - Refactorizar analyze() para aceptar rules_bundle
2.1.2 - Refactorizar _analyze_user_agents() para usar rules inyectadas
2.1.3 - Refactorizar _analyze_sensitive_uris()
2.1.4 - Refactorizar _analyze_injection_patterns()
2.1.5 - Mantener diccionarios como fallback
2.1.6 - Garantizar compatibilidad 100% de output
2.1.7 - Tests comparativo (antes vs después con mismas reglas)
```

**Criterios de Aceptación:**
- ✅ Acepta rules_bundle como parámetro opcional
- ✅ Output idéntico con mismas reglas
- ✅ Fallback funciona
- ✅ Inyección de reglas bien documentada

---

#### Tarea 2.2: Criar Punto de Inyección en execute_analyze_web_activity
**Objetivo:** Conectar RulesEngine en la cadena de análisis

**Archivos a modificar:**
- `mcp_servers/log_analysis_server/tools/analyze_activity.py` (±50 líneas)

**Cambio:**
```python
# Obtener engine de reglas desde contexto global o inyección
rules_engine = get_rules_engine()  # Global o inyección
rules_bundle = await rules_engine.get_active_rules()

# Pasar a heurísticas
threat_score, indicators, reasoning = ThreatHeuristics.analyze(
    telemetry,
    rules_bundle=rules_bundle
)
```

**Subtareas:**
```
2.2.1 - Crear singleton o contexto para RulesEngine
2.2.2 - Modificar execute_analyze_web_activity()
2.2.3 - Manejo de errores (RulesEngine caído)
2.2.4 - Fallback a reglas por defecto
2.2.5 - Logging de qué versión de reglas se usó
2.2.6 - Tests de integración end-to-end
```

**Criterios de Aceptación:**
- ✅ Llama RulesEngine en análisis
- ✅ Logs incluyen version_hash de reglas
- ✅ Fallback automático funciona
- ✅ Sin latencia significativa

---

#### Tarea 2.3: Tests de Compatibilidad
**Objetivo:** Garantizar 100% compatibilidad backward

**Archivos a crear:**
- `core_orchestrator/test/unit/test_heuristics_migration.py` (500+ líneas)

**Test cases:**
```python
def test_heuristics_output_identical_with_default_rules()
def test_heuristics_with_custom_rules_bundle()
def test_heuristics_fallback_no_rules_bundle()
def test_rules_injection_scoring_unchanged()
def test_ua_analysis_with_db_rules()
def test_uri_analysis_with_db_rules()
def test_injection_pattern_detection_consistency()
def test_performance_with_injected_rules()
def test_version_hash_tracking()
```

**Criterios de Aceptación:**
- ✅ 100% de tests pasan
- ✅ Output idéntico con reglas por defecto
- ✅ Rendimiento dentro de 5% vs. original

---

### FASE 3: API de Administración de Reglas (2-3 días)

#### Tarea 3.1: Crear Endpoints REST
**Objetivo:** API completa para CRUD de reglas

**Archivo a crear:**
- `core_orchestrator/api/v1/endpoints/rules_management.py` (500+ líneas)

**Endpoints:**

```
GET /api/v1/rules
  Descripción: Listar todas las reglas activas
  Response: { rules: [HeuristicRule], version_hash: str }

GET /api/v1/rules/{rule_id}
  Descripción: Obtener regla específica
  Response: HeuristicRule

POST /api/v1/rules
  Descripción: Crear nueva regla
  Body: HeuristicRule
  Response: { rule_id: str, message: str }

PATCH /api/v1/rules/{rule_id}
  Descripción: Actualizar regla existente
  Body: { updates... }
  Response: { message: str, updated_at: datetime }

DELETE /api/v1/rules/{rule_id}
  Descripción: Marcar regla como inactiva
  Response: { message: str }

GET /api/v1/rules/versions
  Descripción: Listar historial de versiones
  Response: [RuleVersion]

GET /api/v1/rules/versions/{version_hash}
  Descripción: Obtener versión específica
  Response: RuleVersion

POST /api/v1/rules/versions/activate/{version_hash}
  Descripción: Activar versión específica
  Response: { message: str, active_version: str }

GET /api/v1/rules/audit-log
  Descripción: Obtener log de auditoría
  Queryparams: rule_id, limit, offset
  Response: [AuditLog]

POST /api/v1/rules/validate
  Descripción: Validar reglas sin guardar
  Body: HeuristicRule[]
  Response: { valid: bool, errors: [str] }

GET /api/v1/rules/health
  Descripción: Estado del engine de reglas
  Response: { status: str, cached: bool, last_updated: datetime }
```

**Subtareas:**
```
3.1.1 - Implementar GET /api/v1/rules
3.1.2 - Implementar POST /api/v1/rules (con validación)
3.1.3 - Implementar PATCH /api/v1/rules/{rule_id}
3.1.4 - Implementar DELETE /api/v1/rules/{rule_id}
3.1.5 - Implementar endpoints de versiones
3.1.6 - Implementar POST /api/v1/rules/versions/activate/{version_hash}
3.1.7 - Implementar endpoints de auditoría
3.1.8 - Implementar POST /api/v1/rules/validate
3.1.9 - Implementar GET /api/v1/rules/health
3.1.10 - Rate limiting y autenticación
3.1.11 - Documentación OpenAPI/Swagger
```

**Criterios de Aceptación:**
- ✅ Todos los endpoints funcionales
- ✅ Validación completa de entrada
- ✅ Errores bien documentados
- ✅ Rate limiting configurado
- ✅ OpenAPI spec generado

---

#### Tarea 3.2: Sistema de Validación
**Objetivo:** Validar reglas antes de guardar

**Archivo a crear:**
- `core_orchestrator/services/rule_validator.py` (200+ líneas)

**Validaciones:**
```python
class RuleValidator:
    @staticmethod
    def validate_rule(rule: HeuristicRule) -> ValidationResult:
        # Validar esquema (Pydantic lo hace)
        # Validar scores 0-100
        # Validar no duplicados
        # Validar referencias a categories válidas
        # Validar patterns compilables (si regex)
        # Validar longitud de keywords
        pass
    
    @staticmethod
    def validate_rule_bundle(bundle: RulesBundle) -> ValidationResult:
        # Validar compatibilidad entre reglas
        # Validar no hay conflictos
        pass
    
    @staticmethod
    def test_rules_with_patterns(rules: List[HeuristicRule]) -> TestResult:
        # Ejecutar con payloads de test conocidos
        # Verificar detecciones esperadas
        pass
```

**Subtareas:**
```
3.2.1 - Crear RuleValidator con validaciones básicas
3.2.2 - Validaciones de rango y tipo
3.2.3 - Validaciones de compatibilidad
3.2.4 - Sistema de test patterns predefinidos
3.2.5 - Ejecutar tests antes de activar versión
3.2.6 - Tests unitarios del validador
```

**Criterios de Aceptación:**
- ✅ Rechaza scores fuera de rango
- ✅ Rechaza duplicados
- ✅ Permite crear versiones solo si pasan tests
- ✅ Valida patterns regex si aplica

---

#### Tarea 3.3: Auditoría y Logging
**Objetivo:** Registrar todos los cambios de reglas

**Archivo a modificar:**
- `core_orchestrator/services/database.py` (+50 líneas para auditoría)

**Cambios:**
```python
async def log_rule_action(
    self,
    action: str,              # CREATE, UPDATE, DELETE, ACTIVATE
    rule_id: str,
    user: str,
    changes: Dict[str, Any],   # before/after
    reason: str = "",
    status: str = "success"
) -> str:
    # Crear documento en collection rule_audit_log
    # Incluir timestamp, user, IP, cambios detallados
    pass
```

**Subtareas:**
```
3.3.1 - Agregar logging a create_rule()
3.3.2 - Agregar logging a update_rule()
3.3.3 - Agregar logging a delete_rule()
3.3.4 - Agregar logging a activate_version()
3.3.5 - Endpoint GET /api/v1/rules/audit-log
3.3.6 - Filtrado por rule_id, usuario, fecha
3.3.7 - Tests de auditoría
```

**Criterios de Aceptación:**
- ✅ Todos los cambios registrados
- ✅ Con before/after snapshot
- ✅ Con usuario y timestamp
- ✅ API de auditoría funcional

---

### FASE 4: Testing y QA (2-3 días)

#### Tarea 4.1: Tests Unitarios
**Objetivo:** Coverage completo de componentes

**Archivos a crear:**
- `core_orchestrator/test/unit/test_rules_engine.py` (400+ líneas)
- `core_orchestrator/test/unit/test_rule_validator.py` (300+ líneas)
- Ampliación de `test_heuristics.py`

**Coverage Target:** 95%+

**Subtareas:**
```
4.1.1 - Tests de RulesEngine (cargar, cachear, recargar)
4.1.2 - Tests de RuleValidator (validación completa)
4.1.3 - Tests de ThreatHeuristics refactorizado
4.1.4 - Tests de inyección de dependencias
4.1.5 - Tests de fallback
4.1.6 - Tests de error handling
4.1.7 - Tests de concurrencia
```

---

#### Tarea 4.2: Tests de Integración
**Objetivo:** Flujos end-to-end

**Archivos a crear:**
- `core_orchestrator/test/integration/test_rules_api_e2e.py` (400+ líneas)

**Scenarios:**
```
E2E 1: Create rule → Validate → Activate → Use in analysis
E2E 2: Update rule → Validate new rules → Activate new version
E2E 3: Rollback to previous version
E2E 4: Cache invalidation after version change
E2E 5: Audit log tracking for all operations
E2E 6: Concurrent rule updates (race condition tests)
E2E 7: Database failure → Fallback to hardcoded rules
E2E 8: Redis cache miss → Reload from MongoDB
```

**Subtareas:**
```
4.2.1 - Implementar E2E 1-8
4.2.2 - Fixtures para datos de test
4.2.3 - Cleanup después de cada test
4.2.4 - Tests en ambiente aislado (Docker Compose)
```

---

#### Tarea 4.3: Tests de Rendimiento
**Objetivo:** Benchmarking caché vs. sin caché

**Archivo a crear:**
- `core_orchestrator/test/performance/test_rules_performance.py` (200+ líneas)

**Benchmarks:**
```
Benchmark 1: Cargar reglas sin caché (desde MongoDB)
  Target: < 100ms para 200 reglas

Benchmark 2: Cargar reglas con caché (desde Redis)
  Target: < 5ms para 200 reglas

Benchmark 3: ThreatHeuristics.analyze() sin cambios
  Target: Rendimiento idéntico (± 2%)

Benchmark 4: Análisis con bundle inyectado vs. diccionarios
  Target: < 1% diferencia

Benchmark 5: Concurrencia (100 análisis simultáneos)
  Target: < 5% degradación
```

**Subtareas:**
```
4.3.1 - Implementar fixtures de carga
4.3.2 - Benchmark cargas sin caché
4.3.3 - Benchmark cargas con caché
4.3.4 - Benchmark análisis
4.3.5 - Benchmark bajo concurrencia
4.3.6 - Reportes y comparativas
```

---

#### Tarea 4.4: Prueba de Carga
**Objetivo:** Validar bajo alta concurrencia

**Herramientas:** Apache JMeter o K6

**Scenarios:**
```
Load Test 1: 100 req/s durante 5min al endpoint analizar
Load Test 2: 50 cambios de reglas simultáneos
Load Test 3: 1000 análisis concurrentes con caché
Load Test 4: MongoDB + Redis failover
```

---

### FASE 5: Migración de Datos (1-2 días)

#### Tarea 5.1: Script de Migración
**Objetivo:** Convertir diccionarios actuales a MongoDB

**Archivo a crear:**
- `scripts/migrate_rules_to_mongodb.py` (300+ líneas)

**Proceso:**
```
1. Exportar diccionarios actuales de heuristics_engine.py
2. Validar cada diccionario
3. Crear documentos MongoDB con versión inicial
4. Asignar IDs y hashes
5. Crear entrada en rule_versions
6. Marcar como activa
7. Verificar auditoría
8. Reporte de migración
```

**Subtareas:**
```
5.1.1 - Crear script dass lee hardcodes
5.1.2 - Transformar a HeuristicRule objects
5.1.3 - Insertar en MongoDB
5.1.4 - Crear versión inicial
5.1.5 - Cargar en Redis caché
5.1.6 - Validar migración
5.1.7 - Generar reporte
```

**Criterios de Aceptación:**
- ✅ Todos los diccionarios migrados
- ✅ Con version_hash correcto
- ✅ En caché Redis DB3
- ✅ Auditoría registrada

---

#### Tarea 5.2: Validación Post-Migración
**Objetivo:** Verificar integridad de datos

**Checklist:**
```
□ Comparar scoring con reglas originales
□ Ejecutar análisis con payloads de test
□ Verificar resultados idénticos
□ Corroborar caché en Redis DB3
□ Reporte de auditoría limpio
□ Sin datos duplicados en MongoDB
□ Todas las categorías presentes
```

---

### FASE 6: Deploy y Documentación (1 día)

#### Tarea 6.1: Documentación API (OpenAPI 3.0)
**Archivos a crear:**
- `docs/api/rules_management.openapi.yaml` (200+ líneas)
- `docs/api/rules_management.md` (500+ líneas)

**Contenido:**
```
- Descripción de endpoints
- Ejemplos de request/response
- Códigos de error
- Rate limits
- Validaciones
- Casos de uso comunes
```

---

#### Tarea 6.2: Guía de Operación
**Archivos a crear:**
- `docs/operations/rules_administration_guide.md` (1000+ líneas)

**Secciones:**
```
1. Introducción y conceptos
2. Crear nueva regla (paso a paso)
3. Actualizar regla existente
4. Crear nueva versión
5. Activar versión
6. Rollback
7. Monitoreo y salud
8. Troubleshooting
9. FAQ
10. Mejores prácticas
```

---

#### Tarea 6.3: Deployment en Staging
**Pasos:**
```
1. Backup de MongoDB (colecciones existentes)
2. Deploy código actualizado
3. Ejecutar script de migración
4. Validar todos los tests (unit + integration)
5. Pruebas de carga
6. Approval para production
```

---

## 🔄 Estrategia de Migración

### Enfoque: Gradual y Reversible

```
Semana 1: Fase 1-2 (Preparación + Refactorización)
├─ Desarrollo en featura branch
├─ Code review
└─ Tests en ambiente dev

Semana 2: Fase 3-4 (API + Testing)
├─ Merge a develop
├─ Tests en staging
├─ QA completo
└─ Performance testing

Semana 3: Fase 5-6 (Migración + Deploy)
├─ Migración de datos en staging
├─ Validación exhaustiva
├─ Deploy a production (horario bajo tráfico)
├─ Monitoreo 24/7 iniciales
└─ Documentación final
```

### Estrategia de Rollback

```
Si hay problemas en production:

OPCIÓN 1: Rollback de código (< 1 minuto)
  1. Revert commit en git
  2. ThreatHeuristics.analyze() usa fallback a diccionarios
  3. Sistema operativo con reglas por defecto

OPCIÓN 2: Rollback de versión de reglas (< 30 segundos)
  1. POST /api/v1/rules/versions/activate/{version_anterior_hash}
  2. Caché se invalida automáticamente
  3. Nueva versión se carga desde MongoDB
  4. Sistema usa reglas anteriores
```

---

## ✅ Testing y Validación

### Test Strategy Matrix

| Componente | Unitario | Integración | Carga | Performance |
|-----------|----------|------------|-------|------------|
| RulesEngine | ✅ | ✅ | ✅ | ✅ |
| RuleValidator | ✅ | ✅ | - | - |
| API Endpoints | ✅ | ✅ | ✅ | ✅ |
| ThreatHeuristics | ✅ | ✅ | ✅ | ✅ |
| Migración | ✅ | ✅ | - | - |
| Caché Redis | ✅ | ✅ | ✅ | ✅ |

### Criterios de Terminación

```
✅ Unit test coverage > 95%
✅ Todos los E2E tests pasan
✅ Performance tests < 5% degradación
✅ Carga test exitosa (100 req/s)
✅ Migration validation exitosa
✅ Backward compatibility verified
✅ Documentation completa
✅ Approval de stakeholders
```

---

## 🔙 Rollback y Recuperación

### Plan de Rollback de Código

**Tiempo estimado:** < 1 minuto

```bash
# 1. Revert commit
git revert <commit_hash>
git push production

# 2. Verificar
curl http://api.sentinel.local/health
curl http://api.sentinel.local/api/v1/telemetry/status

# 3. ThreatHeuristics usa automáticamente fallback a diccionarios
# Sistema operativo sin cambios en comportamiento
```

### Plan de Rollback de Versión de Reglas

**Tiempo estimado:** < 30 segundos

```bash
# 1. Obtener versión anterior
curl http://api.sentinel.local/api/v1/rules/versions

# 2. Activar versión anterior
curl -X POST http://api.sentinel.local/api/v1/rules/versions/activate/{prev_version_hash}

# 3. Verificar caché invalidado
curl http://api.sentinel.local/api/v1/rules/health

# 4. Ver cambios en auditoría
curl http://api.sentinel.local/api/v1/rules/audit-log
```

### Monitoreo Post-Deploy

```
Métricas a monitorear (primeras 24h):
- Latencia de /api/v1/telemetry/analyze (< 100ms)
- Cache hit rate en Redis (> 99%)
- Error rate en API de reglas (< 0.1%)
- Memory usage MongoDB (+5-10% esperado)
- Redis DB3 size (< 50MB)
- Tiempo de activación de versión (< 500ms)
```

---

## 📖 Documentación API

### Resumen de Endpoints

```
LECTURA
GET /api/v1/rules
GET /api/v1/rules/{rule_id}
GET /api/v1/rules/versions
GET /api/v1/rules/versions/{version_hash}
GET /api/v1/rules/audit-log
GET /api/v1/rules/health

ESCRITURA
POST /api/v1/rules (crear)
PATCH /api/v1/rules/{rule_id} (actualizar)
DELETE /api/v1/rules/{rule_id} (desactivar)
POST /api/v1/rules/validate (validar sin guardar)
POST /api/v1/rules/versions/activate/{version_hash} (activar)
```

### Ejemplo: Crear Regla

```bash
POST /api/v1/rules
Content-Type: application/json
Authorization: Bearer <token>

{
  "rule_id": "suspicious_ua_tokens_v4",
  "rule_type": "keyword_mapping",
  "category": "user_agent",
  "version": 4,
  "is_active": true,
  "description": "Detect suspicious token patterns in User-Agent",
  "content": {
    "type": "keyword_mapping",
    "data": {
      "gobuster": 22,
      "masscan": 20,
      "nikto": 30
    },
    "match_strategy": "substring_case_insensitive"
  },
  "metadata": {
    "source": "admin_dashboard",
    "changed_by": "security@company.com",
    "change_reason": "Added gobuster and masscan detection",
    "compatibility_version": "1.0.0"
  }
}

Response 201 Created:
{
  "rule_id": "suspicious_ua_tokens_v4",
  "message": "Rule created successfully",
  "version_hash": "v4_hash_xyz789abc",
  "created_at": "2026-06-23T10:00:00Z"
}
```

### Ejemplo: Activar Nueva Versión

```bash
POST /api/v1/rules/versions/activate/v4_hash_xyz789abc
Authorization: Bearer <token>

Response 200 OK:
{
  "message": "Version activated successfully",
  "active_version": "v4_hash_xyz789abc",
  "deployed_at": "2026-06-23T10:05:00Z",
  "rules_included": [
    "malicious_ua_keywords_v4",
    "sensitive_uris_v2",
    "sql_injection_patterns_v3"
  ]
}
```

---

## ⏲️ Cronograma Estimado

### Timeline Detallado

```
SEMANA 1 (6-10 de julio)
├─ Lunes-Martes: Fase 1 (Modelos, Database)
│   ├─ 1.1: Crear RuleSchema (6h)
│   └─ 1.2: Extender Database (8h)
├─ Miércoles-Jueves: Fase 1-2 (RulesEngine)
│   ├─ 1.3: Crear RulesEngine (8h)
│   └─ 2.1: Refactorizar ThreatHeuristics (8h)
└─ Viernes: Code review + Tests iniciales (4h)
  Total Semana 1: 34h

SEMANA 2 (13-17 de julio)
├─ Lunes-Martes: Fase 2-3 (Inyección + API)
│   ├─ 2.2: Punto de inyección (6h)
│   └─ 3.1: Endpoints API (12h)
├─ Miércoles: Fase 3-4 (Validador + Tests)
│   ├─ 3.2: RuleValidator (8h)
│   └─ 4.1: Unit tests (8h)
├─ Jueves-Viernes: Fase 4 (Integration tests)
│   ├─ 4.2: E2E tests (12h)
│   └─ 4.3: Performance tests (6h)
  Total Semana 2: 52h

SEMANA 3 (20-24 de julio)
├─ Lunes-Martes: Fase 5 (Migración)
│   ├─ 5.1: Script migración (8h)
│   └─ 5.2: Validación (6h)
├─ Miércoles-Jueves: Fase 6 (Documentación)
│   ├─ 6.1: OpenAPI spec (6h)
│   ├─ 6.2: Operation guide (12h)
│   └─ 6.3: Deploy staging (4h)
└─ Viernes: Testing final + Approval (8h)
  Total Semana 3: 44h

SEMANA 4 (27-31 de julio)
├─ Lunes-Martes: Validación final en staging
├─ Miércoles: Deploy a production (horario bajo tráfico)
├─ Jueves-Viernes: Monitoreo y soporte
  Total Semana 4: 32h

TOTAL ESTIMADO: ~160 horas (4 semanas, 1 desarrollador full-time)
```

### Hitos Principales

```
Hito 1 (EOD Semana 1): Modelos + Database + RulesEngine listos
  ✅ Criterio: Unit tests > 80%

Hito 2 (EOD Semana 1 Viernes): ThreatHeuristics refactorizado
  ✅ Criterio: Tests de compatibilidad pasan

Hito 3 (Mid Semana 2): API completa + Validador
  ✅ Criterio: Todos los endpoints funcionales

Hito 4 (EOD Semana 2): QA completado
  ✅ Criterio: E2E tests + Performance tests pasan

Hito 5 (Mid Semana 3): Migración exitosa en staging
  ✅ Criterio: Datos migrados + Auditoría limpia

Hito 6 (EOD Semana 3): Documentación completa + Approval
  ✅ Criterio: Stakeholders aprobar

Hito 7 (Semana 4): Deploy a production
  ✅ Criterio: 99.9% uptime, cero incidentes
```

---

## 📚 Recursos Adicionales

### Herramientas Recomendadas

```
Development:
- Python 3.11+
- FastAPI 0.108+
- Pydantic 2.0+
- motor (async MongoDB driver)
- redis-py o aioredis

Testing:
- pytest
- pytest-asyncio
- pytest-cov
- pytest-benchmark

Monitoring:
- Newrelic / DataDog
- MongoDB Atlas (monitores)
- Redis Sentinel (para HA)

CI/CD:
- GitHub Actions / GitLab CI
- Docker para tests
```

### Referencias

```
- MITRE ATT&CK Framework: https://attack.mitre.org/
- MongoDB Best Practices: https://docs.mongodb.com/
- Redis Caching Patterns: https://redis.io/
- FastAPI Documentation: https://fastapi.tiangolo.com/
- Pydantic Validation: https://docs.pydantic.dev/
```

---

## 🤝 Responsabilidades por Rol

### Arquitecto/Tech Lead
- ✅ Validar diseño pre-implementación
- ✅ Code reviews
- ✅ Decisiones de trade-offs
- ✅ Escalabilidad y performance

### Desarrollador Backend
- ✅ Implementar todas las fases
- ✅ Escribir tests
- ✅ Integration testing
- ✅ Documentación técnica

### QA/Tester
- ✅ Testing exhaustivo
- ✅ Load testing
- ✅ Compatibility testing
- ✅ Documentación de bugs

### DevOps/Platform
- ✅ Infraestructura MongoDB/Redis
- ✅ Monitoring y alertas
- ✅ Deployment/Rollback procedures
- ✅ Backup y recuperación

### Seguridad
- ✅ Validación de autenticación API
- ✅ Rate limiting
- ✅ Audit log review
- ✅ Cambios en production

---

## 🎯 Conclusión

Este plan proporciona una hoja de ruta clara para refactorizar el sistema de reglas heurísticas de Sentinel SOA, moviendo de diccionarios hardcodeados a una arquitectura parametrizable basada en MongoDB + Redis.

### Beneficios Clave

```
✅ Reglas sin redeploy (cambio dinámico)
✅ Auditoría completa (rastreabilidad 100%)
✅ Caché inteligente (5-10x más rápido)
✅ Versionamiento (rollback fácil)
✅ Escalable (miles de reglas)
✅ Mantenible (lógica separada)
✅ Backward compatible (sin breaking changes)
✅ Well-tested (>95% coverage)
```

### Próximos Pasos

1. ✅ **Aprobación del plan** (stakeholders)
2. ✅ **Asignación de recursos** (equipo)
3. ✅ **Creación de epics** (project management)
4. ✅ **Setup de ambiente** (dev + staging)
5. ✅ **Inicio Fase 1** (semana siguiente)

---

**Documento preparado por:** GitHub Copilot  
**Última actualización:** 2026-06-23  
**Versión:** 1.0

