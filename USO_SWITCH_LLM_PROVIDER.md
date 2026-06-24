# switch_llm_provider.py - Análisis de Uso

## 🎯 ¿Qué es?

Un script **auxiliar/opcional** para cambiar el proveedor LLM de forma más fácil.

## ❓ ¿Se llama automáticamente en el flujo?

**NO.** Está completamente desacoplado del flujo de ejecución. Es solo una **herramienta de administración**.

---

## 🔄 Flujo Real De Selección De Proveedor

```
┌─────────────────────────────────────────────────────────────┐
│                    FLUJO AUTOMÁTICO                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Sistema inicia (Docker o local)                         │
│     ↓                                                        │
│  2. Lee archivo .env (LLM_PROVIDER=gemini)                 │
│     ↓                                                        │
│  3. core_orchestrator/config.py ←─────────────────────┐    │
│     - Parse LLM_PROVIDER                             │    │
│     - Valida (debe ser gemini|ollama|openai|groq)    │    │
│     ↓                                                        │
│  4. MCP Server hereda via environment variables             │
│     (OrchestratorSettings.llm_provider → environ)           │
│     ↓                                                        │
│  5. LogAnalysisServerSettings (config.py del MCP)           │
│     - Lee LLM_PROVIDER del environment                      │
│     ↓                                                        │
│  6. LLMAnalyzer._get_provider()                             │
│     ↓                                                        │
│  7. create_llm_provider(provider_name, config)              │
│     ↓                                                        │
│  8. Factory router:                                         │
│     if provider == "gemini" → GeminiProvider ✅ ACTUAL     │
│     if provider == "openai" → OpenAIProvider               │
│     if provider == "groq"   → GroqProvider                 │
│     if provider == "ollama" → OllamaProvider               │
│     ↓                                                        │
│  9. Análisis de telemetría con proveedor seleccionado      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 🛠️ Herramienta Auxiliar (Manual/Opcional)

```
┌─────────────────────────────────────────────────────────────┐
│          HERRAMIENTA DE ADMINISTRACIÓN (MANUAL)             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  python switch_llm_provider.py                              │
│     ↓                                                        │
│  get_current_provider()                                     │
│  └─→ Lee .env y retorna proveedor actual                   │
│     ↓                                                        │
│  change_provider("openai")                                  │
│  └─→ Modifica .env: LLM_PROVIDER=openai                    │
│     ↓                                                        │
│  Requiere RESTART del servicio                              │
│  └─→ docker-compose restart  O  python main.py             │
│     ↓ (entonces vuelve al flujo automático arriba)          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 💡 Uso Práctico

### Escenario 1: Cambio Manual (RECOMENDADO)
```bash
# Opción A: Editar directamente .env
vi .env
# Cambiar: LLM_PROVIDER=gemini → LLM_PROVIDER=openai

# Opción B: Usar el script
python switch_llm_provider.py
# Leer el script y ejecutar:
# change_provider("openai")

# Luego reiniciar
docker-compose down
docker-compose up -d
```

### Escenario 2: Desde Python
```python
from switch_llm_provider import change_provider, get_current_provider

# Ver actual
print(get_current_provider())  # "gemini"

# Cambiar
change_provider("groq")

# Reiniciar aplicación...
```

### Escenario 3: Desde Bash Automation
```bash
#!/bin/bash
# cambiar_proveedor.sh

PROVEEDOR=${1:-"openai"}  # por defecto cambiar a openai

cd /path/to/sentinel_soa
python -c "from switch_llm_provider import change_provider; change_provider('$PROVEEDOR')"

# Reiniciar
docker-compose restart core_orchestrator
docker-compose restart mcp_server

echo "Proveedor cambiado a: $PROVEEDOR"
```

---

## 🔍 Comparativa: Manual vs Automático

| Aspecto | Manual (.env) | Script | Flujo Automático |
|---------|---|---|---|
| Requiere llamada en código | ❌ No | ✅ Si | ❌ No |
| Se ejecuta automáticamente | ❌ No | ❌ No | ✅ Si |
| Momento de ejecución | Init o cambio manual | Cuando ejecutas script | Cada inicio |
| Requiere reinicio | ✅ Si | ✅ Si | ✅ Si |
| Controlado por | Variables entorno | Python script | Core Orchestrator |

---

## 📌 Casos de Uso del Script

### ✅ USAR `switch_llm_provider.py` CUANDO:
1. Necesitas **cambiar proveedores frecuentemente** en desarrollo
2. Quieres **automatizar cambios** en CI/CD
3. Necesitas **una herramienta de administración**
4. Desarrollas **scripts de testing** que prueban múltiples providers

### ❌ NO NECESITAS si:
1. Cambias el proveedor una sola vez
2. Lo configuras manualmente en `.env`
3. Solo necesitas que funcione normalmente

---

## 🚀 Recomendación

### Para desarrolladores/testing:
```bash
#!/bin/bash
# test_all_providers.sh
for provider in ollama gemini openai groq; do
  echo "Testing $provider..."
  python -c "from switch_llm_provider import change_provider; change_provider('$provider')"
  docker-compose restart
  sleep 5
  # run tests...
done
```

### Para producción:
```bash
# Solo editar .env una vez al deplegar
LLM_PROVIDER=gemini  # O el que necesites
# Luego olvidarse del script
```

---

## 🎓 Lecciones sobre Patrones

Este script demuestra dos patrones importantes:

### 1. **Factory Pattern (Automático)**
```python
# En analyze_activity.py - se ejecuta automáticamente
provider = create_llm_provider(settings.llm_provider, config)
```

### 2. **Configuration Management Pattern (Manual)**
```python
# En switch_llm_provider.py - herramienta auxiliar
def change_provider(name):
    # Modifica configuración
    pass
```

El **flujo automático** (Factory) es lo importante.  
El script es solo una **conveniencia administrativa**.

---

## 📊 Diagrama Decisional

```
¿Necesito cambiar proveedor?
    │
    ├─→ Una sola vez
    │   └─→ Edita .env directamente ✅ MEJOR
    │
    ├─→ Frecuentemente en desarrollo
    │   └─→ Usa switch_llm_provider.py 📚
    │
    └─→ En automatización/CI-CD
        └─→ Integra el script en pipeline
```

---

## Conclusión

| Componente | Propósito | Automático | Necesario |
|-----------|-----------|-----------|----------|
| `.env` | Configuración persistente | ✅ Automático | ✅ Sí |
| `core_orchestrator/config.py` | Parse de variables | ✅ Automático | ✅ Sí |
| `create_llm_provider()` | Instanciación de provider | ✅ Automático | ✅ Sí |
| `switch_llm_provider.py` | **Herramienta auxiliar** | ❌ Manual | ❌ No (opcional) |

**El script NO es parte del flujo crítico. Es una utilidad para administración.**

