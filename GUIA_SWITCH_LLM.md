# 📖 Guía Completa: switch_llm_provider.py

## 🎯 Propósito

Es una **herramienta auxiliar de administración** para cambiar entre proveedores LLM de forma fácil y segura.

**NO se ejecuta automáticamente** en el flujo normal de la aplicación.

---

## 📋 Comparativa: Flujo Automático vs Script

```
┌─────────────────────────────────────────────────────────────┐
│                  FLUJO AUTOMÁTICO                           │
│              (Se ejecuta siempre)                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  .env (LLM_PROVIDER=gemini)                                 │
│    ↓ (Se lee automáticamente)                              │
│  core_orchestrator/config.py                                │
│    ↓ (Se valida automáticamente)                           │
│  MCP Server config.py                                       │
│    ↓ (Se hereda automáticamente)                           │
│  create_llm_provider() factory                              │
│    ↓ (Elige proveedor automáticamente)                     │
│  GeminiProvider / OpenAIProvider / GroqProvider            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────┐
│         HERRAMIENTA AUXILIAR (MANUAL - Este Script)        │
│            (Solo cuando lo ejecutas)                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  python switch_llm_provider.py openai                       │
│        ↓                                                     │
│     MODIFICA .env (LLM_PROVIDER=openai)                    │
│        ↓                                                     │
│     REQUIERE REINICIO                                       │
│        ↓ (luego el flujo automático arriba se ejecuta)      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Uso

### 1️⃣ Modo Línea de Comandos (Rápido)

```bash
# Ver proveedor actual
python switch_llm_provider.py
# Output: 👉 Gemini es ACTUAL

# Cambiar a OpenAI
python switch_llm_provider.py openai
# Output: 
# ✅ Proveedor cambiado exitosamente!
# Anterior: gemini
# Nuevo:    openai
# 
# ⚠️  RECORDAR: Se requiere reiniciar los servicios:
#    docker-compose restart

# Cambiar a GROQ
python switch_llm_provider.py groq

# Cambiar a Ollama
python switch_llm_provider.py ollama
```

### 2️⃣ Modo Interactivo (Menú)

```bash
python switch_llm_provider.py
# Output:
# ============================================================
# 🛠️  GESTOR DE PROVEEDORES LLM
# ============================================================
#
# 📍 Proveedor actual: GEMINI
#
# 📋 Proveedores LLM Disponibles:
#
# 👉 [1] OLLAMA
#    Descripción: LLM local sin costo
#    Modelo:      mistral (local)
#    Velocidad:   ⚡ Rápido
#    Costo:       💰 Gratis
#    Calidad:     ⭐ Media
#    ← ACTUAL
#
# [2] GEMINI
#    Descripción: Google Gemini (actual)
#    Modelo:      gemini-3.5-flash
#    Velocidad:   ⚡⚡ Muy rápido
#    Costo:       💰 Bajo
#    Calidad:     ⭐⭐⭐⭐ Excelente
#
# [3] OPENAI
#    Descripción: OpenAI (NEW)
#    Modelo:      gpt-4o-mini
#    Velocidad:   ⚡⚡ Muy rápido
#    Costo:       💰💰 Moderado
#    Calidad:     ⭐⭐⭐⭐⭐ Excelente
#
# [4] GROQ
#    Descripción: GROQ (NEW - Ultra rápido)
#    Modelo:      mixtral-8x7b-32768
#    Velocidad:   ⚡⚡⚡ Ultra rápido
#    Costo:       💰 Gratis
#    Calidad:     ⭐⭐⭐⭐ Muy bueno
#
# ============================================================
# Selecciona una opción:
#   1-4  → Cambiar a ese proveedor
#   l    → Listar todos
#   q    → Salir
# ============================================================
#
# ¿Opción? 3
# ¿Cambiar a OPENAI? (s/n) s
# ✅ Cambio completado
```

---

## 📚 Ejemplo de Uso en Desarrollo

### Testear todos los proveedores

```bash
#!/bin/bash
# test_providers.sh

cd /path/to/sentinel_soa

for provider in ollama gemini openai groq; do
    echo "=========================================="
    echo "Probando con: $provider"
    echo "=========================================="
    
    # Cambiar proveedor
    python switch_llm_provider.py "$provider"
    
    # Reiniciar
    docker-compose restart core_orchestrator mcp_server
    sleep 10  # esperar que inicie
    
    # Ejecutar tests
    python -m pytest tests/test_llm_provider.py -v
    
    echo ""
done
```

### Cambiar rápidamente en desarrollo

```bash
# Alias en ~/.bashrc o ~/.zshrc
alias switch_llm='python /path/to/sentinel_soa/switch_llm_provider.py'

# Luego desde cualquier lugar:
switch_llm openai
switch_llm groq
switch_llm gemini
```

---

## 🔧 Funciones Internas

### `get_current_provider()` 
Lee el .env y retorna el proveedor actual.

```python
current = get_current_provider()
# Retorna: "gemini"
```

### `change_provider(new_provider: str) → bool`
Cambia el proveedor en .env.

```python
result = change_provider("openai")
# Si exitoso: True y modifica .env
# Si error: False y no modifica nada
```

### `show_providers()`
Muestra lista de proveedores con detalles.

```python
show_providers()
# Output: tabla con todos los proveedores y sus características
```

### `interactive_menu()`
Menú interactivo para seleccionar proveedor.

```python
interactive_menu()
# Abre menú con opciones 1-4 y comandos
```

---

## ✅ Checklist Después de Cambiar

```
☐ 1. Ejecutar: python switch_llm_provider.py [proveedor]
☐ 2. Verificar: grep LLM_PROVIDER .env
☐ 3. Reiniciar: docker-compose restart
☐ 4. Esperar: 10 segundos para que inicie
☐ 5. Verificar logs: docker-compose logs core_orchestrator
☐ 6. Buscar: "LLM provider initialized: [proveedor]"
☐ 7. Probar análisis: Enviar una solicitud de telemetría
```

---

## ⚠️ Cosas Importantes

### 1️⃣ Requiere Reinicio
Cambiar .env sin reiniciar NO tiene efecto.

```bash
# ✅ CORRECTO
python switch_llm_provider.py openai
docker-compose restart

# ❌ INCORRECTO
python switch_llm_provider.py openai
# Esperar que funcione sin reiniciar...
```

### 2️⃣ Validación de API Keys
El script cambia .env, pero si la API key no es válida, el servicio fallará al iniciar.

```bash
# Verificar que la API key existe en .env
grep "OPENAI_API_KEY=" .env   # Debe retornar algo
grep "GROQ_API_KEY=" .env     # Debe retornar algo
```

### 3️⃣ El Script NO es Crítico
Si el script falla, puedes editar .env manualmente:

```bash
# Manual (sin script)
vi .env
# Editar: LLM_PROVIDER=gemini → LLM_PROVIDER=openai
# Guardar
docker-compose restart
```

---

## 📊 Casos de Uso

| Caso | Solución |
|------|----------|
| Cambiar una sola vez | Editar .env manualmente |
| Cambiar frecuentemente | Usar script en línea de comandos |
| Automatizar cambios | Usar script en CI/CD bash |
| Testear múltiples providers | Usar script en loop bash |
| Presentación/Demo | Usar modo interactivo |

---

## 🎓 Conclusión

```
switch_llm_provider.py
├─ NO: Se ejecuta automáticamente
├─ NO: Es parte del flujo crítico
├─ NO: Es necesario para que funcione
├──────────────────────────────
├─ SÍ: Es una herramienta de conveniencia
├─ SÍ: Facilita cambiar proveedores
├─ SÍ: Útil en desarrollo/testing
└─ SÍ: Podría automatizarse en CI/CD
```

**Resumen:**
- ✅ Herramienta auxiliar/opcional
- ✅ Modifica .env para cambiar proveedor
- ✅ Requiere reinicio de servicios
- ❌ No se llama automáticamente
- ❌ No es parte del flujo normal

