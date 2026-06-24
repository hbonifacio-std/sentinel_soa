# Quick Start - Usando OpenAI y GROQ

## Paso 1: Instalar Dependencias

```bash
# Desde la carpeta del proyecto
pip install openai==1.68.0 groq==0.11.3
```

O si usa requirements.txt:
```bash
cd mcp_servers/log_analysis_server
pip install -r requirements.txt
```

## Paso 2: Cambiar de Proveedor

### Opción A: Editar .env directamente

```dotenv
# Cambiar esta línea:
LLM_PROVIDER=gemini

# A una de estas opciones:
LLM_PROVIDER=openai    # Para usar OpenAI
LLM_PROVIDER=groq      # Para usar GROQ
LLM_PROVIDER=ollama    # Para usar Ollama local
```

### Opción B: Usar el script provided

```bash
python switch_llm_provider.py
```

Luego ejecutar (personalizar según tu elección):
```python
from switch_llm_provider import change_provider
change_provider("openai")  # o "groq"
```

## Paso 3: Reiniciar los Servicios

```bash
# Con Docker
docker-compose down
docker-compose up -d

# O manualmente
python core_orchestrator/main.py
```

## Verificar que Funciona

Chequear logs para confirmar que el proveedor se inicializó correctamente:

```bash
# Buscar líneas como:
# "LLM provider initialized: openai"
# "GroqProvider initialized for model: mixtral-8x7b-32768"
```

---

## Configuración Recomendada

### 🚀 Para Máximo Rendimiento (GROQ)
```dotenv
LLM_PROVIDER=groq
GROQ_MODEL=mixtral-8x7b-32768
GROQ_MAX_OUTPUT_TOKENS=4096
GROQ_TIMEOUT_SECONDS=60
```

**Ventajas:**
- Ultra-rápido (inferencia en milisegundos)
- Gratis
- Excelente calidad de respuestas

### 💰 Para Mejor Calidad (OpenAI)
```dotenv
LLM_PROVIDER=openai
OPENAI_MODEL=gpt-4o-mini
OPENAI_MAX_OUTPUT_TOKENS=4096
OPENAI_TIMEOUT_SECONDS=60
```

**Ventajas:**
- Muy confiable
- Excelente precisión
- Múltiples modelos disponibles

### 🏠 Para Ambiente Local (Ollama)
```dotenv
LLM_PROVIDER=ollama
OLLAMA_MODEL=mistral
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_TIMEOUT_SECONDS=900
```

**Ventajas:**
- Completamente local
- Privacidad total
- Costo cero

---

## Troubleshooting

### Error: "Invalid JSON from OpenAI"
- Verificar que `response_format={"type": "json_object"}` está configurado
- Aumentar `OPENAI_MAX_OUTPUT_TOKENS` si la respuesta se corta

### Error: "GROQ API failure"
- Verificar que `GROQ_API_KEY` es válida
- Chequear límites de rate (GROQ tiene límites generosos pero existen)
- Los logs te dirán si es un error de autenticación

### Error: "Configuration error for provider"
- Verificar que `LLM_PROVIDER` está en minúsculas en .env
- Asegurar que la API key está presente con el prefijo correcto
- Ver archivo de log para more details

### Ollama no responde
- Verificar que el contenedor Ollama está ejecutando: `docker ps`
- Verificar URL: `curl http://ollama:11434/api/tags`

---

## Monitoreo

Para ver qué proveedor está activo en runtime:

```bash
# Revisar logs
tail -f logs/*.log | grep "LLM provider"

# O ejecutar un pequeño script:
python -c "from core_orchestrator.config import orchestrator_settings; print(f'Provider: {orchestrator_settings.llm_provider}')"
```

---

## Costo Estimado (por 1M tokens)

| Proveedor | Entrada | Salida | 
|-----------|---------|--------|
| OpenAI (gpt-4o-mini) | $0.15 | $0.60 |
| GROQ | $0.00 | $0.00 |
| Ollama | $0.00 | $0.00 |
| Gemini (gemini-3.5-flash) | $0.075 | $0.30 |

---

## Cambio Rápido Entre Proveedores

```bash
# Script para cambiar rápidamente
for provider in openai groq gemini ollama; do
  echo "Cambiando a $provider..."
  sed -i "s/LLM_PROVIDER=.*/LLM_PROVIDER=$provider/" .env
  echo "Proveedor actual: $(grep LLM_PROVIDER .env)"
  sleep 2
done
```

---

**¡Estás listo!** Ahora puedes usar OpenAI, GROQ, Gemini u Ollama según tus necesidades.

