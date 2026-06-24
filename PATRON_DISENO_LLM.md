# Análisis del Patrón de Diseño de Proveedores LLM

## Patrones de Diseño Utilizados

### 1. **Factory Pattern**
La función `create_llm_provider()` en `llm_providers/__init__.py` actúa como factory que selecciona el proveedor correcto basado en configuración.

```python
# Ejemplo de uso
config = settings.get_provider_config()
provider = create_llm_provider(settings.llm_provider, config)
```

### 2. **Strategy Pattern**
Cada proveedor (`GeminiProvider`, `OllamaProvider`, `OpenAIProvider`, `GroqProvider`) implementa la interfaz `LLMProviderInterface` con diferentes estrategias para:
- Construir prompts
- Llamar al modelo
- Validar respuestas

### 3. **Template Method Pattern**
La clase base `LLMProviderInterface` define el contrato que todos los proveedores deben implementar:

```python
class LLMProviderInterface(ABC):
    @abstractmethod
    def build_analysis_prompt(self, telemetry: Any, history: List[Any]) -> str:
        """Cada proveedor construye su propio prompt"""
        pass
    
    @abstractmethod
    async def call_model(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """Cada proveedor tiene su propia forma de llamar a la API"""
        pass
    
    @abstractmethod
    async def validate_response(self, response: str) -> LLMResponse:
        """Normaliza la respuesta al esquema común"""
        pass
```

## Flujo de Instantiación

```
.env (LLM_PROVIDER=openai)
    ↓
Core Orchestrator (core_orchestrator/config.py)
    └─→ OrchestratorSettings.llm_provider = "openai"
    └─→ Pass environment variables to MCP Server
    ↓
MCP Server (mcp_servers/log_analysis_server/config.py)
    └─→ LogAnalysisServerSettings.llm_provider = "openai"
    └─→ server_settings.get_provider_config()
    ↓
analyze_web_activity.py
    └─→ LLMAnalyzer._get_provider()
    └─→ create_llm_provider(settings.llm_provider, config)
    ↓
Factory Router
    ├─ if "openai" → OpenAIProvider(config)
    ├─ if "groq" → GroqProvider(config)
    ├─ if "gemini" → GeminiProvider(config)
    └─ if "ollama" → OllamaProvider(config)
    ↓
Selected Provider Instance
    ├─ LLMProviderInterface methods
    ├─ Model-specific error handling
    └─ Provider-specific optimizations
```

## Características Clave de Cada Proveedor

### OpenAI
| Aspecto | Valor |
|---------|-------|
| Respuesta esperada | JSON estructurado (via response_format) |
| Formato | Chat Completions API |
| Timeout | 60 segundos |
| Modelo recomendado | gpt-4o-mini (rápido y económico) |
| Autenticación | Bearer token via API key |
| Ventajas | Muy confiable, excelente calidad |
| Desventajas | Costo por token, requiere internet |

### GROQ
| Aspecto | Valor |
|---------|-------|
| Respuesta esperada | JSON (puede venir envuelto en markdown) |
| Formato | Chat Completions API |
| Timeout | 60 segundos |
| Modelo recomendado | mixtral-8x7b-32768 (ultra-rápido) |
| Autenticación | Bearer token via API key |
| Ventajas | Extremadamente rápido, inferencia gratuita |
| Desventajas | Limite de rate, menos modelos disponibles |

### Gemini (existente)
| Aspecto | Valor |
|---------|-------|
| Respuesta esperada | JSON (generationConfig.response_schema) |
| Timeout | N/A (configurable) |
| Modelo recomendado | gemini-3.5-flash |
| Ventajas | Google quality, multimodal |
| Desventajas | API relativamente nueva |

### Ollama (existente)
| Aspecto | Valor |
|---------|-------|
| Respuesta esperada | JSON (pero puede variar) |
| Formato | /api/generate endpoint |
| Timeout | 900 segundos (15 min) |
| Modelo recomendado | mistral (local) |
| Ventajas | Completamente local, sin costo |
| Desventajas | Requiere hardware, menor calidad |

## Jerarquía de Clases

```
LLMProviderInterface (ABC)
    ├── GeminiProvider
    ├── OllamaProvider
    ├── OpenAIProvider (NEW)
    └── GroqProvider (NEW)

Cada proveedor hereda:
    - config dictionary
    - Métodos abstractos a implementar
    - _sanitize_config() para logging seguro
```

## Configuración Centralizada

La arquitectura sigue un principio de **"Single Source of Truth"**:

1. **Core Orchestrator** (`core_orchestrator/config.py`):
   - Define todas las variables de configuración LLM
   - Valida los valores al startup
   - Las pasa como environment variables al MCP Server

2. **MCP Server** (`mcp_servers/log_analysis_server/config.py`):
   - Hereda la configuración via environment
   - Expone método `get_provider_config()` para el factory
   - Validación de runtime

3. **Factory** (`llm_providers/__init__.py`):
   - Usa la configuración centralizada
   - Crea la instancia de proveedor correcta
   - Maneja errores de configuración

## Ventajas del Diseño

✅ **Extensibilidad**: Agregar nuevos proveedores es trivial
✅ **Desacoplamiento**: Los proveedores no saben uno del otro
✅ **Testabilidad**: Cada proveedor puede ser testeado independientemente
✅ **Mantenibilidad**: Los cambios en un proveedor no afectan a otros
✅ **Configuración centralizada**: Un solo lugar para definir variables
✅ **Type safety**: Pydantic valida todas las configuraciones
✅ **Async-ready**: Todos los proveedores soportan operaciones asincrónicas

## Cómo Agregar un Nuevo Proveedor

1. **Crear archivo proveedor** (`new_provider.py`):
```python
from mcp_servers.log_analysis_server.llm_providers.base import LLMProviderInterface

class MyProvider(LLMProviderInterface):
    # Implementar métodos abstractos
    pass
```

2. **Actualizar config.py**:
```python
my_provider_api_key: Optional[SecretStr] = Field(...)
my_provider_model: str = Field(...)
```

3. **Actualizar factory**:
```python
elif provider_name_lower == 'myprovider':
    from ... import MyProvider
    provider_class = MyProvider
```

4. **Actualizar validador**:
```python
valid_providers = [..., 'myprovider']
```

5. **Instalar dependencias**:
```
pip install nuevo-sdk
```

---

**Conclusión**: El patrón actual proporciona una arquitectura robusta, escalable y mantenible para manejar múltiples proveedores de LLM.

