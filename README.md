# Gateway LLM con Seguridad de Nivel Producción

Gateway en **FastAPI** que expone un único endpoint (`POST /chat`) y reenvía las consultas a **Groq**. Corre 100 % en local y demuestra, con el **mismo código**, una **línea base vulnerable** frente a un **escudo activo** para tres categorías del **OWASP Top 10 for LLM Applications**:

| OWASP | Riesgo | Mitigación | Resultado esperado |
|---|---|---|---|
| LLM01 | Prompt Injection | Filtro regex en el borde | HTTP **400** |
| LLM10 | Unbounded Consumption | Rate limiting con slowapi | HTTP **429** |
| LLM02 | Sensitive Information Disclosure | Credenciales en `.env`, logs JSON con redaction, errores genéricos | **500/502** genérico, sin datos |

> Proyecto Final, Opción 4 — Certified AI/LLM Solution Architect (BSG).

---

## 1. Mapa OWASP → mitigación en código → evidencia reproducible

| Categoría | Mitigación (dónde está en el código) | Cómo reproducirla | Evidencia |
|---|---|---|---|
| **LLM01** Prompt Injection | `app/middlewares/sanitization.py`: normaliza el texto (tildes, mayúsculas, caracteres invisibles) y aplica 6 familias de reglas EN/ES. Se inyecta como dependencia de `POST /chat`. Si hay coincidencia, responde 400 y **no llama al proveedor** (0 tokens). | `python scripts\baseline_demo.py jailbreak` (7 ataques) y `python -m pytest tests\test_llm01_injection.py -v` | Antes: `evidencias/01_baseline_llm01_inyeccion.png`. Después: `04_escudo_llm01_bloqueo_400.png`, `05_escudo_llm01_tests_verde.png` |
| **LLM10** Unbounded Consumption | `app/middlewares/rate_limit.py`: slowapi, límite `RATE_LIMIT=5/minute` por IP; handler propio que devuelve 429 con `Retry-After`. Además `MAX_TOKENS` y `UPSTREAM_TIMEOUT_S` limitan cada llamada (`app/config.py`, `app/services/llm_client.py`). | `python scripts\baseline_demo.py burst -n 10` y `python -m pytest tests\test_llm10_ratelimit.py -v` | Antes: `02_baseline_llm10_rafaga.png`. Después: `06_escudo_llm10_429.png`, `07_escudo_llm10_tests_verde.png` |
| **LLM02** Sensitive Information Disclosure | `app/config.py` (clave en `.env` como `SecretStr`, `.env` en `.gitignore`), `app/logging_config.py` (logs JSON + `redactar()`), `app/main.py` (handler global 500 genérico, handler 502 para fallos del proveedor, el prompt nunca se registra), `app/services/llm_client.py` (errores controlados). | `python scripts\baseline_demo.py leak` con clave falsa y `python -m pytest tests\test_llm02_credentials.py -v` | Antes: `03_baseline_llm02_log_filtra.png`. Después: `08_escudo_llm02_log_json_redactado.png`, `08b_escudo_llm02_log_chat_ok.png`, `09_escudo_llm02_error_generico.png`, `10_escudo_llm02_tests_verde.png` |
| Suite completa | 51 tests (31 LLM01 + 5 LLM10 + 15 LLM02). Ninguno usa la clave real ni llama a Groq. | `python -m pytest -v` | `11_pytest_todos_verde.png` |

Capturas incrustadas:

| Línea base (vulnerable) | Escudo activo |
|---|---|
| ![LLM01 baseline](evidencias/01_baseline_llm01_inyeccion.png) | ![LLM01 escudo](evidencias/04_escudo_llm01_bloqueo_400.png) |
| ![LLM10 baseline](evidencias/02_baseline_llm10_rafaga.png) | ![LLM10 escudo](evidencias/06_escudo_llm10_429.png) |
| ![LLM02 baseline](evidencias/03_baseline_llm02_log_filtra.png) | ![LLM02 escudo](evidencias/08_escudo_llm02_log_json_redactado.png) |

Más evidencia del escudo: [error genérico 502](evidencias/09_escudo_llm02_error_generico.png), [chat normal con log sin prompt](evidencias/08b_escudo_llm02_log_chat_ok.png), tests en verde ([LLM01](evidencias/05_escudo_llm01_tests_verde.png), [LLM10](evidencias/07_escudo_llm10_tests_verde.png), [LLM02](evidencias/10_escudo_llm02_tests_verde.png), [todos](evidencias/11_pytest_todos_verde.png)).

### Resultados medidos (mismo código, solo cambia `PROTECTION_ENABLED`)

| Caso | Línea base | Escudo |
|---|---|---|
| 7 jailbreaks contra `allam-2-7b` | **6 de 7** lograron su objetivo, ~1 367 tokens consumidos | **0 de 7**, 7 bloqueados con HTTP 400, **0 tokens** |
| Ráfaga de 10 peticiones | 10 × 200 | 5 × 200 y 5 × 429 |
| Fallo del proveedor (clave inválida) | El log imprime la clave y el prompt; el cliente recibe 500 sin formato | Log JSON solo con metadatos; el cliente recibe 502 genérico |

---

## 2. Arquitectura

### 2.1 Vista lógica y fronteras de confianza

```mermaid
flowchart LR
    C["Cliente<br/>(zona no confiable)"] -->|HTTPS POST /chat| GW

    subgraph GW["Gateway LLM (FastAPI) · zona de confianza propia"]
        direction TB
        A["Auditoría<br/>solo metadatos"] --> F["LLM01<br/>Filtro de inyección"]
        F --> R["LLM10<br/>Rate limit + max_tokens"]
        R --> L["Cliente LLM<br/>timeout y errores controlados"]
        E["LLM02<br/>Manejo de errores 500/502<br/>Logs JSON con redaction"]
    end

    L -->|HTTPS + API key desde .env| P["Proveedor LLM<br/>(Groq · zona externa)"]
    F -.->|400| C
    R -.->|429 + Retry-After| C
    L -.->|502 genérico| C
    GW -.->|logs sin datos sensibles| O["Observabilidad<br/>(consola / JSON)"]
```

| Componente | Responsabilidad | Control OWASP | Código |
|---|---|---|---|
| Punto de entrada único | Un solo endpoint expuesto: `POST /chat` (+ `/health`) | Todos | `app/main.py` |
| Auditoría | Registra método, ruta, status y latencia; nunca el contenido | LLM02 | `app/main.py`, `app/logging_config.py` |
| Filtro de inyección | Bloquea patrones de ataque antes de gastar tokens | LLM01 | `app/middlewares/sanitization.py` |
| Limitador de tasa | Cuota por cliente y tope de salida por llamada | LLM10 | `app/middlewares/rate_limit.py`, `app/config.py` |
| Cliente del proveedor | Timeout, `max_tokens`, errores convertidos en `UpstreamError` | LLM10, LLM02 | `app/services/llm_client.py` |
| Gestión de secretos | Clave solo en entorno, como `SecretStr` | LLM02 | `app/config.py`, `.env` |
| Manejo de errores | 500 y 502 genéricos, sin trazas, rutas ni claves | LLM02 | `app/main.py` |

**Flujo de una petición.** El cliente llama a `/chat` → se audita → el filtro revisa el prompt (si ataca, 400 y 0 tokens) → el limitador comprueba la cuota (si la excede, 429) → el gateway llama al proveedor con la clave del entorno → devuelve 200 con la respuesta y los tokens usados. Si el proveedor falla, el cliente recibe un 502 genérico; si ocurre cualquier otro error, un 500 genérico.

**Orden de los controles.** El filtro de inyección corre **antes** del rate limit: un ataque bloqueado no consume cuota ni tokens externos. La clave no cruza ninguna frontera hacia el cliente ni hacia los logs.

**Principios de diseño.** Defensa en profundidad (varias capas independientes), fallo seguro (ante error, respuesta genérica), mínimo dato (solo metadatos en logs) y el mismo código para línea base y escudo, para comparar de forma honesta.

### 2.2 Referencia de despliegue en Azure (diseño objetivo, no implementado)

Este proyecto es un **prototipo local** que valida la lógica de seguridad. La tabla muestra cómo cada control se desplegaría en Azure para producción. No se desplegó nada en Azure en esta entrega.

```mermaid
flowchart LR
    U["Clientes"] --> FD["Azure Front Door + WAF"]
    FD --> APIM["Azure API Management<br/>auth, rate-limit-by-key,<br/>límite de tokens"]
    APIM --> CA["Gateway LLM (FastAPI)<br/>Azure Container Apps<br/>con Managed Identity"]
    CA --> KV["Azure Key Vault<br/>secretos"]
    CA --> AOAI["Proveedor LLM<br/>Azure OpenAI / otro"]
    CA --> CS["Azure AI Content Safety<br/>Prompt Shields"]
    CA --> LOG["Application Insights<br/>+ Log Analytics"]
    APIM --> REDIS["Azure Cache for Redis<br/>cuotas compartidas"]
```

| Control en el prototipo | Equivalente en Azure |
|---|---|
| Filtro regex (LLM01) | Se mantiene como primera capa barata; se suma **Azure AI Content Safety (Prompt Shields)** o un clasificador como llama-prompt-guard como segunda capa; WAF en Front Door para el borde HTTP |
| slowapi por IP (LLM10) | **API Management**: `rate-limit-by-key` por suscripción o identidad, y política de límite de tokens para LLM; contadores compartidos entre instancias |
| `.env` con `SecretStr` (LLM02) | **Key Vault** + **Managed Identity** (sin claves en variables ni en el repo) y rotación de secretos |
| Logs JSON con redaction (LLM02) | **Application Insights / Log Analytics**, conservando la redaction en la app y con retención y RBAC |
| Errores 500/502 genéricos (LLM02) | Se mantienen en el gateway; alertas en Azure Monitor sobre 5xx y 429 |
| Un solo endpoint | Un solo backend detrás de APIM; red privada hacia el proveedor (Private Endpoint) |
| Autenticación (no incluida) | **Microsoft Entra ID** o claves de suscripción en APIM; habilita el rate limit por usuario |

> Los nombres de políticas y servicios deben validarse contra la documentación vigente de Azure antes de implementarlos.

### 2.3 Estructura del repositorio

```
app/
  main.py                    # endpoint único, handlers 500/502, auditoría
  config.py                  # settings y secretos (SecretStr)
  logging_config.py          # logs JSON y redactar()
  middlewares/sanitization.py  # LLM01
  middlewares/rate_limit.py    # LLM10
  services/llm_client.py     # cliente de Groq, errores controlados
scripts/baseline_demo.py     # demos: jailbreak | burst | leak
scripts/evidencias.py        # checklist de capturas
tests/                       # 51 tests
evidencias/                  # capturas PNG
```

---

## 3. Reproducir desde cero (Windows, PowerShell)

Requisitos: Python 3.10 o superior, Git y una API key gratuita de [Groq](https://console.groq.com/keys).

```powershell
git clone https://github.com/giannyalfaro/llm-gateway-owasp.git llm-gateway
cd llm-gateway
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env      # luego edita .env y pega tu GROQ_API_KEY
```

**Tests (no necesitan clave real ni red):**

```powershell
python -m pytest -v          # 51 passed
```

**Demo en vivo.** Terminal 1 = servidor, terminal 2 = ataques (activa el venv en cada una).

Línea base vulnerable (usa `allam-2-7b`, que sí cae ante los ataques):
```powershell
# Terminal 1
$env:GROQ_MODEL="allam-2-7b"; $env:REASONING_EFFORT="off"; $env:PROTECTION_ENABLED="false"
uvicorn app.main:app --port 8000
# Terminal 2
python scripts\baseline_demo.py jailbreak
python scripts\baseline_demo.py burst -n 10
```

Escudo activo (reinicia el servidor; `uvicorn --reload` no relee `.env`):
```powershell
# Terminal 1
$env:GROQ_MODEL="allam-2-7b"; $env:REASONING_EFFORT="off"; $env:PROTECTION_ENABLED="true"
uvicorn app.main:app --port 8000
# Terminal 2
python scripts\baseline_demo.py jailbreak     # 0 de 7, 7 bloqueados con 400
python scripts\baseline_demo.py burst -n 10   # 5 x 200 y 5 x 429
```

Demo de LLM02 con **clave falsa** (nunca uses la real para la línea base):
```powershell
$env:GROQ_API_KEY="gsk_FAKE_DEMO_KEY_1234567890"
$env:PROTECTION_ENABLED="false"      # o "true" para ver el escudo
uvicorn app.main:app --port 8000
python scripts\baseline_demo.py leak
```

Variables en `.env.example`: `GROQ_API_KEY`, `GROQ_MODEL`, `REASONING_EFFORT`, `MAX_TOKENS`, `UPSTREAM_TIMEOUT_S`, `PROTECTION_ENABLED`, `RATE_LIMIT`, `API_HOST`, `API_PORT`.

---

## 4. Por qué es una defensa local / de borde

- **Antes del proveedor.** Los controles viven en el gateway, delante de Groq. Un ataque bloqueado no llega al modelo, así que cuesta **0 tokens** y no depende de que el LLM "se porte bien".
- **Independiente del modelo.** Si mañana cambia el modelo o el proveedor, la protección sigue igual. El modelo `gpt-oss-20b` resistió los ataques por sí solo; `allam-2-7b` no. El escudo protege a ambos.
- **Un solo punto de control.** Hay un único endpoint de entrada, por lo que filtros, límites, auditoría y manejo de errores se aplican de forma uniforme y son fáciles de probar.
- **Sin dependencias externas de seguridad.** Todo corre en la máquina: sin servicios de pago ni envío de prompts a terceros adicionales para inspeccionarlos.

## 5. Qué NO se registra y por qué (LLM02)

| No se registra | Motivo |
|---|---|
| El **prompt** del usuario (solo `prompt_chars`) | Puede contener datos personales (DNI, correo, tarjeta) |
| La **respuesta** del modelo | Puede devolver datos personales o el system prompt |
| La **API key** y cabeceras `Authorization` | Credencial que da acceso a la cuenta |
| **Trazas de pila, rutas de archivos y variables** | Revelan estructura interna; en el cliente solo hay mensajes genéricos |

Lo que sí se registra, en JSON con timestamp UTC: método, ruta, status, latencia, modelo, longitud del prompt y tokens usados. Además, `redactar()` enmascara claves (`[REDACTED_KEY]`), correos, tarjetas, teléfonos, DNI y rutas de Windows en cualquier campo que pase por el logger.

Gestión de secretos: la clave vive solo en `.env` (ignorado por git), se carga como `SecretStr` (no aparece en `str()` ni `repr()`) y un test escanea el código para asegurar que no haya claves escritas a mano.

## 6. Degradación controlada

Si Groq falla o rechaza la clave, el gateway no muestra trazas: responde **502** con `{"error": "upstream_unavailable"}` y registra solo la causa resumida (`upstream_status_401`). Cualquier otro error inesperado devuelve un **500 genérico**. Ambos casos están cubiertos por tests.

## 7. Limitaciones conocidas

- **El filtro regex no es infalible.** Es una primera capa: detecta familias conocidas (EN/ES, con normalización contra tildes y caracteres invisibles), pero un atacante creativo puede reformular. Por eso no se vende como solución única.
- **Falsos positivos posibles.** Se probaron prompts legítimos (por ejemplo "Quiero ignorar la caja y devolver solo el producto"), pero una lista de reglas siempre requiere ajuste.
- **Rate limit por IP, no por API key.** Dos usuarios detrás de la misma IP comparten cuota y un atacante con varias IPs la evade. Es el error común que señala el profesor y se documenta aquí como límite.
- **Estado en memoria.** slowapi usa memoria del proceso: no se comparte entre varias instancias ni sobrevive a reinicios.
- **Trazas de uvicorn.** En un error no controlado, uvicorn puede imprimir la traza en la consola del servidor; el cliente solo recibe el 500 genérico. En producción la consola iría a un recolector con redaction.
- **El 500 global se verifica por test**, no por demo en vivo, porque el flujo normal de fallos del proveedor termina en el 502.
- **Baseline a propósito inseguro.** Con `PROTECTION_ENABLED=false` el gateway imprime el prompt y, ante un error del proveedor, las cabeceras. Úsalo **solo** con una clave falsa.

## 8. Mitigaciones futuras

**5.ª mitigación propuesta — clasificador semántico en el borde.** Añadir `meta-llama/llama-prompt-guard-2-22m` (disponible en Groq) como segunda capa tras el regex. El regex es rápido y barato; el clasificador detecta reformulaciones que el regex no ve. Otras mejoras: rate limit **por API key** con almacenamiento compartido (Redis), cuotas de tokens por día y filtro de **salida** (LLM07, ver abajo).

**LLM07 — System Prompt Leakage (opcional, en preparación).** El código interno `TA-INTERNO-7731` del system prompt es el objetivo de los ataques. La mitigación prevista es un filtro de salida que bloquee la respuesta si contiene el secreto. Evidencia prevista: `evidencias/12_escudo_llm07_system_prompt.png`.

---

## 9. Seguridad del repositorio

- `.env` está en `.gitignore`; solo se versiona `.env.example` con un placeholder.
- No hay claves en el código, los tests ni el historial de git (test automático `test_no_hay_claves_hardcodeadas_en_el_codigo`).
- Los tests fuerzan una clave falsa en `tests/conftest.py`; nunca tocan Groq.
