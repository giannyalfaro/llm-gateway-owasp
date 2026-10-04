# Manual de usuario — Gateway LLM con escudo OWASP

Guía para usar el gateway una vez instalado ([MANUAL_INSTALACION.md](MANUAL_INSTALACION.md)). Todos los comandos son de PowerShell con el entorno virtual activo.

## 1. Qué hace

El gateway es el **único punto de entrada** hacia el modelo de Groq. El usuario envía un texto a `POST /chat`; el gateway lo revisa, aplica límites y lo reenvía al proveedor. Con el escudo activo protege tres riesgos del OWASP Top 10 para LLM:

| Riesgo | Qué hace el gateway | Lo que ve el usuario |
|---|---|---|
| LLM01 Prompt Injection | Rechaza prompts que intentan anular las instrucciones o extraer el prompt del sistema | HTTP 400 |
| LLM10 Consumo sin límites | Permite 5 peticiones por minuto por IP y limita los tokens de salida | HTTP 429 |
| LLM02 Fuga de información | Mantiene la clave fuera del código, no registra prompts y devuelve errores genéricos | HTTP 502 / 500 |

## 2. Modos de funcionamiento

| Modo | `PROTECTION_ENABLED` | Uso |
|---|---|---|
| Escudo activo | `true` | Uso normal y seguro |
| Línea base vulnerable | `false` | Solo para demostrar el "antes" de los ataques. **Inseguro a propósito**: imprime prompts y cabeceras en consola; úsalo únicamente con una clave falsa |

Para cambiar de modo en la sesión actual:

```powershell
$env:PROTECTION_ENABLED="true"     # o "false"
uvicorn app.main:app --port 8000
```

Detén y vuelve a arrancar el servidor cada vez que cambies una variable. Para saber en qué modo está: `curl.exe http://127.0.0.1:8000/health`.

## 3. Enviar una consulta

### 3.1 Contrato de la API

| Elemento | Detalle |
|---|---|
| Endpoint | `POST http://127.0.0.1:8000/chat` |
| Cabecera | `Content-Type: application/json` |
| Cuerpo | `{"prompt": "tu pregunta"}` (1 a 4000 caracteres) |
| Respuesta 200 | `{"respuesta": "...", "modelo": "...", "latencia_ms": 850, "tokens_usados": 120}` |

### 3.2 Ejemplo con curl

En PowerShell es más fiable enviar el JSON desde un archivo (evita problemas de comillas):

```powershell
'{"prompt": "Explica en dos frases qué es un gateway de API."}' | Out-File -Encoding ascii body.json
curl.exe -s -X POST http://127.0.0.1:8000/chat -H "Content-Type: application/json" --data-binary "@body.json"
```

`body.json` está en `.gitignore`. También puedes probar desde el navegador en http://127.0.0.1:8000/docs (`POST /chat` > Try it out).

## 4. Respuestas y códigos de estado

| Código | Significado | Cuerpo (resumen) | Qué hacer |
|---|---|---|---|
| 200 | Consulta atendida | `respuesta`, `modelo`, `latencia_ms`, `tokens_usados` | Nada |
| 400 | Prompt bloqueado por posible inyección (LLM01) | `error: prompt_injection_detected`, `owasp: LLM01` | Reformular la consulta sin pedir ignorar instrucciones ni revelar el prompt del sistema |
| 422 | Cuerpo inválido (vacío, sin `prompt` o de más de 4000 caracteres) | Detalle de validación | Corregir el JSON |
| 429 | Límite de peticiones superado (LLM10) | `error: rate_limit_exceeded` + cabecera `Retry-After: 60` | Esperar 60 segundos |
| 502 | El proveedor no está disponible o rechazó la credencial | `error: upstream_unavailable` | Reintentar más tarde; avisar al administrador si persiste |
| 500 | Error interno inesperado | `error: internal_error` | Avisar al administrador; el detalle solo está en el log del servidor |

Los mensajes de error son genéricos a propósito: no revelan claves, rutas ni trazas.

## 5. Ver los logs

El servidor escribe un registro JSON por evento en la terminal donde corre. Ejemplo de campos: marca de tiempo, `evento`, `status_code`, `latencia_ms`, `modelo`, `prompt_chars` y `tokens_usados`.

| Evento | Se emite cuando |
|---|---|
| `http_request` | Cada petición (método, ruta, status, latencia) |
| `chat_completado` | Una consulta se atendió bien |
| `llm01_bloqueado` | Se bloqueó una inyección (incluye la regla, no el texto) |
| `llm10_limite_excedido` | Se superó el límite de peticiones |
| `error_upstream` / `error_no_controlado` | Falló el proveedor o hubo un error inesperado |

**No se registra** el prompt, la respuesta del modelo, la API key ni las cabeceras `Authorization`. Solo se guarda la longitud del prompt.

## 6. Reproducir las demostraciones de seguridad

Usa dos terminales con el entorno activo: la 1 para el servidor y la 2 para los ataques.

### 6.1 LLM01 — Inyección de prompts

```powershell
# Terminal 1: línea base (modelo que sí cae ante los ataques)
$env:GROQ_MODEL="allam-2-7b"; $env:REASONING_EFFORT="off"; $env:PROTECTION_ENABLED="false"
uvicorn app.main:app --port 8000
# Terminal 2
python scripts\baseline_demo.py jailbreak
```
Esperado sin protección: la mayoría de los 7 ataques logra su objetivo (revela el código `TA-INTERNO-7731` o responde `PWNED`).

```powershell
# Terminal 1: Ctrl+C y reiniciar con escudo
$env:PROTECTION_ENABLED="true"
uvicorn app.main:app --port 8000
# Terminal 2
python scripts\baseline_demo.py jailbreak
```
Esperado con escudo: 0 de 7, todos con HTTP 400 y 0 tokens consumidos.

### 6.2 LLM10 — Consumo sin límites

```powershell
# Sin protección (PROTECTION_ENABLED=false)
python scripts\baseline_demo.py burst -n 10        # 10 x 200
# Con escudo (reiniciar el servidor con PROTECTION_ENABLED=true)
python scripts\baseline_demo.py burst -n 10 --secuencial   # 5 x 200 y 5 x 429
```

### 6.3 LLM02 — Fuga de información (solo con clave FALSA)

```powershell
# Terminal 1
$env:GROQ_API_KEY="gsk_FAKE_DEMO_KEY_1234567890"
$env:PROTECTION_ENABLED="false"     # luego repetir con "true"
uvicorn app.main:app --port 8000
# Terminal 2
python scripts\baseline_demo.py leak
```
Sin protección, el log del servidor muestra el prompt con datos personales y la clave en `Authorization`, y el cliente recibe un 500 sin formato. Con escudo, el log solo tiene metadatos y el cliente recibe un 502 genérico. Al terminar, ejecuta `Remove-Item Env:GROQ_API_KEY` para volver a usar la clave real del `.env`.

### 6.4 Tests automáticos

```powershell
python -m pytest -v                                  # 51 tests
python -m pytest tests\test_llm01_injection.py -v    # 31
python -m pytest tests\test_llm10_ratelimit.py -v    # 5
python -m pytest tests\test_llm02_credentials.py -v  # 15
```

Evidencias gráficas del antes y después: carpeta [`evidencias/`](../evidencias).

## 7. Buenas prácticas

- Usa el modo `PROTECTION_ENABLED=true` para cualquier uso que no sea la demostración.
- Nunca abras ni compartas `.env`; trabaja siempre con la clave falsa en las demos de línea base.
- Este gateway es un prototipo local. Sus límites conocidos están en el README, sección 7 (filtro regex como primera capa, límite por IP y estado en memoria).
