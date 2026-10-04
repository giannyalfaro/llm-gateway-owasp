# Manual de instalación — Gateway LLM con escudo OWASP

Este manual permite instalar y verificar el gateway desde cero en una máquina limpia. El uso diario está en [MANUAL_USUARIO.md](MANUAL_USUARIO.md) y el mapeo OWASP en el [README](../README.md).

## 1. Requisitos

| Requisito | Detalle |
|---|---|
| Sistema operativo | Windows 10/11 (comandos en PowerShell). En Linux/macOS ver la sección 7 |
| Python | 3.10 o superior (`python --version`) |
| Git | Para clonar el repositorio (`git --version`) |
| Cuenta de Groq | API key gratuita en https://console.groq.com/keys |
| Red | Salida HTTPS a `api.groq.com` (solo para usar el chat real; los tests no la necesitan) |

## 2. Obtener el código

```powershell
git clone https://github.com/giannyalfaro/llm-gateway-owasp.git llm-gateway
cd llm-gateway
```

## 3. Crear el entorno virtual e instalar dependencias

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

El prompt de PowerShell debe mostrar `(.venv)`. **Cada terminal nueva necesita activar el entorno** con `.\.venv\Scripts\Activate.ps1`.

Dependencias principales: FastAPI, uvicorn, httpx, slowapi, pydantic-settings, python-dotenv y pytest.

## 4. Configurar la API key (sin exponerla)

```powershell
copy .env.example .env
notepad .env
```

En `.env` reemplaza `pega_aqui_tu_api_key_de_groq` por tu clave de Groq y guarda. Reglas de seguridad:

- `.env` está en `.gitignore`: **nunca** lo subas al repositorio ni lo muestres en pantalla o capturas.
- Si una clave se expone por error, revócala en la consola de Groq y crea otra.
- Si falta la clave o queda el texto de ejemplo, la aplicación no arranca y pide editar `.env`.

### Variables de configuración

| Variable | Valor por defecto | Para qué sirve |
|---|---|---|
| `GROQ_API_KEY` | (obligatoria) | Credencial del proveedor |
| `GROQ_MODEL` | `openai/gpt-oss-20b` | Modelo a usar |
| `REASONING_EFFORT` | `low` | Esfuerzo de razonamiento (`off` si el modelo no lo soporta) |
| `MAX_TOKENS` | `500` | Techo de tokens de salida (LLM10) |
| `UPSTREAM_TIMEOUT_S` | `30` | Timeout hacia Groq |
| `PROTECTION_ENABLED` | `false` | `false` = línea base vulnerable, `true` = escudo activo |
| `RATE_LIMIT` | `5/minute` | Límite por IP (LLM10) |
| `API_HOST` / `API_PORT` | `127.0.0.1` / `8000` | Dirección de escucha |

> Para uso normal, pon `PROTECTION_ENABLED=true` en `.env`. El valor `false` existe solo para la demostración "antes".

## 5. Verificar la instalación

### 5.1 Tests (no usan la clave real ni la red)

```powershell
python -m pytest -v
```

Resultado esperado: `51 passed`.

### 5.2 Arrancar el servidor

```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Debe aparecer `Uvicorn running on http://127.0.0.1:8000`.

### 5.3 Comprobar que responde (otra terminal, con el entorno activo)

```powershell
curl.exe http://127.0.0.1:8000/health
```

Respuesta esperada:

```json
{"status":"ok","modo":"escudo-activo"}
```

(`"modo":"baseline-vulnerable"` si `PROTECTION_ENABLED=false`.) También hay documentación interactiva en http://127.0.0.1:8000/docs.

## 6. Problemas frecuentes

| Síntoma | Causa | Solución |
|---|---|---|
| `la ejecución de scripts está deshabilitada` al activar el venv | Política de PowerShell | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` y volver a activar |
| `GROQ_API_KEY no configurada` | `.env` ausente o con el texto de ejemplo | Crear `.env` desde `.env.example` y pegar la clave |
| `ModuleNotFoundError` | Entorno virtual no activo | Activar `.venv` en esa terminal e instalar `requirements.txt` |
| Cambié `.env` y no se nota | uvicorn no relee `.env` en caliente | Detener (Ctrl+C) y volver a arrancar |
| Puerto 8000 ocupado | Otro proceso lo usa | Arrancar con `--port 8001` |
| `502 upstream_unavailable` | Clave inválida o sin red hacia Groq | Revisar la clave y la conexión; el detalle solo aparece en el log del servidor |

## 7. Linux / macOS

```bash
git clone https://github.com/giannyalfaro/llm-gateway-owasp.git llm-gateway
cd llm-gateway
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env && nano .env
python -m pytest -v
uvicorn app.main:app --port 8000
```

En el resto de manuales, usa `curl` en lugar de `curl.exe` y `export VARIABLE=valor` en lugar de `$env:VARIABLE="valor"`.

## 8. Desinstalar

Detén el servidor (Ctrl+C), ejecuta `deactivate` y borra la carpeta del proyecto. Si ya no usarás la clave, revócala en https://console.groq.com/keys.
