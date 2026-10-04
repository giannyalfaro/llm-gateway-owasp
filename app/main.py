"""Gateway LLM — punto único de entrada hacia el proveedor (Groq).

PROTECTION_ENABLED=false -> LÍNEA BASE vulnerable a propósito (para el "antes" del video).
PROTECTION_ENABLED=true  -> ESCUDO activo:
    LLM01  filtro de inyección de prompts       (app/middlewares/sanitization.py)  -> HTTP 400
    LLM10  rate limiting con SlowAPI            (app/middlewares/rate_limit.py)    -> HTTP 429
    LLM02  credenciales en .env, logs JSON con redaction, errores genéricos 500/502
"""
import time

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.logging_config import log_event, redactar
from app.middlewares.rate_limit import limite_actual, limiter, manejar_limite_excedido
from app.middlewares.sanitization import bloquear_inyeccion
from app.services.llm_client import UpstreamError, call_llm

app = FastAPI(title="LLM Gateway", version="0.3.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, manejar_limite_excedido)


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4000)


class ChatResponse(BaseModel):
    respuesta: str
    modelo: str
    latencia_ms: int
    tokens_usados: int


# ─── LLM02: manejo seguro de errores ─────────────────────────────────────────
@app.exception_handler(UpstreamError)
async def manejar_error_upstream(request: Request, exc: UpstreamError) -> JSONResponse:
    """Degradación controlada: el proveedor falló, el cliente recibe un mensaje claro y genérico."""
    log_event("error_upstream", nivel="error", causa=str(exc))
    return JSONResponse(
        status_code=502,
        content={
            "detail": {
                "error": "upstream_unavailable",
                "mensaje": "El proveedor de IA no está disponible en este momento. Intenta más tarde.",
                "owasp": "LLM02",
            }
        },
    )


@app.exception_handler(Exception)
async def manejar_error_no_controlado(request: Request, exc: Exception):
    """Cualquier error no previsto: 500 genérico, sin stack trace, rutas ni variables al cliente."""
    if not settings.protection_enabled:
        return PlainTextResponse("Internal Server Error", status_code=500)  # línea base
    log_event("error_no_controlado", nivel="error", tipo=type(exc).__name__, mensaje=redactar(str(exc)))
    return JSONResponse(
        status_code=500,
        content={
            "detail": {
                "error": "internal_error",
                "mensaje": "Error interno del gateway.",
                "owasp": "LLM02",
            }
        },
    )


# ─── Auditoría: solo metadatos (timestamp lo agrega el formateador JSON) ─────
def _auditar(request: Request, status: int, inicio: float) -> None:
    if settings.protection_enabled:
        log_event(
            "http_request",
            metodo=request.method,
            endpoint=request.url.path,
            status_code=status,
            latencia_ms=int((time.perf_counter() - inicio) * 1000),
        )


@app.middleware("http")
async def auditoria(request: Request, call_next):
    inicio = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        _auditar(request, 500, inicio)
        raise
    _auditar(request, response.status_code, inicio)
    return response


# ─── Endpoints ───────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "modo": "escudo-activo" if settings.protection_enabled else "baseline-vulnerable"}


@app.post("/chat", response_model=ChatResponse, dependencies=[Depends(bloquear_inyeccion)])
@limiter.limit(limite_actual)
async def chat(request: Request, req: ChatRequest):
    inicio = time.perf_counter()
    if not settings.protection_enabled:
        # VULNERABLE a propósito (línea base): imprime el prompt completo.
        print(f"[BASELINE] prompt recibido: {req.prompt}")
    texto, tokens = await call_llm(req.prompt)
    latencia = int((time.perf_counter() - inicio) * 1000)
    if settings.protection_enabled:
        # Solo metadatos: longitud del prompt, nunca su contenido.
        log_event("chat_completado", modelo=settings.groq_model, prompt_chars=len(req.prompt),
                  tokens_usados=tokens, latencia_ms=latencia)
    return ChatResponse(respuesta=texto, modelo=settings.groq_model, latencia_ms=latencia, tokens_usados=tokens)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=settings.api_host, port=settings.api_port, reload=True)
