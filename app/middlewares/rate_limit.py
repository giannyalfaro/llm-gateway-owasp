"""Escudo LLM10 (OWASP Unbounded Consumption): rate limiting con SlowAPI.

El límite se ata a la IP remota del cliente y se aplica con @limiter.limit en POST /chat.
Al excederlo, el gateway responde HTTP 429 sin llamar al proveedor (cero tokens).
Solo actúa cuando PROTECTION_ENABLED=true.
"""
from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import settings
from app.logging_config import log_event

limiter = Limiter(key_func=get_remote_address, enabled=settings.protection_enabled)


def limite_actual() -> str:
    """Se evalúa en cada petición, así RATE_LIMIT puede cambiarse sin tocar código."""
    return settings.rate_limit


async def manejar_limite_excedido(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    # No se registra IP ni prompt: solo que hubo un rechazo por límite (LLM02).
    log_event("llm10_limite_excedido", nivel="warning")
    return JSONResponse(
        status_code=429,
        content={
            "detail": {
                "error": "rate_limit_exceeded",
                "mensaje": "Demasiadas solicitudes. Intenta nuevamente en un minuto.",
                "owasp": "LLM10",
            }
        },
        headers={"Retry-After": "60"},
    )
