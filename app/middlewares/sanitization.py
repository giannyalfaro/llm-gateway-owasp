"""Escudo LLM01 (OWASP Prompt Injection): inspección del prompt ANTES de llamar al LLM.

Se implementa como dependencia de FastAPI aplicada a POST /chat. Si el prompt coincide
con un patrón de inyección, el flujo se corta con HTTP 400 y NO se consume ningún
token del proveedor. Solo actúa cuando PROTECTION_ENABLED=true.
"""
import re
import unicodedata
from typing import Optional

from fastapi import HTTPException, Request

from app.config import settings
from app.logging_config import log_event

_INVISIBLES = re.compile(r"[​-‏‪-‮⁠﻿]")


def normalizar(texto: str) -> str:
    """Normaliza para evitar evasiones triviales: tildes, mayúsculas, espacios y
    caracteres invisibles (zero-width)."""
    t = unicodedata.normalize("NFKD", texto)
    t = "".join(c for c in t if not unicodedata.combining(c))
    t = _INVISIBLES.sub("", t)
    return re.sub(r"\s+", " ", t).strip().lower()


# Patrones sin tildes (el texto se normaliza antes). Cada regla: (id, regex).
_REGLAS = [
    (
        "ignorar_instrucciones",
        r"\b(ignor\w*|disregard|forget|olvid\w*|omit\w*|override|anul\w*)\b[^.\n]{0,40}"
        r"\b(instructions?|instrucciones|rules|reglas|directives|directrices|guidelines|prompts?)\b",
    ),
    (
        "modo_desarrollador",
        r"\b(developer|dev|dan|god|jailbreak(ed)?|debug|admin(istrator)?)\s*mode\b"
        r"|\bmodo\s+(desarrollador|developer|dios|depuracion|administrador)\b",
    ),
    (
        "evadir_seguridad",
        r"\b(bypass|disable|turn off|deactivate|circumvent|evad\w*|desactiv\w*|salt\w*)\b"
        r"[^.\n]{0,30}\b(safety|security|filters?|guardrails?|restrictions?|seguridad|filtros?|restricciones|proteccion)\b",
    ),
    (
        "revelar_prompt_sistema",
        r"\b(reveal|show|print|display|repeat|leak|dump|output|muestra|revela|imprime|repite|dime|ensename)\b"
        r"[^.\n]{0,40}\b(system\s*prompt|prompt\s*del\s*sistema|initial\s*instructions?|"
        r"instrucciones\s*(iniciales|internas|del\s*sistema|confidenciales)|confidential\s*instructions?)",
    ),
    (
        "cambio_de_rol",
        r"\b(you are now|from now on you|a partir de ahora (eres|actuaras)|do anything now)\b",
    ),
    (
        "delimitadores_de_rol",
        r"(<\|?(system|im_start|im_end)\|?>|\[/?inst\]|###\s*system)",
    ),
]
_COMPILADAS = [(nombre, re.compile(rx, re.IGNORECASE)) for nombre, rx in _REGLAS]


def detectar_inyeccion(texto: str) -> Optional[str]:
    """Devuelve el id de la primera regla que coincide, o None si el texto es limpio."""
    limpio = normalizar(texto)
    for nombre, rx in _COMPILADAS:
        if rx.search(limpio):
            return nombre
    return None


async def bloquear_inyeccion(request: Request) -> None:
    """Dependencia de FastAPI: corta con HTTP 400 si el prompt parece una inyección."""
    if not settings.protection_enabled:
        return  # línea base: sin protección
    try:
        cuerpo = await request.json()
    except Exception:
        return  # JSON inválido: lo resuelve la validación de FastAPI (422)
    prompt = cuerpo.get("prompt") if isinstance(cuerpo, dict) else None
    if not isinstance(prompt, str):
        return
    regla = detectar_inyeccion(prompt)
    if regla:
        # Se registra la regla y la longitud, NUNCA el prompt (LLM02).
        log_event("llm01_bloqueado", nivel="warning", regla=regla, prompt_chars=len(prompt))
        raise HTTPException(
            status_code=400,
            detail={
                "error": "prompt_injection_detected",
                "mensaje": "La solicitud fue bloqueada por el filtro de seguridad del gateway.",
                "owasp": "LLM01",
            },
        )
