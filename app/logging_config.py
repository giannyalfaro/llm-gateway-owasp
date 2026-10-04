"""Logging estructurado (JSON) con censura (redaction) — OWASP LLM02.

Reglas de diseño:
  * Se registran SOLO metadatos: timestamp, evento, endpoint, status, latencia, longitudes.
  * NUNCA se registra el prompt del usuario ni la API key.
  * Aun así, todo texto que llegue al log pasa por `redactar()` como segunda barrera.
"""
import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any

# El orden importa: primero las credenciales, luego los datos personales.
_PATRONES = [
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"), "[REDACTED_KEY]"),
    (re.compile(r"\b(?:gsk|sk|pk|rk)[_-][A-Za-z0-9_\-]{8,}"), "[REDACTED_KEY]"),
    (
        re.compile(r"(?i)\b(api[_-]?key|authorization|token|secret|password)(['\"]?\s*[:=]\s*['\"]?)([^\s,'\"}]+)"),
        r"\1\2[REDACTED_KEY]",
    ),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[REDACTED_CARD]"),
    (re.compile(r"\b9\d{8}\b"), "[REDACTED_PHONE]"),
    (re.compile(r"\b\d{8}\b"), "[REDACTED_ID]"),
    (re.compile(r"[A-Za-z]:\\[^\s'\"]+"), "[REDACTED_PATH]"),
]


def redactar(texto: str) -> str:
    for patron, mascara in _PATRONES:
        texto = patron.sub(mascara, texto)
    return texto


def _limpiar(valor: Any) -> Any:
    if isinstance(valor, str):
        return redactar(valor)
    if isinstance(valor, dict):
        return {k: _limpiar(v) for k, v in valor.items()}
    if isinstance(valor, (list, tuple)):
        return [_limpiar(v) for v in valor]
    return valor


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        registro = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "nivel": record.levelname,
            "evento": record.getMessage(),
        }
        registro.update(getattr(record, "campos", {}))
        return json.dumps(_limpiar(registro), ensure_ascii=False)


class _StdoutHandler(logging.StreamHandler):
    """Escribe en el sys.stdout vigente (permite capturarlo en tests)."""

    def __init__(self) -> None:
        logging.Handler.__init__(self)

    @property
    def stream(self):  # type: ignore[override]
        return sys.stdout


def _crear_logger() -> logging.Logger:
    logger = logging.getLogger("gateway")
    if not logger.handlers:
        handler = _StdoutHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


logger = _crear_logger()


def log_event(evento: str, nivel: str = "info", **campos: Any) -> None:
    """Registra un evento de auditoría. Pasa solo metadatos, nunca el prompt."""
    logger.log(getattr(logging, nivel.upper()), evento, extra={"campos": campos})
