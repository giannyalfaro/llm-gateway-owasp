"""Tests OWASP LLM02 — Sensitive Information Disclosure (credenciales, logs, errores)."""
import json
import re
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.config import settings
from app.logging_config import redactar
from app.middlewares.rate_limit import limiter
from app.services import llm_client
from app.services.llm_client import UpstreamError

RAIZ = Path(__file__).resolve().parent.parent
CLAVE_FALSA = "gsk_FAKE_DEMO_KEY_1234567890abcdef"


@pytest.fixture
def escudo(monkeypatch):
    monkeypatch.setattr(settings, "protection_enabled", True)
    monkeypatch.setattr(limiter, "enabled", False)  # aislar LLM02 del rate limit
    yield
    limiter.reset()


# ─── redactar() ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("texto,secreto", [
    (f"key={CLAVE_FALSA}", CLAVE_FALSA),
    ("Authorization: Bearer abc.DEF-123_xyz", "abc.DEF-123_xyz"),
    ("contacto juan.perez@example.com", "juan.perez@example.com"),
    ("DNI 45871236", "45871236"),
    (r"File C:\dev\llm-gateway\app\main.py", r"C:\dev"),
])
def test_redactar_enmascara_datos_sensibles(texto, secreto):
    salida = redactar(texto)
    assert secreto not in salida
    assert "[REDACTED" in salida


# ─── Logs JSON ───────────────────────────────────────────────────────────────
def _eventos(capsys):
    out = capsys.readouterr().out
    return [json.loads(l) for l in out.splitlines() if l.strip().startswith("{")]


def test_log_es_json_con_timestamp_y_redaction(capsys):
    from app.logging_config import log_event
    log_event("prueba", detalle=f"token {CLAVE_FALSA}")
    ev = _eventos(capsys)[-1]
    assert ev["evento"] == "prueba" and "timestamp" in ev
    assert CLAVE_FALSA not in json.dumps(ev)
    assert "[REDACTED_KEY]" in ev["detalle"]


def test_escudo_no_registra_el_prompt(escudo, monkeypatch, capsys):
    async def llm_falso(prompt):
        return "ok", 7
    monkeypatch.setattr(main, "call_llm", llm_falso)
    unico = "FRASE_UNICA_PROMPT_QZX987"
    r = TestClient(main.app).post("/chat", json={"prompt": f"Hola {unico}"})
    assert r.status_code == 200
    out = capsys.readouterr().out
    assert unico not in out
    evs = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
    http = [e for e in evs if e["evento"] == "http_request"][-1]
    assert http["status_code"] == 200 and "latencia_ms" in http and "timestamp" in http
    chat = [e for e in evs if e["evento"] == "chat_completado"][-1]
    assert chat["tokens_usados"] == 7 and chat["prompt_chars"] == len(f"Hola {unico}")


def test_linea_base_si_imprime_el_prompt(monkeypatch, capsys):
    async def llm_falso(prompt):
        return "ok", 1
    monkeypatch.setattr(main, "call_llm", llm_falso)
    monkeypatch.setattr(settings, "protection_enabled", False)
    monkeypatch.setattr(limiter, "enabled", False)
    TestClient(main.app).post("/chat", json={"prompt": "PROMPT_VISIBLE_EN_BASELINE"})
    assert "PROMPT_VISIBLE_EN_BASELINE" in capsys.readouterr().out


# ─── Errores genéricos ───────────────────────────────────────────────────────
def test_500_global_es_generico_y_no_filtra(escudo, monkeypatch, capsys):
    async def roto(prompt):
        raise RuntimeError(f"fallo con {CLAVE_FALSA} en C:\\dev\\llm-gateway\\app\\main.py")
    monkeypatch.setattr(main, "call_llm", roto)
    c = TestClient(main.app, raise_server_exceptions=False)
    r = c.post("/chat", json={"prompt": "Hola"})
    assert r.status_code == 500
    cuerpo = r.text
    assert r.json()["detail"]["error"] == "internal_error"
    for prohibido in ("gsk_", "C:\\", "RuntimeError", "Traceback"):
        assert prohibido not in cuerpo
    assert CLAVE_FALSA not in capsys.readouterr().out  # tampoco en logs


def test_error_upstream_devuelve_502_generico(escudo, monkeypatch):
    async def caido(prompt):
        raise UpstreamError("upstream_status_401")
    monkeypatch.setattr(main, "call_llm", caido)
    r = TestClient(main.app, raise_server_exceptions=False).post("/chat", json={"prompt": "Hola"})
    assert r.status_code == 502
    assert r.json()["detail"]["error"] == "upstream_unavailable"
    assert "401" not in r.text


# ─── Cliente HTTP hacia Groq ─────────────────────────────────────────────────
def _parchear_transporte(monkeypatch, status):
    real = httpx.AsyncClient

    def fabrica(*a, **kw):
        kw["transport"] = httpx.MockTransport(lambda req: httpx.Response(status, json={"error": "x"}))
        return real(*a, **kw)
    monkeypatch.setattr(llm_client.httpx, "AsyncClient", fabrica)


def test_escudo_upstream_401_no_imprime_credenciales(escudo, monkeypatch, capsys):
    import asyncio
    _parchear_transporte(monkeypatch, 401)
    with pytest.raises(UpstreamError):
        asyncio.run(llm_client.call_llm("hola"))
    out = capsys.readouterr().out
    assert "Bearer" not in out and "gsk_" not in out


def test_baseline_upstream_401_filtra_cabeceras(monkeypatch, capsys):
    import asyncio
    monkeypatch.setattr(settings, "protection_enabled", False)
    _parchear_transporte(monkeypatch, 401)
    with pytest.raises(Exception):
        asyncio.run(llm_client.call_llm("hola"))
    assert "[BASELINE]" in capsys.readouterr().out  # documenta el "antes"


# ─── Gestión de secretos ─────────────────────────────────────────────────────
def test_clave_enmascarada_en_str_y_repr():
    clave = settings.groq_api_key
    assert clave.get_secret_value() not in str(clave)
    assert clave.get_secret_value() not in repr(clave)
    assert "**********" in str(clave)


def test_no_hay_claves_hardcodeadas_en_el_codigo():
    patron = re.compile(r"gsk_[A-Za-z0-9]{20,}")
    for carpeta in ("app", "scripts", "tests"):
        for f in (RAIZ / carpeta).rglob("*.py"):
            assert not patron.search(f.read_text(encoding="utf-8")), f


def test_env_ignorado_y_ejemplo_con_placeholder():
    assert re.search(r"^\.env$", (RAIZ / ".gitignore").read_text(), re.M)
    ejemplo = (RAIZ / ".env.example").read_text()
    assert "GROQ_API_KEY=" in ejemplo and not re.search(r"gsk_[A-Za-z0-9]{20,}", ejemplo)
