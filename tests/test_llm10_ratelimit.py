"""Tests OWASP LLM10 — Unbounded Consumption (rate limiting)."""
import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.config import settings
from app.middlewares.rate_limit import limiter


@pytest.fixture
def cliente(monkeypatch):
    llamadas = {"n": 0}

    async def llm_falso(prompt):
        llamadas["n"] += 1
        return "respuesta simulada", 10

    monkeypatch.setattr(main, "call_llm", llm_falso)
    monkeypatch.setattr(settings, "rate_limit", "5/minute")
    limiter.reset()
    c = TestClient(main.app)
    c.llamadas = llamadas
    yield c
    limiter.reset()


def _chat(c):
    return c.post("/chat", json={"prompt": "Hola, quiero devolver un producto."})


def test_escudo_activo_cinco_200_y_luego_429(cliente, monkeypatch):
    monkeypatch.setattr(limiter, "enabled", True)
    codigos = [_chat(cliente).status_code for _ in range(8)]
    assert codigos == [200] * 5 + [429] * 3


def test_429_tiene_cuerpo_owasp_y_retry_after(cliente, monkeypatch):
    monkeypatch.setattr(limiter, "enabled", True)
    for _ in range(5):
        _chat(cliente)
    r = _chat(cliente)
    assert r.status_code == 429
    assert r.json()["detail"]["owasp"] == "LLM10"
    assert r.headers["Retry-After"] == "60"


def test_peticiones_limitadas_no_llegan_al_proveedor(cliente, monkeypatch):
    monkeypatch.setattr(limiter, "enabled", True)
    for _ in range(12):
        _chat(cliente)
    assert cliente.llamadas["n"] == 5  # solo 5 consumieron tokens externos


def test_linea_base_sin_proteccion_no_limita(cliente, monkeypatch):
    monkeypatch.setattr(limiter, "enabled", False)
    codigos = [_chat(cliente).status_code for _ in range(10)]
    assert codigos == [200] * 10
    assert cliente.llamadas["n"] == 10


def test_el_limite_es_configurable(cliente, monkeypatch):
    monkeypatch.setattr(limiter, "enabled", True)
    monkeypatch.setattr(settings, "rate_limit", "2/minute")
    codigos = [_chat(cliente).status_code for _ in range(4)]
    assert codigos == [200, 200, 429, 429]
