"""Configuración común de tests. Usa una key falsa: los tests NUNCA tocan Groq ni tu key real."""
import os

os.environ["GROQ_API_KEY"] = "gsk_test_dummy_key_for_pytest"
os.environ["PROTECTION_ENABLED"] = "false"
