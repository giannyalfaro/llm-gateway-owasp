"""Configuración del Gateway. Todas las credenciales vienen de .env (OWASP LLM02)."""
from pathlib import Path

from dotenv import load_dotenv
from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env", extra="ignore", case_sensitive=False
    )

    # SecretStr: su repr/str muestra '**********', nunca la key real
    groq_api_key: SecretStr
    groq_model: str = "openai/gpt-oss-20b"
    groq_base_url: str = "https://api.groq.com/openai/v1"

    max_tokens: int = 500
    # Modelos de razonamiento (gpt-oss): "low" evita gastar el techo de tokens pensando
    reasoning_effort: str = ""
    upstream_timeout_s: float = 30.0

    protection_enabled: bool = False
    rate_limit: str = "5/minute"

    api_host: str = "127.0.0.1"
    api_port: int = 8000

    @field_validator("groq_api_key")
    @classmethod
    def key_no_es_placeholder(cls, v: SecretStr) -> SecretStr:
        valor = v.get_secret_value().strip()
        if not valor or valor.startswith("pega_aqui"):
            raise ValueError("GROQ_API_KEY no configurada: edita tu archivo .env")
        return v


settings = Settings()
