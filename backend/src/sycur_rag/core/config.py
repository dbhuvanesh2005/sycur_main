from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[4]
ENV_FILE = PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",

    )

    # ---------------------------------------------------------
    # Application
    # ---------------------------------------------------------
    APP_ENV: Literal["development", "test", "staging", "production"] = (
        "development"
    )

    LOG_LEVEL: Literal[
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
    ] = "INFO"

    # ---------------------------------------------------------
    # Browser authentication and CORS
    # ---------------------------------------------------------
    SUPABASE_URL: str | None = None
    SUPABASE_JWT_AUDIENCE: str = "authenticated"
    CORS_ALLOWED_ORIGIN: str = "http://localhost:5173"

    # ---------------------------------------------------------
    # Database
    # ---------------------------------------------------------
    DB_NAME: str = Field(default="sycur_rag_poc", min_length=1)
    DB_USER: str = Field(default="postgres", min_length=1)
    DB_PASSWORD: SecretStr
    DB_HOST: str = Field(default="localhost", min_length=1)
    DB_PORT: int = Field(
        default=5432,
        ge=1,
        le=65535,
    )

    # ---------------------------------------------------------
    # Ollama / AI Models
    # ---------------------------------------------------------
    OLLAMA_BASE_URL: str = "http://localhost:11434"

    EMBED_MODEL: str = Field(
        default="bge-m3",
        min_length=1,
    )

    CHAT_MODEL: str = Field(
        default="qwen3.5:9b",
        min_length=1,
    )

    EMBEDDING_DIMENSION: int = Field(
        default=1024,
        gt=0,
    )

    EMBEDDING_BATCH_SIZE: int = Field(
        default=32,
        ge=1,
        le=512,
    )

    OLLAMA_TIMEOUT_SECONDS: int = Field(
        default=180,
        gt=0,
    )

    OLLAMA_MAX_RETRIES: int = Field(
        default=2,
        ge=0,
        le=10,
    )

    OLLAMA_RETRY_BACKOFF_SECONDS: float = Field(
        default=0.5,
        ge=0,
        le=30,
    )

    # ---------------------------------------------------------
    # Hybrid Retrieval
    # ---------------------------------------------------------
    KEYWORD_TOP_K: int = Field(
        default=20,
        gt=0,
    )

    VECTOR_TOP_K: int = Field(
        default=20,
        gt=0,
    )

    FINAL_TOP_K: int = Field(
        default=10,
        gt=0,
    )

    GRAPH_MAX_DEPTH: int = Field(
        default=2,
        ge=1,
        le=5,
    )

    # ---------------------------------------------------------
    # Evidence Selection
    # ---------------------------------------------------------
    EVIDENCE_TOKEN_BUDGET: int = Field(
        default=4000,
        ge=512,
    )

    TOKEN_BUCKET_SIZE: int = Field(
        default=50,
        gt=0,
    )

    # ---------------------------------------------------------
    # Redis / Cache
    # ---------------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379/0"

    CACHE_TTL_SECONDS: int = Field(
        default=3600,
        gt=0,
    )

    # ---------------------------------------------------------
    # Queue
    # ---------------------------------------------------------
    REVIEW_QUEUE_NAME: str = Field(
        default="sycur-review-jobs",
        min_length=1,
    )

    # ---------------------------------------------------------
    # Worker Concurrency
    # ---------------------------------------------------------
    SCANNER_WORKER_CONCURRENCY: int = Field(
        default=4,
        ge=1,
    )

    RAG_WORKER_CONCURRENCY: int = Field(
        default=4,
        ge=1,
    )

    LLM_WORKER_CONCURRENCY: int = Field(
        default=2,
        ge=1,
    )

    # ---------------------------------------------------------
    # GitHub Webhook
    # ---------------------------------------------------------
    GITHUB_WEBHOOK_SECRET: SecretStr
    GITHUB_APP_ID: int | None = None
    GITHUB_APP_PRIVATE_KEY_PATH: str | None = None

    # ---------------------------------------------------------
    # Security Report
    # ---------------------------------------------------------
    SYCUR_PUBLIC_BASE_URL: str = Field(
        default="http://127.0.0.1:8000",
        min_length=1,
    )

    # ---------------------------------------------------------
    # Validators
    # ---------------------------------------------------------
    @field_validator("OLLAMA_BASE_URL")
    @classmethod
    def validate_ollama_base_url(cls, value: str) -> str:
        cleaned = value.strip().rstrip("/")

        if not cleaned.startswith(("http://", "https://")):
            raise ValueError(
                "OLLAMA_BASE_URL must start with http:// or https://"
            )

        return cleaned

    @field_validator("REDIS_URL")
    @classmethod
    def validate_redis_url(cls, value: str) -> str:
        cleaned = value.strip()

        if not cleaned.startswith(("redis://", "rediss://")):
            raise ValueError(
                "REDIS_URL must start with redis:// or rediss://"
            )

        return cleaned

    @field_validator("SYCUR_PUBLIC_BASE_URL")
    @classmethod
    def validate_sycur_public_base_url(
        cls,
        value: str,
    ) -> str:
        cleaned = value.strip().rstrip("/")
        parsed = urlsplit(cleaned)

        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "Invalid SYCUR public base URL."
            )

        if (
            parsed.scheme != "https"
            and parsed.hostname not in {
                "localhost",
                "127.0.0.1",
                "::1",
            }
        ):
            raise ValueError(
                "Public SYCUR URLs must use HTTPS."
            )

        return cleaned

    @field_validator("SUPABASE_URL")
    @classmethod
    def validate_supabase_url(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned = value.strip().rstrip("/")
        parsed = urlsplit(cleaned)

        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Invalid Supabase URL.")

        if (
            parsed.scheme != "https"
            and parsed.hostname not in {
                "localhost",
                "127.0.0.1",
                "::1",
            }
        ):
            raise ValueError(
                "Remote Supabase URLs must use HTTPS."
            )

        return cleaned

    @field_validator("CORS_ALLOWED_ORIGIN")
    @classmethod
    def validate_cors_allowed_origin(
        cls,
        value: str,
    ) -> str:
        cleaned = value.strip().rstrip("/")
        parsed = urlsplit(cleaned)

        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Invalid CORS origin.")

        if (
            parsed.scheme != "https"
            and parsed.hostname not in {
                "localhost",
                "127.0.0.1",
                "::1",
            }
        ):
            raise ValueError(
                "Remote frontend origins must use HTTPS."
            )

        return cleaned

    # ---------------------------------------------------------
    # Derived values
    # ---------------------------------------------------------
    @property
    def ollama_embed_url(self) -> str:
        return f"{self.OLLAMA_BASE_URL}/api/embed"

    @property
    def ollama_chat_url(self) -> str:
        return f"{self.OLLAMA_BASE_URL}/api/chat"

    @property
    def documents_dir(self) -> Path:
        return PROJECT_ROOT / "documents"

    @property
    def supabase_issuer(self) -> str:
        if self.SUPABASE_URL is None:
            raise ValueError("Supabase authentication is not configured.")

        return f"{self.SUPABASE_URL}/auth/v1"

    @property
    def supabase_jwks_url(self) -> str:
        return f"{self.supabase_issuer}/.well-known/jwks.json"

    @property
    def db_password_value(self) -> str:
        return self.DB_PASSWORD.get_secret_value()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
