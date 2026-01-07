"""
Application configuration settings.

Central configuration module using Pydantic BaseSettings with environment variable support.
Loads from .env file and environment variables.
"""
import json
import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Union
from urllib.parse import quote_plus

from dotenv import load_dotenv
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Load .env file if it exists (python-dotenv)
env_path = Path(".env")
if env_path.exists():
    load_dotenv(dotenv_path=env_path)


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # App settings
    APP_NAME: str = "NetSec Auditor"
    APP_ENV: str = Field(default="local", env="APP_ENV")
    DEBUG: bool = Field(default=False, env="DEBUG")

    # Database settings - Railway / generic connection string (highest priority)
    DATABASE_URL: Optional[str] = Field(
        default=None,
        env="DATABASE_URL",
        description="Database connection URL (Railway-style full URL)",
    )
    
    # Railway Postgres plugin raw vars (PG*)
    PGUSER: Optional[str] = Field(default=None, env="PGUSER")
    PGPASSWORD: Optional[str] = Field(default=None, env="PGPASSWORD")
    PGHOST: Optional[str] = Field(default=None, env="PGHOST")
    PGPORT: Optional[str] = Field(default=None, env="PGPORT")
    PGDATABASE: Optional[str] = Field(default=None, env="PGDATABASE")
    
    # Local docker-compose Postgres settings (fallback for local dev)
    # Note: No default passwords - must be set via environment variables
    POSTGRES_USER: Optional[str] = Field(default=None, env="POSTGRES_USER")
    POSTGRES_PASSWORD: Optional[str] = Field(default=None, env="POSTGRES_PASSWORD")
    POSTGRES_HOST: Optional[str] = Field(default=None, env="POSTGRES_HOST")
    POSTGRES_PORT: str = Field(default="5432", env="POSTGRES_PORT")
    POSTGRES_DB: str = Field(default="netsec_auditor", env="POSTGRES_DB")
    
    @property
    def sqlalchemy_database_uri(self) -> str:
        """
        Build SQLAlchemy database URI with priority:
        1. DATABASE_URL (Railway-style full URL)
        2. PG* vars (Railway Postgres plugin raw env vars)
        3. Local docker-compose Postgres (POSTGRES_*)
        4. SQLite (local development without Docker)
        """
        # Priority 1: DATABASE_URL (Railway or explicit connection string)
        if self.DATABASE_URL:
            return self.DATABASE_URL
        
        # Priority 2: PG* vars (Railway Postgres plugin)
        if self.PGUSER and self.PGHOST and self.PGDATABASE:
            password = quote_plus(self.PGPASSWORD or "")
            host = self.PGHOST
            port = self.PGPORT or "5432"
            return f"postgresql+psycopg2://{self.PGUSER}:{password}@{host}:{port}/{self.PGDATABASE}"
        
        # Priority 3: Local docker-compose Postgres
        # Only use if POSTGRES_HOST env var is explicitly set AND all required vars are present
        # (docker-compose sets DATABASE_URL, so this is rarely hit)
        if os.getenv("POSTGRES_HOST") and self.POSTGRES_USER and self.POSTGRES_PASSWORD:
            password = quote_plus(self.POSTGRES_PASSWORD)
            return (
                f"postgresql+psycopg2://"
                f"{self.POSTGRES_USER}:{password}@"
                f"{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
            )
        
        # Priority 4: SQLite fallback (local development without Docker)
        return "sqlite:///./netsec_auditor.db"
    
    def get_database_url(self) -> str:
        """
        Get the database URL (alias for sqlalchemy_database_uri for backward compatibility).
        
        Returns:
            Database connection URL following priority order:
            DATABASE_URL > PG* vars > docker-compose > SQLite
        """
        return self.sqlalchemy_database_uri

    # CORS settings
    CORS_ORIGINS: Union[str, List[str]] = Field(
        default='["http://localhost:3000", "http://localhost:8000"]',
        env="CORS_ORIGINS",
    )

    @field_validator("CORS_ORIGINS")
    @classmethod
    def parse_cors_origins(cls, v):
        """Parse CORS_ORIGINS from string or list."""
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                # If not JSON, treat as comma-separated
                return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    # File upload settings
    MAX_UPLOAD_SIZE: int = Field(
        default=10 * 1024 * 1024, env="MAX_UPLOAD_SIZE", description="Max upload size in bytes (10MB default)"
    )
    UPLOAD_DIR: str = Field(default="./uploads", env="UPLOAD_DIR")

    # AI settings (OpenAI) - Optional
    OPENAI_API_KEY: Optional[str] = Field(
        default=None,
        env="OPENAI_API_KEY",
        description="OpenAI API key for enhanced AI security audit (optional)",
    )
    OPENAI_MODEL: str = Field(
        default="gpt-4",
        env="OPENAI_MODEL",
        description="OpenAI model to use for AI analysis",
    )

    # Logging
    LOG_LEVEL: str = Field(
        default="INFO",
        env="LOG_LEVEL",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )
    
    # API Authentication
    API_KEY: Optional[str] = Field(
        default=None,
        env="API_KEY",
        description="API key for authenticating write operations (upload, parse, audit). Leave empty to disable authentication.",
    )

    def is_openai_available(self) -> bool:
        """Check if OpenAI API key is configured and not empty."""
        return (
            self.OPENAI_API_KEY is not None
            and isinstance(self.OPENAI_API_KEY, str)
            and self.OPENAI_API_KEY.strip() != ""
        )


# Create global settings instance
@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()

# Backward compatibility: keep global settings instance
settings = get_settings()

