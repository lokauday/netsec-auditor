"""
Application configuration settings.

Central configuration module using Pydantic BaseSettings with environment variable support.
Loads from .env file and environment variables.
"""
import json
from pathlib import Path
from typing import List, Optional, Union

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

    # Database settings
    DATABASE_URL: Optional[str] = Field(
        default=None,
        env="DATABASE_URL",
        description="Database connection URL. If not set, uses SQLite for local development (sqlite:///./netsec_auditor.db)",
    )
    
    def get_database_url(self) -> str:
        """
        Get the database URL, defaulting to SQLite for local development.
        
        Returns:
            Database connection URL (SQLite for local, PostgreSQL if DATABASE_URL is set)
        """
        if self.DATABASE_URL:
            return self.DATABASE_URL
        
        # Default to SQLite for local development
        return "sqlite:///./netsec_auditor.db"

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
settings = Settings()

