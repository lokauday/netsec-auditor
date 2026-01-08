import os
import sys
from logging.config import fileConfig
from urllib.parse import urlparse

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# Add the app directory to the path so we can import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Import Base and all models to ensure metadata is populated
from app.core.database import Base
from app.models import (
    ConfigFile,
    ACL,
    NATRule,
    VPN,
    Interface,
    Route,
    AuditRecord,
    APIKey,
    ActivityLog,
    Rule,
    Device,
    RulePack,
    DeviceRulePack,
)

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set target_metadata for autogenerate support
target_metadata = Base.metadata

# Get DATABASE_URL from environment and convert if needed
def get_database_url():
    """Get database URL from environment, converting postgres:// to postgresql+psycopg2:// if needed."""
    database_url = os.getenv("DATABASE_URL")
    
    if not database_url:
        # Fall back to settings if DATABASE_URL not set
        from app.core.config import get_settings
        settings = get_settings()
        database_url = settings.sqlalchemy_database_uri
    
    if not database_url:
        raise ValueError("DATABASE_URL not set and no fallback available")
    
    # Convert postgres:// to postgresql+psycopg2:// (Railway uses postgres://)
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql+psycopg2://", 1)
        print(f"[Alembic] Converted postgres:// to postgresql+psycopg2://")
    
    # Add sslmode=require for PostgreSQL if not present (Railway requires SSL)
    if database_url.startswith("postgresql") and "sslmode" not in database_url:
        separator = "&" if "?" in database_url else "?"
        database_url = f"{database_url}{separator}sslmode=require"
        print(f"[Alembic] Added sslmode=require for PostgreSQL connection")
    
    print(f"[Alembic] DATABASE_URL detected, running migrations...")
    return database_url

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    # Use DATABASE_URL from environment, fall back to config file
    url = get_database_url() if os.getenv("DATABASE_URL") else config.get_main_option("sqlalchemy.url")
    
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    # Get database URL from environment
    database_url = get_database_url()
    
    # Override sqlalchemy.url in config with environment DATABASE_URL
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = database_url
    
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
