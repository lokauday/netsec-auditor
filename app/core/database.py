"""
Database configuration and session management.

Uses SQLAlchemy 2.x style with DeclarativeBase for Python 3.13 compatibility.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings

# Get database URL (defaults to SQLite for local development)
database_url = settings.get_database_url()

# Connection arguments for SQLite
connect_args = {}
if database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

# Create engine with appropriate connection args
engine = create_engine(
    database_url,
    pool_pre_ping=True if not database_url.startswith("sqlite") else False,
    echo=settings.DEBUG,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# SQLAlchemy 2.x style base class (replaces deprecated declarative_base)
class Base(DeclarativeBase):
    """Base class for all database models using SQLAlchemy 2.x style."""
    pass


def get_db():
    """Dependency for getting database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

