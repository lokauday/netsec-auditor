"""
Pytest configuration and fixtures.
"""
import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from unittest.mock import patch

# Import Base and get_db from the app's database module
from app.core.database import Base, get_db
from app.core.auth import verify_api_key
from app.main import app

# Import all models to ensure they register with Base.metadata
# This is critical - tables won't be created if models aren't imported
from app.models import (
    ConfigFile,
    ACL,
    NATRule,
    VPN,
    Interface,
    Route,
    AuditRecord,
    APIKey,
    Device,  # Ensure Device model is imported so table is created
    ActivityLog,  # Ensure ActivityLog model is imported so table is created
    Rule,  # Ensure Rule model is imported so table is created
    RulePack,  # Ensure RulePack model is imported so table is created
    DeviceRulePack,  # Ensure DeviceRulePack model is imported so table is created
)

# Use file-based SQLite for testing (more reliable than in-memory)
TEST_DATABASE_URL = "sqlite:///./test_netsec_auditor.db"

# Create test engine
test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    pool_pre_ping=False,
)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """
    Create all tables before tests run and clean up after all tests complete.
    This runs once per test session.
    """
    # Create all tables
    Base.metadata.create_all(bind=test_engine)
    yield
    # Clean up: drop all tables after all tests
    Base.metadata.drop_all(bind=test_engine)
    # Note: We don't delete the SQLite file here because on Windows it may still be in use
    # The file will be reused/overwritten on the next test run, which is fine


@pytest.fixture(scope="function", autouse=True)
def disable_openai():
    """Disable OpenAI for all tests by patching the settings."""
    with patch("app.core.config.settings.OPENAI_API_KEY", None):
        yield


@pytest.fixture(scope="function", autouse=True)
def disable_api_key():
    """Disable API key authentication for all tests."""
    with patch("app.core.config.settings.API_KEY", None):
        yield


@pytest.fixture(scope="function")
def client():
    """
    Create a test client with database override.
    
    For testing, API key authentication and OpenAI are disabled via fixtures
    to rely only on rule-based logic.
    
    The get_db dependency is overridden to use TestingSessionLocal,
    creating a new session for each request (as FastAPI expects).
    """
    def override_get_db():
        """Override get_db dependency to use test database session."""
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()
    
    # Override database dependency to use test session factory
    app.dependency_overrides[get_db] = override_get_db
    
    yield TestClient(app)
    
    # Clean up: clear dependency overrides after test
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def client_with_auth():
    """
    Create a test client with API key authentication enabled.
    
    Sets API_KEY="test-key" for testing authentication.
    """
    def override_get_db():
        """Override get_db dependency to use test database session."""
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()
    
    # Override database dependency
    app.dependency_overrides[get_db] = override_get_db
    
    # Enable API key auth for this test
    with patch("app.core.config.settings.API_KEY", "test-key"):
        yield TestClient(app)
    
    # Clean up
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def db_session():
    """
    Provide a database session for tests that need direct DB access.
    """
    db = TestingSessionLocal()
    try:
        yield db
        db.rollback()
    finally:
        db.close()

