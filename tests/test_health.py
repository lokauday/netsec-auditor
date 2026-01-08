"""
Tests for health check endpoint.
"""
import pytest
from fastapi import status
from fastapi.testclient import TestClient
from app.main import app


def test_health_endpoint_returns_ok(client):
    """Test that /api/v1/health returns ok when DB is healthy."""
    response = client.get("/api/v1/health")
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["ok"] is True
    assert data["db"] is True
    assert "environment" in data


def test_health_endpoint_with_db_failure(monkeypatch):
    """Test that /api/v1/health returns 503 when DB is down."""
    # Mock get_db to raise an exception
    from app.core.database import get_db
    from sqlalchemy.exc import SQLAlchemyError
    
    def failing_get_db():
        raise SQLAlchemyError("Simulated DB failure")
        yield  # Make it a generator
    
    # Patch get_db dependency
    app.dependency_overrides[get_db] = failing_get_db
    
    try:
        client = TestClient(app)
        response = client.get("/api/v1/health")
        
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        data = response.json()
        assert "detail" in data
    finally:
        # Clean up dependency override
        app.dependency_overrides.clear()


def test_health_endpoint_trace_id_header(client):
    """Test that health endpoint includes trace_id in response headers."""
    response = client.get("/api/v1/health")
    
    # RequestLoggingMiddleware should add X-Trace-ID header
    assert "X-Trace-ID" in response.headers
    trace_id = response.headers["X-Trace-ID"]
    assert len(trace_id) > 0  # Should be a UUID string

