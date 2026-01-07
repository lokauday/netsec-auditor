"""
Tests for API key authentication and RBAC.
"""
import pytest
from fastapi import status
from unittest.mock import patch

from app.models.api_key import APIKey
from app.api.v1.endpoints.api_keys import hash_api_key

# Minimal valid ASA config for testing
SAMPLE_ASA_CONFIG = """hostname test-asa
interface GigabitEthernet0/0
 nameif outside
 ip address 203.0.113.1 255.255.255.0
access-list OUTSIDE-IN extended permit tcp any host 203.0.113.10 eq 443
"""


def test_upload_without_api_key_fails(client_with_auth):
    """Test that requests without API key are rejected when API_KEY is configured."""
    # client_with_auth has API_KEY="test-key" configured
    response = client_with_auth.post(
        "/api/v1/upload/",
        files={"file": ("test_config.txt", b"test content", "text/plain")}
    )
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Missing API key" in response.json()["detail"] or "Invalid API key" in response.json()["detail"]


def test_upload_with_valid_static_api_key_succeeds(client_with_auth):
    """Test that requests with valid static API key succeed."""
    response = client_with_auth.post(
        "/api/v1/upload/",
        files={"file": ("test_config.txt", SAMPLE_ASA_CONFIG.encode(), "text/plain")},
        headers={"X-API-Key": "test-key"}
    )
    
    assert response.status_code == status.HTTP_201_CREATED
    assert "id" in response.json()


def test_upload_with_invalid_api_key_fails(client_with_auth):
    """Test that requests with invalid API key fail."""
    response = client_with_auth.post(
        "/api/v1/upload/",
        files={"file": ("test_config.txt", b"test content", "text/plain")},
        headers={"X-API-Key": "invalid-key"}
    )
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid API key" in response.json()["detail"]


def test_upload_with_db_api_key_succeeds(client_with_auth, db_session):
    """Test that requests with valid DB API key succeed."""
    # Create a DB API key with hashed key
    raw_key = "db-test-key-12345"
    db_key = APIKey(
        key_hash=hash_api_key(raw_key),
        label="Test DB Key",
        role="read_only",
        is_active=True
    )
    db_session.add(db_key)
    db_session.commit()
    
    response = client_with_auth.post(
        "/api/v1/upload/",
        files={"file": ("test_config.txt", SAMPLE_ASA_CONFIG.encode(), "text/plain")},
        headers={"X-API-Key": raw_key}
    )
    
    assert response.status_code == status.HTTP_201_CREATED
    assert "id" in response.json()


def test_read_only_role_can_access_endpoints(client_with_auth, db_session):
    """Test that read_only role can access endpoints requiring read_only."""
    # Create a read_only DB API key with hashed key
    raw_key = "readonly-key-12345"
    db_key = APIKey(
        key_hash=hash_api_key(raw_key),
        label="Read Only Key",
        role="read_only",
        is_active=True
    )
    db_session.add(db_key)
    db_session.commit()
    
    # Upload should work (requires read_only)
    response = client_with_auth.post(
        "/api/v1/upload/",
        files={"file": ("test_config.txt", SAMPLE_ASA_CONFIG.encode(), "text/plain")},
        headers={"X-API-Key": raw_key}
    )
    
    assert response.status_code == status.HTTP_201_CREATED


def test_admin_role_can_access_endpoints(client_with_auth):
    """Test that admin role (static key) can access all endpoints."""
    # Static key is admin by default
    response = client_with_auth.post(
        "/api/v1/upload/",
        files={"file": ("test_config.txt", SAMPLE_ASA_CONFIG.encode(), "text/plain")},
        headers={"X-API-Key": "test-key"}
    )
    
    assert response.status_code == status.HTTP_201_CREATED


def test_inactive_db_key_fails(client_with_auth, db_session):
    """Test that inactive DB API keys are rejected."""
    # Create an inactive DB API key with hashed key
    raw_key = "inactive-key-12345"
    db_key = APIKey(
        key_hash=hash_api_key(raw_key),
        label="Inactive Key",
        role="read_only",
        is_active=False
    )
    db_session.add(db_key)
    db_session.commit()
    
    response = client_with_auth.post(
        "/api/v1/upload/",
        files={"file": ("test_config.txt", b"test content", "text/plain")},
        headers={"X-API-Key": raw_key}
    )
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

