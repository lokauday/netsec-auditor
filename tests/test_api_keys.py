"""
Tests for API key management endpoints.
"""
import pytest
from fastapi import status

from app.models.api_key import APIKey
from app.api.v1.endpoints.api_keys import hash_api_key


def test_list_api_keys_requires_admin(client_with_auth, db_session):
    """Test that listing API keys requires admin role."""
    # Create a read_only key with hashed key
    raw_key = "readonly-list-key"
    read_only_key = APIKey(
        key_hash=hash_api_key(raw_key),
        label="Read Only Key",
        role="read_only",
        is_active=True
    )
    db_session.add(read_only_key)
    db_session.commit()
    
    # Try to list keys with read_only role - should fail
    response = client_with_auth.get(
        "/api/v1/api-keys/",
        headers={"X-API-Key": raw_key}
    )
    
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_admin_can_list_api_keys(client_with_auth, db_session):
    """Test that admin can list API keys."""
    # Create some test keys with hashed keys
    key1 = APIKey(
        key_hash=hash_api_key("test-key-1"),
        label="Test Key 1",
        role="read_only",
        is_active=True
    )
    key2 = APIKey(
        key_hash=hash_api_key("test-key-2"),
        label="Test Key 2",
        role="admin",
        is_active=True
    )
    db_session.add(key1)
    db_session.add(key2)
    db_session.commit()
    
    # List keys with admin key (static key)
    response = client_with_auth.get(
        "/api/v1/api-keys/",
        headers={"X-API-Key": "test-key"}
    )
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 2
    
    # Check that keys are masked and last_used_at is present
    for item in data["items"]:
        assert "key_masked" in item
        assert item["key_masked"] is not None
        assert "last_used_at" in item  # May be None


def test_admin_can_create_api_key(client_with_auth, db_session):
    """Test that admin can create a new API key."""
    response = client_with_auth.post(
        "/api/v1/api-keys/",
        headers={"X-API-Key": "test-key"},
        json={
            "name": "New Test Key",
            "role": "read_only"
        }
    )
    
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "id" in data
    assert "key" in data
    assert data["name"] == "New Test Key"
    assert data["role"] == "read_only"
    assert data["is_active"] is True
    assert len(data["key"]) > 0  # Should have a generated key
    
    # Verify key was saved to DB (as hash, not raw)
    db_key = db_session.query(APIKey).filter(APIKey.id == data["id"]).first()
    assert db_key is not None
    # Verify the hash matches
    from app.api.v1.endpoints.api_keys import verify_api_key_hash
    assert verify_api_key_hash(data["key"], db_key.key_hash)
    assert db_key.label == "New Test Key"


def test_non_admin_cannot_create_api_key(client_with_auth, db_session):
    """Test that non-admin cannot create API keys."""
    # Create a read_only key with hashed key
    raw_key = "readonly-create-key"
    read_only_key = APIKey(
        key_hash=hash_api_key(raw_key),
        label="Read Only Key",
        role="read_only",
        is_active=True
    )
    db_session.add(read_only_key)
    db_session.commit()
    
    # Try to create a key with read_only role - should fail
    response = client_with_auth.post(
        "/api/v1/api-keys/",
        headers={"X-API-Key": raw_key},
        json={
            "name": "Should Fail",
            "role": "read_only"
        }
    )
    
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_admin_can_deactivate_api_key(client_with_auth, db_session):
    """Test that admin can deactivate an API key."""
    # Create a test key with hashed key
    raw_test_key = "deactivate-test-key"
    test_key = APIKey(
        key_hash=hash_api_key(raw_test_key),
        label="Key to Deactivate",
        role="read_only",
        is_active=True
    )
    db_session.add(test_key)
    db_session.commit()
    key_id = test_key.id
    
    # Deactivate it using DELETE endpoint (soft delete)
    response = client_with_auth.delete(
        f"/api/v1/api-keys/{key_id}",
        headers={"X-API-Key": "test-key"}
    )
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["is_active"] is False
    
    # Verify it's deactivated in DB
    db_session.refresh(test_key)
    assert test_key.is_active is False
    
    # Verify deactivated key cannot be used
    upload_response = client_with_auth.post(
        "/api/v1/upload/",
        files={"file": ("test.txt", b"test", "text/plain")},
        headers={"X-API-Key": raw_test_key}
    )
    assert upload_response.status_code == status.HTTP_401_UNAUTHORIZED


def test_deactivate_nonexistent_key_returns_404(client_with_auth):
    """Test that deactivating a nonexistent key returns 404."""
    response = client_with_auth.delete(
        "/api/v1/api-keys/99999",
        headers={"X-API-Key": "test-key"}
    )
    
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_get_current_user_info(client_with_auth, db_session):
    """Test the /auth/me endpoint."""
    # Test with static admin key
    response = client_with_auth.get(
        "/api/v1/auth/me",
        headers={"X-API-Key": "test-key"}
    )
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["role"] == "admin"
    assert data["source"] == "static"
    assert data["is_admin"] is True
    
    # Test with DB read_only key (with hashed key)
    raw_readonly_key = "readonly-me-key"
    read_only_key = APIKey(
        key_hash=hash_api_key(raw_readonly_key),
        label="Read Only Key",
        role="read_only",
        is_active=True
    )
    db_session.add(read_only_key)
    db_session.commit()
    
    response = client_with_auth.get(
        "/api/v1/auth/me",
        headers={"X-API-Key": raw_readonly_key}
    )
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["role"] == "read_only"
    assert data["source"] == "db"
    assert data["is_admin"] is False

