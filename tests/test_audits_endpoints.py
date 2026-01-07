"""
Tests for audit history and summary endpoints.
"""
import pytest
from fastapi import status


def test_audit_summary_endpoint(client, db_session):
    """Test that /api/v1/audits/summary endpoint works without parsing errors."""
    # This should not try to parse "summary" as an integer
    response = client.get(
        "/api/v1/audits/summary",
        headers={"X-API-Key": "test-admin-key"}
    )
    # Should return 200 (even if empty) or 401/403 if auth fails, but NOT 422 (validation error)
    assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY, \
        "Summary endpoint should not try to parse 'summary' as audit_id"
    # Should be either 200 (success) or 401/403 (auth required)
    assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]


def test_audit_history_endpoint(client, db_session):
    """Test that /api/v1/audits/history endpoint works without parsing errors."""
    # This should not try to parse "history" as an integer
    response = client.get(
        "/api/v1/audits/history",
        headers={"X-API-Key": "test-admin-key"}
    )
    # Should return 200 (even if empty) or 401/403 if auth fails, but NOT 422 (validation error)
    assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY, \
        "History endpoint should not try to parse 'history' as audit_id"
    # Should be either 200 (success) or 401/403 (auth required)
    assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]


def test_audit_id_endpoint_still_works(client, db_session):
    """Test that /api/v1/audits/{audit_id} still works for integer IDs."""
    # This should try to parse an integer and return 404 (not found) or 401/403 (auth)
    response = client.get(
        "/api/v1/audits/1",
        headers={"X-API-Key": "test-admin-key"}
    )
    # Should be 404 (not found) or 401/403 (auth), but NOT 422 (validation error)
    assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY, \
        "Audit ID endpoint should accept integer IDs"
    assert response.status_code in [
        status.HTTP_404_NOT_FOUND,
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN
    ]

