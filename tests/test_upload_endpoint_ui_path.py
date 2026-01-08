"""
Test to verify the exact upload endpoint path/method used by Streamlit UI.

This test mimics exactly what the Streamlit UI does when uploading a file.
It ensures the backend route matches what the UI expects.
"""
import pytest
from fastapi.testclient import TestClient
from fastapi import status


def test_ui_upload_path_exact_match(client: TestClient):
    """
    Test that the upload endpoint works with the exact path and method used by Streamlit UI.
    
    The UI calls: POST /api/v1/upload/ (with trailing slash)
    This test verifies that exact path works.
    """
    # Sample config content
    config_content = """
hostname test-device
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
!
access-list TEST-ACL extended permit ip any any
!
"""
    
    # Mimic exactly what Streamlit UI does:
    # - URL: /api/v1/upload/ (with trailing slash)
    # - Method: POST
    # - Content-Type: multipart/form-data (handled by files parameter)
    # - Form data: file + optional metadata
    response = client.post(
        "/api/v1/upload/",  # Exact path used by UI (with trailing slash)
        files={"file": ("test_config.txt", config_content, "text/plain")},
        data={
            "device_name": "test-device",
            "environment": "test"
        }
    )
    
    # Should return 201 Created (not 405 Method Not Allowed)
    assert response.status_code == status.HTTP_201_CREATED, \
        f"Expected 201 Created, got {response.status_code}. Response: {response.text}"
    
    data = response.json()
    assert "id" in data
    assert "filename" in data
    assert data["vendor"] in ["cisco_asa", "cisco_ios", "fortinet", "palo_alto"]


def test_ui_upload_path_without_trailing_slash(client: TestClient):
    """
    Test that the upload endpoint behavior without trailing slash.
    
    With redirect_slashes=False, the route without trailing slash should return 404.
    This is expected behavior - the UI should use the exact path with trailing slash.
    """
    config_content = """
hostname test-device
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
!
"""
    
    response = client.post(
        "/api/v1/upload",  # Without trailing slash
        files={"file": ("test_config.txt", config_content, "text/plain")}
    )
    
    # With redirect_slashes=False, this should return 404 (not found)
    # This is expected - the UI must use the exact path with trailing slash
    assert response.status_code == status.HTTP_404_NOT_FOUND, \
        f"Expected 404 (route not found without trailing slash), got {response.status_code}. Response: {response.text}"


def test_upload_endpoint_methods(client: TestClient):
    """
    Verify that only POST is allowed on the upload endpoint.
    """
    # GET should not be allowed (or return 405)
    response = client.get("/api/v1/upload/")
    assert response.status_code in [status.HTTP_405_METHOD_NOT_ALLOWED, status.HTTP_404_NOT_FOUND]
    
    # PUT should not be allowed
    response = client.put("/api/v1/upload/")
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
    
    # DELETE should not be allowed
    response = client.delete("/api/v1/upload/")
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

