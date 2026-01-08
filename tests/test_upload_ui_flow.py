"""
UI-parity tests that simulate the exact upload flow used by Streamlit UI.

These tests ensure that the backend handles the exact same requests
that the Streamlit UI sends, preventing production mismatches.
"""
import pytest
from fastapi.testclient import TestClient
from fastapi import status
from app.main import app


# Use the same client fixture from conftest.py that sets up the test database properly
# This ensures all tables (including devices) are created


def test_ui_upload_path_full_flow(client):
    """
    Test that simulates the exact upload call the Streamlit UI makes.
    
    UI behavior:
    - URL: POST /api/v1/upload/ (with trailing slash)
    - Method: POST
    - Content-Type: multipart/form-data
    - Field name: "file"
    - Optional form fields: device_name, device_ip, environment, location
    - Headers: X-API-Key (if API key is configured)
    """
    # Sample config content (minimal valid config)
    sample_cfg = """hostname test-device
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
!
access-list TEST-ACL extended permit ip any any
!
"""
    
    # Mimic exact UI call:
    # - Same path: /api/v1/upload/ (with trailing slash)
    # - Same method: POST
    # - Same field name: "file"
    # - Same form data structure
    files = {"file": ("test_config.txt", sample_cfg, "text/plain")}
    data = {
        "device_name": "test-device",
        "environment": "test"
    }
    
    # In production, UI sends X-API-Key header if configured
    # For tests, we rely on the test client's auth setup (from conftest.py)
    headers = {}
    
    # Make the exact call the UI makes
    response = client.post(
        "/api/v1/upload/",  # Exact path with trailing slash
        files=files,
        data=data,
        headers=headers
    )
    
    # Should return 201 Created (not 405, not 500)
    assert response.status_code == status.HTTP_201_CREATED, (
        f"Expected 201 Created, got {response.status_code}. "
        f"Response: {response.text}"
    )
    
    # Verify response structure matches what UI expects
    data = response.json()
    assert "id" in data, f"Response missing 'id' field: {data}"
    assert "filename" in data, f"Response missing 'filename' field: {data}"
    assert "vendor" in data, f"Response missing 'vendor' field: {data}"
    assert data["vendor"] in ["cisco_asa", "cisco_ios", "fortinet", "palo_alto"], \
        f"Invalid vendor: {data.get('vendor')}"


def test_ui_upload_with_all_optional_fields(client):
    """
    Test upload with all optional fields that UI can send.
    
    UI can send: device_name, device_ip, environment, location, device_id
    """
    sample_cfg = """hostname test-device
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
!
"""
    
    files = {"file": ("config.txt", sample_cfg, "text/plain")}
    data = {
        "device_name": "test-router",
        "device_ip": "10.0.0.1",
        "environment": "production",
        "location": "datacenter-1"
    }
    
    response = client.post(
        "/api/v1/upload/",
        files=files,
        data=data
    )
    
    assert response.status_code == status.HTTP_201_CREATED, response.text
    result = response.json()
    
    # Verify optional fields were stored
    assert result.get("device_name") == "test-router"
    assert result.get("device_ip") == "10.0.0.1"
    assert result.get("environment") == "production"
    assert result.get("location") == "datacenter-1"


def test_ui_upload_minimal_call(client):
    """
    Test upload with minimal fields (just the file, no optional metadata).
    
    This simulates when UI doesn't send optional form fields.
    """
    sample_cfg = """hostname minimal-device
interface GigabitEthernet0/0
 ip address 172.16.0.1 255.255.255.0
!
"""
    
    files = {"file": ("minimal.txt", sample_cfg, "text/plain")}
    # No data dict - just the file
    
    response = client.post(
        "/api/v1/upload/",
        files=files
    )
    
    assert response.status_code == status.HTTP_201_CREATED, response.text
    result = response.json()
    assert "id" in result
    assert "filename" in result


def test_ui_upload_error_handling(client):
    """
    Test that upload returns proper error codes for invalid requests.
    
    UI should get clear error messages, not 500 Internal Server Error.
    """
    # Test: Missing file
    response = client.post(
        "/api/v1/upload/",
        data={"device_name": "test"}
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY, \
        "Missing file should return 422, not 500"
    
    # Test: Invalid file type (not .txt)
    files = {"file": ("config.conf", "invalid content", "text/plain")}
    response = client.post(
        "/api/v1/upload/",
        files=files
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST, \
        "Invalid file type should return 400, not 500"
    assert "Only .txt files are supported" in response.json().get("detail", "")

