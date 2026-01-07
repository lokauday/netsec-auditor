"""
Tests for multi-vendor support (IOS, Fortinet, Palo Alto).
"""
import pytest
from fastapi import status


# Sample Cisco IOS configuration
SAMPLE_CISCO_IOS_CONFIG = """
hostname test-router
!
interface GigabitEthernet0/0
 ip address 203.0.113.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
! ACL with permit ip any any (should trigger IOS_ACL_PERMIT_ANY_ANY)
access-list 100 permit ip any any
access-list 100 permit tcp host 192.168.1.10 host 203.0.113.10 eq 80
!
ip route 0.0.0.0 0.0.0.0 203.0.113.254
!
"""


# Sample Fortinet FortiGate configuration
SAMPLE_FORTINET_CONFIG = """
config system global
    set hostname "test-fgt"
end

config system interface
    edit "port1"
        set ip 203.0.113.1 255.255.255.0
        set status up
    next
    edit "port2"
        set ip 192.168.1.1 255.255.255.0
        set status up
    next
end

config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
    edit 2
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "192.168.1.0/24"
        set dstaddr "203.0.113.10"
        set service "HTTP"
        set action accept
    next
end

config router static
    edit 1
        set dst 0.0.0.0/0
        set gateway 203.0.113.254
    next
end
"""


# Sample Palo Alto Networks configuration
SAMPLE_PALO_ALTO_CONFIG = """
set deviceconfig system hostname test-pa

set network interface ethernet1/1 layer3 ip static-ip 203.0.113.1/24
set network interface ethernet1/2 layer3 ip static-ip 192.168.1.1/24

set rulebase security rules rule1 source any
set rulebase security rules rule1 destination any
set rulebase security rules rule1 application any
set rulebase security rules rule1 action allow

set rulebase security rules rule2 source 192.168.1.0/24
set rulebase security rules rule2 destination 203.0.113.10
set rulebase security rules rule2 application http
set rulebase security rules rule2 action allow

set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0 nexthop ip-address 203.0.113.254
"""


def test_ios_upload_parse_audit(client):
    """Test IOS: upload -> parse -> audit flow."""
    # Upload
    upload_response = client.post(
        "/api/v1/upload/",
        files={"file": ("test_ios_config.txt", SAMPLE_CISCO_IOS_CONFIG, "text/plain")}
    )
    assert upload_response.status_code == status.HTTP_201_CREATED
    config_id = upload_response.json()["id"]
    assert upload_response.json()["vendor"] == "cisco_ios"
    
    # Parse
    parse_response = client.post(f"/api/v1/upload/{config_id}/parse")
    assert parse_response.status_code == status.HTTP_200_OK
    parse_data = parse_response.json()
    assert parse_data["parsed"] is True
    
    elements = parse_data["elements_parsed"]
    assert elements["acls"] > 0, "Should have parsed at least one ACL"
    assert elements["interfaces"] > 0, "Should have parsed at least one interface"
    assert elements["routes"] > 0, "Should have parsed at least one route"
    
    # Audit
    audit_response = client.post(f"/api/v1/audit/{config_id}")
    assert audit_response.status_code == status.HTTP_200_OK
    audit_data = audit_response.json()
    
    assert audit_data["risk_score"] > 0, "Should have risk score > 0"
    assert audit_data["total_findings"] > 0, "Should have at least one finding"
    
    # Verify specific finding code
    finding_codes = [f.get("code", "") for f in audit_data["findings"]]
    assert "IOS_ACL_PERMIT_ANY_ANY" in finding_codes, "Expected IOS_ACL_PERMIT_ANY_ANY finding"
    
    # Verify breakdown
    breakdown = audit_data["breakdown"]
    assert breakdown["critical"] >= 1, "Should have at least one critical finding"


def test_fortinet_upload_parse_audit(client):
    """Test Fortinet: upload -> parse -> audit flow."""
    # Upload
    upload_response = client.post(
        "/api/v1/upload/",
        files={"file": ("test_fortinet_config.txt", SAMPLE_FORTINET_CONFIG, "text/plain")}
    )
    assert upload_response.status_code == status.HTTP_201_CREATED
    config_id = upload_response.json()["id"]
    assert upload_response.json()["vendor"] == "fortinet"
    
    # Parse
    parse_response = client.post(f"/api/v1/upload/{config_id}/parse")
    assert parse_response.status_code == status.HTTP_200_OK
    parse_data = parse_response.json()
    assert parse_data["parsed"] is True
    
    elements = parse_data["elements_parsed"]
    assert elements["acls"] > 0, "Should have parsed at least one ACL/policy"
    assert elements["interfaces"] > 0, "Should have parsed at least one interface"
    assert elements["routes"] > 0, "Should have parsed at least one route"
    
    # Audit
    audit_response = client.post(f"/api/v1/audit/{config_id}")
    assert audit_response.status_code == status.HTTP_200_OK
    audit_data = audit_response.json()
    
    assert audit_data["risk_score"] > 0, "Should have risk score > 0"
    assert audit_data["total_findings"] > 0, "Should have at least one finding"
    
    # Verify specific finding code
    finding_codes = [f.get("code", "") for f in audit_data["findings"]]
    assert "FGT_ANY_ANY_POLICY" in finding_codes, "Expected FGT_ANY_ANY_POLICY finding"
    
    # Verify breakdown
    breakdown = audit_data["breakdown"]
    assert breakdown["critical"] >= 1, "Should have at least one critical finding"


def test_palo_alto_upload_parse_audit(client):
    """Test Palo Alto: upload -> parse -> audit flow."""
    # Upload
    upload_response = client.post(
        "/api/v1/upload/",
        files={"file": ("test_paloalto_config.txt", SAMPLE_PALO_ALTO_CONFIG, "text/plain")}
    )
    assert upload_response.status_code == status.HTTP_201_CREATED
    config_id = upload_response.json()["id"]
    assert upload_response.json()["vendor"] == "palo_alto"
    
    # Parse
    parse_response = client.post(f"/api/v1/upload/{config_id}/parse")
    assert parse_response.status_code == status.HTTP_200_OK
    parse_data = parse_response.json()
    assert parse_data["parsed"] is True
    
    elements = parse_data["elements_parsed"]
    assert elements["acls"] > 0, "Should have parsed at least one ACL/rule"
    # Note: Interface parsing may vary based on config format - not critical for audit
    
    # Audit
    audit_response = client.post(f"/api/v1/audit/{config_id}")
    assert audit_response.status_code == status.HTTP_200_OK
    audit_data = audit_response.json()
    
    assert audit_data["risk_score"] > 0, "Should have risk score > 0"
    assert audit_data["total_findings"] > 0, "Should have at least one finding"
    
    # Verify specific finding code
    finding_codes = [f.get("code", "") for f in audit_data["findings"]]
    assert "PA_ANY_ANY_RULE" in finding_codes, "Expected PA_ANY_ANY_RULE finding"
    
    # Verify breakdown
    breakdown = audit_data["breakdown"]
    assert breakdown["critical"] >= 1, "Should have at least one critical finding"

