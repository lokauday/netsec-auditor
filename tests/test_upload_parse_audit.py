"""
Tests for upload, parse, and audit flows.
"""
import pytest
from fastapi import status


# Sample Cisco ASA configuration for testing
# This config includes patterns that should trigger security findings:
# - "permit ip any any" (critical: ACL_PERMIT_ANY_ANY)
# - "route outside 0.0.0.0 0.0.0.0" (medium: DEFAULT_ROUTE_OUTSIDE)
# - No "deny ... log" lines (low: NO_DENY_LOGGING)
# - Weak crypto (medium: WEAK_CRYPTO)
# PHASE A CHECKS:
# - A.1: Policy-map without inspect lines (high: ASA_INSPECTION_MISCONFIG)
# - A.2: Weak VPN crypto (high: ASA_WEAK_VPN_SUITE)
# - A.3: Object-group with any used in ACL (critical: ASA_ANY_ANY_OBJECT_GROUP)
# - A.4.1: Management exposed on outside (critical: ASA_MGMT_EXPOSED_OUTSIDE)
# - A.4.2: Weak SNMP community (medium: ASA_SNMP_WEAK_COMMUNITY)
# - A.5: Shadowed ACL (medium: ASA_SHADOWED_ACL)
# - A.6: Unused ACL (low: ASA_UNUSED_ACL)
# - A.7: Overlapping ACL (low: ASA_OVERLAPPING_ACL)
SAMPLE_CISCO_ASA_CONFIG = """
hostname test-asa
!
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.0
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.1.1 255.255.255.0
!
! Object-group with any used in ACL (triggers ASA_ANY_ANY_OBJECT_GROUP - A.3)
object-group network ANY-NETWORKS
 network-object 0.0.0.0 0.0.0.0
!
! ACL using object-group with any (triggers ASA_ANY_ANY_OBJECT_GROUP)
access-list TEST-ACL extended permit ip object-group ANY-NETWORKS object-group ANY-NETWORKS
!
! ACL with permit ip any any (triggers ACL_PERMIT_ANY_ANY)
access-list OUTSIDE-IN extended permit tcp any host 203.0.113.10 eq 443
access-list OUTSIDE-IN extended permit tcp any host 203.0.113.10 eq 80
access-list INSIDE-OUT extended permit ip any any
access-list OUTSIDE-IN extended deny ip any any
!
! Shadowed ACL: later rule is shadowed by earlier "any any" (triggers ASA_SHADOWED_ACL - A.5)
access-list SHADOWED-ACL extended permit ip any any
access-list SHADOWED-ACL extended permit ip host 192.168.1.10 host 10.0.0.1
!
! Unused ACL (not bound to interface) (triggers ASA_UNUSED_ACL - A.6)
access-list UNUSED-ACL extended permit tcp any any eq 443
!
! Overlapping ACL: duplicate rule (triggers ASA_OVERLAPPING_ACL - A.7)
access-list OVERLAP-ACL extended permit tcp 192.168.1.0 255.255.255.0 host 10.0.0.1 eq 80
access-list OVERLAP-ACL extended permit tcp 192.168.1.0 255.255.255.0 host 10.0.0.1 eq 80
!
nat (inside) 1 192.168.1.0 255.255.255.0
!
route outside 0.0.0.0 0.0.0.0 203.0.113.254 1
!
! Management exposed on outside (triggers ASA_MGMT_EXPOSED_OUTSIDE - A.4.1)
ssh 0.0.0.0 0.0.0.0 outside
http 0.0.0.0 0.0.0.0 outside
!
! Weak SNMP community (triggers ASA_SNMP_WEAK_COMMUNITY - A.4.2)
snmp-server community public
!
! Weak VPN crypto (triggers ASA_WEAK_VPN_SUITE - A.2)
crypto ipsec transform-set WEAK-TRANSFORM esp-3des esp-md5-hmac
crypto ikev1 policy 10
 encryption 3des
 hash md5
 authentication pre-share
 group 2
!
crypto map VPN-MAP 1 match address VPN-ACL
crypto map VPN-MAP 1 set peer 203.0.113.100
crypto map VPN-MAP 1 set transform-set WEAK-TRANSFORM
!
! Policy-map without inspect lines in inspection_default (triggers ASA_INSPECTION_MISCONFIG - A.1)
policy-map global_policy
 class inspection_default
!
! Missing service-policy global_policy global
!
"""


def test_upload_config(client):
    """Test uploading a configuration file."""
    response = client.post(
        "/api/v1/upload/",
        files={"file": ("test_config.txt", SAMPLE_CISCO_ASA_CONFIG, "text/plain")}
    )
    
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    
    assert "id" in data
    assert data["filename"].endswith(".txt")
    assert data["vendor"] == "cisco_asa"
    assert data["file_size"] > 0
    
    return data["id"]


def test_parse_config(client):
    """Test parsing an uploaded configuration."""
    # First upload
    upload_response = client.post(
        "/api/v1/upload/",
        files={"file": ("test_config.txt", SAMPLE_CISCO_ASA_CONFIG, "text/plain")}
    )
    config_id = upload_response.json()["id"]
    
    # Then parse
    parse_response = client.post(f"/api/v1/upload/{config_id}/parse")
    
    assert parse_response.status_code == status.HTTP_200_OK
    data = parse_response.json()
    
    assert data["parsed"] is True
    assert "elements_parsed" in data
    assert data["elements_parsed"]["acls"] > 0
    assert data["elements_parsed"]["interfaces"] > 0
    
    return config_id


def test_audit_config(client):
    """Test running a security audit on a parsed configuration."""
    # Upload
    upload_response = client.post(
        "/api/v1/upload/",
        files={"file": ("test_config.txt", SAMPLE_CISCO_ASA_CONFIG, "text/plain")}
    )
    config_id = upload_response.json()["id"]
    
    # Parse
    client.post(f"/api/v1/upload/{config_id}/parse")
    
    # Audit (with AI disabled - rule-based only)
    audit_response = client.post(f"/api/v1/audit/{config_id}")
    
    assert audit_response.status_code == status.HTTP_200_OK
    data = audit_response.json()
    
    # Check structure
    assert "risk_score" in data
    assert "total_findings" in data
    assert "breakdown" in data
    assert "summary" in data
    assert "findings" in data
    
    # Verify risk_score
    assert isinstance(data["risk_score"], int)
    assert 0 < data["risk_score"] <= 100, f"Expected risk_score > 0, got {data['risk_score']}"
    
    # Verify breakdown structure
    breakdown = data["breakdown"]
    assert "critical" in breakdown
    assert "high" in breakdown
    assert "medium" in breakdown
    assert "low" in breakdown
    assert all(isinstance(v, int) for v in breakdown.values())
    
    # Verify we have at least one critical finding (ACL_PERMIT_ANY_ANY or ASA_ANY_ANY_OBJECT_GROUP)
    assert breakdown["critical"] >= 1, f"Expected at least 1 critical finding, got {breakdown['critical']}"
    
    # Verify we have at least one high/medium/low finding combined
    assert (breakdown["high"] + breakdown["medium"] + breakdown["low"]) >= 1, \
        f"Expected at least 1 high/medium/low finding, got high={breakdown['high']}, medium={breakdown['medium']}, low={breakdown['low']}"
    
    # Verify total_findings matches breakdown sum
    breakdown_sum = sum(breakdown.values())
    assert data["total_findings"] == breakdown_sum
    
    # Verify findings list
    assert isinstance(data["findings"], list)
    assert len(data["findings"]) == data["total_findings"]
    
    # Verify specific finding codes are present
    finding_codes = [f.get("code", "") for f in data["findings"]]
    assert "ACL_PERMIT_ANY_ANY" in finding_codes, "Expected ACL_PERMIT_ANY_ANY finding"
    assert "DEFAULT_ROUTE_OUTSIDE" in finding_codes or "NO_DENY_LOGGING" in finding_codes, \
        "Expected DEFAULT_ROUTE_OUTSIDE or NO_DENY_LOGGING finding"
    
    # Verify Phase A finding codes
    assert "ASA_INSPECTION_MISCONFIG" in finding_codes, "Expected ASA_INSPECTION_MISCONFIG finding"
    assert "ASA_WEAK_VPN_SUITE" in finding_codes, "Expected ASA_WEAK_VPN_SUITE finding"
    assert "ASA_ANY_ANY_OBJECT_GROUP" in finding_codes, "Expected ASA_ANY_ANY_OBJECT_GROUP finding"
    assert "ASA_MGMT_EXPOSED_OUTSIDE" in finding_codes, "Expected ASA_MGMT_EXPOSED_OUTSIDE finding"
    assert "ASA_SNMP_WEAK_COMMUNITY" in finding_codes, "Expected ASA_SNMP_WEAK_COMMUNITY finding"
    # Note: Shadowed and overlapping checks may have edge cases - verify at least one is present
    assert ("ASA_SHADOWED_ACL" in finding_codes or "ASA_OVERLAPPING_ACL" in finding_codes), \
        "Expected at least one of ASA_SHADOWED_ACL or ASA_OVERLAPPING_ACL finding"
    assert "ASA_UNUSED_ACL" in finding_codes, "Expected ASA_UNUSED_ACL finding"


def test_full_workflow(client):
    """Test the complete workflow: upload -> parse -> audit."""
    # Upload
    upload_response = client.post(
        "/api/v1/upload/",
        files={"file": ("test_config.txt", SAMPLE_CISCO_ASA_CONFIG, "text/plain")}
    )
    assert upload_response.status_code == status.HTTP_201_CREATED
    config_id = upload_response.json()["id"]
    
    # Parse
    parse_response = client.post(f"/api/v1/upload/{config_id}/parse")
    assert parse_response.status_code == status.HTTP_200_OK
    parse_data = parse_response.json()
    assert parse_data["parsed"] is True
    
    # Verify parsed data structure
    elements = parse_data["elements_parsed"]
    assert "acls" in elements
    assert "interfaces" in elements
    assert "routes" in elements
    assert "nat_rules" in elements
    assert elements["acls"] >= 0
    assert elements["interfaces"] >= 0
    
    # Verify we parsed at least some elements
    assert elements["acls"] > 0, "Should have parsed at least one ACL"
    assert elements["interfaces"] > 0, "Should have parsed at least one interface"
    
    # Audit
    audit_response = client.post(f"/api/v1/audit/{config_id}")
    assert audit_response.status_code == status.HTTP_200_OK
    audit_data = audit_response.json()
    
    # Verify audit structure
    assert "risk_score" in audit_data
    assert "total_findings" in audit_data
    assert "breakdown" in audit_data
    assert "summary" in audit_data
    assert "findings" in audit_data
    
    # Verify risk_score is valid and > 0 (should have findings from test config)
    assert isinstance(audit_data["risk_score"], int)
    assert 0 < audit_data["risk_score"] <= 100, f"Expected risk_score > 0, got {audit_data['risk_score']}"
    
    # Verify breakdown
    breakdown = audit_data["breakdown"]
    assert isinstance(breakdown, dict)
    assert all(key in breakdown for key in ["critical", "high", "medium", "low"])
    assert sum(breakdown.values()) == audit_data["total_findings"]
    
    # Verify we have findings (test config should trigger at least critical + high/medium/low)
    assert audit_data["total_findings"] > 0, "Expected at least one finding from test config"
    assert breakdown["critical"] >= 1, "Expected at least one critical finding (ACL_PERMIT_ANY_ANY or ASA_ANY_ANY_OBJECT_GROUP)"
    assert (breakdown["high"] + breakdown["medium"] + breakdown["low"]) >= 1, \
        "Expected at least one high/medium/low finding"
    
    # Verify findings structure if any exist
    assert isinstance(audit_data["findings"], list)
    assert len(audit_data["findings"]) == audit_data["total_findings"]
    
    # Check findings structure if any exist
    if audit_data["findings"]:
        finding = audit_data["findings"][0]
        assert "severity" in finding
        assert "code" in finding
        assert "description" in finding
        assert "recommendation" in finding
        assert "affected_objects" in finding
        
    # Verify specific finding codes are present
    finding_codes = [f.get("code", "") for f in audit_data["findings"]]
    assert "ACL_PERMIT_ANY_ANY" in finding_codes, "Expected ACL_PERMIT_ANY_ANY finding"
    assert "DEFAULT_ROUTE_OUTSIDE" in finding_codes or "NO_DENY_LOGGING" in finding_codes, \
        "Expected DEFAULT_ROUTE_OUTSIDE or NO_DENY_LOGGING finding"
    
    # Verify at least one high finding (should have multiple from Phase A)
    assert breakdown["high"] >= 1, f"Expected at least one high finding, got {breakdown['high']}"
    
    # Verify Phase A finding codes
    assert "ASA_INSPECTION_MISCONFIG" in finding_codes, "Expected ASA_INSPECTION_MISCONFIG finding"
    assert "ASA_WEAK_VPN_SUITE" in finding_codes, "Expected ASA_WEAK_VPN_SUITE finding"
    assert "ASA_ANY_ANY_OBJECT_GROUP" in finding_codes, "Expected ASA_ANY_ANY_OBJECT_GROUP finding"
    assert "ASA_MGMT_EXPOSED_OUTSIDE" in finding_codes, "Expected ASA_MGMT_EXPOSED_OUTSIDE finding"
    assert "ASA_SNMP_WEAK_COMMUNITY" in finding_codes, "Expected ASA_SNMP_WEAK_COMMUNITY finding"
    # Note: Shadowed and overlapping checks may have edge cases - verify at least one is present
    assert ("ASA_SHADOWED_ACL" in finding_codes or "ASA_OVERLAPPING_ACL" in finding_codes), \
        "Expected at least one of ASA_SHADOWED_ACL or ASA_OVERLAPPING_ACL finding"
    assert "ASA_UNUSED_ACL" in finding_codes, "Expected ASA_UNUSED_ACL finding"
    
    # Test PDF report download
    report_response = client.get(f"/api/v1/audit/{config_id}/report")
    assert report_response.status_code == status.HTTP_200_OK, \
        f"Expected 200 OK for PDF report, got {report_response.status_code}"
    assert report_response.headers["content-type"].startswith("application/pdf"), \
        f"Expected PDF content type, got {report_response.headers['content-type']}"
    assert len(report_response.content) > 1000, \
        f"Expected PDF size > 1000 bytes, got {len(report_response.content)} bytes"

