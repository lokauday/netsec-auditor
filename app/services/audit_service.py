"""
Service for AI-powered security audit of configurations.
"""
import logging
import ipaddress
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session

from app.models.config_file import ConfigFile, VendorType
from app.models.acl import ACL
from app.models.nat_rule import NATRule
from app.models.vpn import VPN
from app.models.routing import Route
from app.models.interface import Interface
from app.models.audit_record import AuditRecord
from app.models.rule import Rule
from app.schemas.findings import SecurityFinding
from app.core.config import settings

logger = logging.getLogger(__name__)


class AuditService:
    """Service for security auditing."""
    
    # Private IP ranges
    PRIVATE_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
    ]
    
    def __init__(self, db: Session):
        """
        Initialize audit service.
        
        Args:
            db: Database session
        """
        self.db = db
    
    def audit_config(self, config_file_id: int, ai_enabled: bool = False) -> Dict[str, Any]:
        """
        Perform security audit on configuration.
        
        Returns structured audit result with risk score, summary, and findings.
        Works with or without AI enabled.
        
        Args:
            config_file_id: Configuration file ID
            
        Returns:
            Dictionary with audit results
        """
        config_file = self.db.query(ConfigFile).filter(ConfigFile.id == config_file_id).first()
        if not config_file:
            raise ValueError(f"Config file not found: {config_file_id}")
        
        # Get all configuration elements
        acls = self.db.query(ACL).filter(ACL.config_file_id == config_file_id).all()
        nat_rules = self.db.query(NATRule).filter(NATRule.config_file_id == config_file_id).all()
        vpns = self.db.query(VPN).filter(VPN.config_file_id == config_file_id).all()
        routes = self.db.query(Route).filter(Route.config_file_id == config_file_id).all()
        interfaces = self.db.query(Interface).filter(Interface.config_file_id == config_file_id).all()
        
        # Run rule-based security checks (includes both built-in and custom rules)
        findings = self._run_rule_based_checks(config_file, acls, nat_rules, routes, interfaces)
        
        # AI analysis flag (use parameter if provided)
        ai_enabled = ai_enabled and settings.is_openai_available()
        ai_summary_enhancement = ""
        
        # If OpenAI API key is configured and ai_enabled=True, enhance with AI analysis
        if ai_enabled:
            try:
                logger.info(f"Running AI-enhanced audit for config file {config_file_id}")
                
                # Read raw config for AI analysis
                from pathlib import Path
                raw_config_text = ""
                try:
                    config_path = Path(config_file.file_path)
                    if config_path.exists():
                        raw_config_text = config_path.read_text(encoding='utf-8', errors='ignore')
                except Exception as e:
                    logger.warning(f"Could not read config file for AI analysis: {e}")
                
                if raw_config_text:
                    # Build rule-based summary for AI
                    severity_counts = {
                        "critical": sum(1 for f in findings if f.severity == "critical"),
                        "high": sum(1 for f in findings if f.severity == "high"),
                        "medium": sum(1 for f in findings if f.severity == "medium"),
                        "low": sum(1 for f in findings if f.severity == "low"),
                    }
                    finding_codes = [f.code for f in findings[:10]]
                    
                    rule_summary = {
                        "severity_counts": severity_counts,
                        "finding_codes": finding_codes,
                        "total_findings": len(findings),
                    }
                    
                    # Run AI analysis with rule-based context
                    ai_result = self._run_ai_analysis(
                        config_text=raw_config_text,
                        vendor=config_file.vendor.value,
                        rule_based_summary=rule_summary,
                        existing_findings=findings,
                    )
                    
                    # Add AI findings (enforce severity limits: medium/low only)
                    for finding_data in ai_result.get("additional_findings", []):
                        try:
                            ai_severity = finding_data.get("severity", "low").lower()
                            # Enforce: AI findings can only be medium or low (no critical/high from AI alone)
                            if ai_severity in ["critical", "high"]:
                                ai_severity = "medium"  # Downgrade to medium
                                logger.debug(f"AI finding severity downgraded from {finding_data.get('severity')} to medium (AI findings limited to medium/low)")
                            
                            # Ensure code has AI_ prefix
                            ai_code = finding_data.get("code", "AI_SUGGESTED_ISSUE")
                            if not ai_code.startswith("AI_"):
                                ai_code = f"AI_{ai_code}"
                            
                            findings.append(SecurityFinding(
                                severity=ai_severity,
                                code=ai_code,
                                description=finding_data.get("description", "AI-identified security concern"),
                                recommendation=finding_data.get("recommendation", "Review and remediate"),
                                affected_objects=finding_data.get("affected_objects", []),
                            ))
                        except Exception as e:
                            logger.warning(f"Failed to create SecurityFinding from AI data: {e}")
                    
                    # Store AI summary enhancement
                    ai_summary_enhancement = ai_result.get("summary", "")
                    ai_enabled = True
                    
            except Exception as e:
                logger.warning(f"AI analysis failed, continuing with rule-based audit only: {e}")
        else:
            logger.info(
                f"OPENAI_API_KEY not configured, skipping AI analysis. "
                f"Running rule-based audit only for config file {config_file_id}"
            )
        
        # Calculate risk score and breakdown
        risk_score = self._calculate_risk_score(findings)
        breakdown = self._calculate_breakdown(findings)
        
        # Calculate policy hygiene score
        hygiene_metrics = self._analyze_policy_hygiene(config_file, acls, nat_rules, routes, interfaces)
        hygiene_score = self._calculate_hygiene_score(hygiene_metrics)
        
        # Generate summary (enhance with AI if available)
        summary = self._generate_summary(findings, risk_score)
        if ai_enabled and ai_summary_enhancement:
            summary += f"\n\nAI Analysis: {ai_summary_enhancement}"
        
        # Convert findings to dict for response
        findings_dict = [finding.model_dump() if isinstance(finding, SecurityFinding) else finding 
                        for finding in findings]
        
        # Save audit record to database
        audit_record = AuditRecord(
            config_file_id=config_file_id,
            risk_score=risk_score,
            summary=summary,
            breakdown=breakdown,  # Store breakdown as JSON
            findings=findings_dict,  # Store as JSON
        )
        self.db.add(audit_record)
        self.db.commit()
        self.db.refresh(audit_record)
        
        # Update device's last audit and scores if device is linked
        if config_file.device_id:
            from app.models.device import Device
            device = self.db.query(Device).filter(Device.id == config_file.device_id).first()
            if device:
                device.last_audit_id = audit_record.id
                device.last_risk_score = risk_score
                device.last_policy_hygiene_score = hygiene_score
                self.db.commit()
        
        logger.info(f"Saved audit record {audit_record.id} for config_file_id={config_file_id}, hygiene_score={hygiene_score}")
        
        return {
            "config_file_id": config_file_id,
            "vendor": config_file.vendor.value,
            "filename": config_file.filename,
            "risk_score": risk_score,
            "policy_hygiene_score": hygiene_score,
            "hygiene_metrics": hygiene_metrics,
            "total_findings": len(findings),
            "breakdown": breakdown,
            "summary": summary,
            "findings": findings_dict,
            "ai_enabled": ai_enabled,
        }
    
    def _run_rule_based_checks(
        self,
        config_file: ConfigFile,
        acls: List[ACL],
        nat_rules: List[NATRule],
        routes: List[Route],
        interfaces: List[Interface],
    ) -> List[SecurityFinding]:
        """Run rule-based security checks and return structured findings."""
        findings = []
        
        # Read raw config file for text-based pattern matching
        from pathlib import Path
        raw_config_text = ""
        try:
            config_path = Path(config_file.file_path)
            if config_path.exists():
                raw_config_text = config_path.read_text(encoding='utf-8', errors='ignore').lower()
        except Exception as e:
            logger.warning(f"Could not read raw config file for pattern matching: {e}")
        
        # ========= ACL_PERMIT_ANY_ANY (CRITICAL) - ASA only =========
        # Normalize full config text (already lowercased above)
        raw_lower = (raw_config_text or "").lower()
        
        # Gather ACL raw text where available
        acl_texts = []
        if acls:
            for acl in acls:
                if getattr(acl, "raw_config", None):
                    acl_texts.append(acl.raw_config.lower())
        
        # Combine ACL texts with full config text
        combined_acl_text = "\n".join(acl_texts) + "\n" + raw_lower
        
        # Patterns to detect
        any_any_patterns = [
            "permit ip any any",
            "permit tcp any any",
            "permit udp any any",
        ]
        
        # Check if any pattern exists in combined text (ASA only)
        if config_file.vendor == VendorType.CISCO_ASA:
            if any(pattern in combined_acl_text for pattern in any_any_patterns):
                # Avoid duplicate if already present
                if not any(f.code == "ACL_PERMIT_ANY_ANY" for f in findings):
                    findings.append(
                        SecurityFinding(
                            severity="critical",
                            code="ACL_PERMIT_ANY_ANY",
                            description=(
                                "Firewall ACL allows unrestricted any-any traffic. "
                                "This effectively bypasses segmentation and exposes "
                                "internal resources to untrusted networks."
                            ),
                            recommendation=(
                                "Replace any-any rules with tightly scoped ACL entries. "
                                "Restrict by source/destination network, ports, and protocols."
                            ),
                            affected_objects=["Access Lists"],
                        )
                    )
        
        # ========= Vendor-specific any-any checks =========
        vendor = (config_file.vendor.value if config_file.vendor else "").lower()
        combined_text = (raw_config_text or "").lower()
        
        # IOS: IOS_ACL_PERMIT_ANY_ANY (CRITICAL)
        if vendor == "cisco_ios":
            if ("permit ip any any" in combined_text or
                "permit tcp any any" in combined_text or
                "permit udp any any" in combined_text):
                # Avoid duplicate if already present
                if not any(f.code == "IOS_ACL_PERMIT_ANY_ANY" for f in findings):
                    findings.append(
                        SecurityFinding(
                            severity="critical",
                            code="IOS_ACL_PERMIT_ANY_ANY",
                            description=(
                                "Cisco IOS ACL allows unrestricted any-any traffic. "
                                "This effectively bypasses segmentation and exposes internal networks."
                            ),
                            recommendation=(
                                "Replace any-any rules with tightly scoped ACLs. "
                                "Restrict by source/destination networks, ports, and protocols."
                            ),
                            affected_objects=["Cisco IOS ACLs"],
                        )
                    )
        
        # Fortinet: FGT_ANY_ANY_POLICY (CRITICAL)
        if vendor == "fortinet":
            if ("config firewall policy" in combined_text and
                'set srcaddr "all"' in combined_text and
                'set dstaddr "all"' in combined_text and
                'set action accept' in combined_text):
                if not any(f.code == "FGT_ANY_ANY_POLICY" for f in findings):
                    findings.append(
                        SecurityFinding(
                            severity="critical",
                            code="FGT_ANY_ANY_POLICY",
                            description=(
                                "Fortinet firewall policy allows any-to-any traffic with action accept. "
                                "This creates a broad exposure to untrusted networks."
                            ),
                            recommendation=(
                                "Replace any-any policies with more specific rules. "
                                "Limit by source/destination address objects, services, and users."
                            ),
                            affected_objects=["Fortinet firewall policies"],
                        )
                    )
        
        # Palo Alto: PA_ANY_ANY_RULE (CRITICAL)
        if vendor == "palo_alto":
            if ("rulebase security" in combined_text and
                " source any" in combined_text and
                " destination any" in combined_text and
                " action allow" in combined_text):
                if not any(f.code == "PA_ANY_ANY_RULE" for f in findings):
                    findings.append(
                        SecurityFinding(
                            severity="critical",
                            code="PA_ANY_ANY_RULE",
                            description=(
                                "Palo Alto security rule allows any-to-any traffic with action allow. "
                                "This can expose internal resources to untrusted sources."
                            ),
                            recommendation=(
                                "Replace any-any rules with scoped policies using address groups, "
                                "applications, and user-based controls."
                            ),
                            affected_objects=["Palo Alto security rules"],
                        )
                    )
        
        # Check 2: DEFAULT_ROUTE_OUTSIDE (medium)
        # Check for "route outside 0.0.0.0 0.0.0.0" in raw config or route data
        default_route_found = False
        for route in routes:
            if route.raw_config:
                raw_route_lower = route.raw_config.lower()
                if "route outside 0.0.0.0 0.0.0.0" in raw_route_lower:
                    findings.append(SecurityFinding(
                        severity="medium",
                        code="DEFAULT_ROUTE_OUTSIDE",
                        description="Default route sends all traffic to the outside interface. Verify upstream firewalling.",
                        affected_objects=[f"Route:{route.id}", f"Interface:{route.interface}", f"Line: {route.raw_config[:100]}"],
                        recommendation="Verify this is intentional and that proper firewall rules are in place. "
                                     "Consider adding specific routes before the default route for internal networks."
                    ))
                    default_route_found = True
                    break
        
        # Also check raw config text if route object didn't have raw_config
        if not default_route_found and raw_config_text:
            if "route outside 0.0.0.0 0.0.0.0" in raw_config_text:
                findings.append(SecurityFinding(
                    severity="medium",
                    code="DEFAULT_ROUTE_OUTSIDE",
                    description="Default route sends all traffic to the outside interface. Verify upstream firewalling.",
                    affected_objects=["Config file", "Default route to outside interface"],
                    recommendation="Verify this is intentional and that proper firewall rules are in place. "
                                 "Consider adding specific routes before the default route for internal networks."
                ))
        
        # Check 3: NO_DENY_LOGGING (low)
        # If there is at least one ACL configured, but there is no line that has both "deny" and "log"
        if len(acls) > 0:
            has_deny_log = False
            # Check ACL raw_config for deny+log patterns
            for acl in acls:
                if acl.raw_config:
                    raw_acl_lower = acl.raw_config.lower()
                    if "deny" in raw_acl_lower and "log" in raw_acl_lower:
                        has_deny_log = True
                        break
            
            # Also check raw config text if no ACL had deny+log
            if not has_deny_log and raw_config_text:
                # Look for access-list lines with both deny and log
                lines = raw_config_text.split('\n')
                for line in lines:
                    if "access-list" in line and "deny" in line and "log" in line:
                        has_deny_log = True
                        break
            
            if not has_deny_log:
                findings.append(SecurityFinding(
                    severity="low",
                    code="NO_DENY_LOGGING",
                    description="ACL does not log denied traffic, which reduces visibility for incident response.",
                    affected_objects=[f"ACL count: {len(acls)}", "All ACL rules"],
                    recommendation="Add 'log' keyword to deny rules to enable logging of blocked traffic. "
                                 "This improves security monitoring and incident response capabilities."
                ))
        
        # Check 4: NAT rules exposing private subnets to internet
        for nat in nat_rules:
            if nat.source_original and self._is_private_network(nat.source_original):
                # Check if NAT is exposing private IPs directly (without restriction)
                if nat.source_translated and not self._is_private_network(nat.source_translated):
                    # Private source being NAT'd to public - this is expected
                    # But check if there are proper ACLs protecting it
                    findings.append(SecurityFinding(
                        severity="high",
                        code="NAT_PRIVATE_EXPOSURE",
                        description=f"NAT rule '{nat.rule_name or 'unnamed'}' translates private network "
                                   f"{nat.source_original} to public IP {nat.source_translated}. "
                                   "Ensure proper ACLs restrict this traffic.",
                        affected_objects=[f"NAT Rule:{nat.rule_name or f'ID:{nat.id}'}"],
                        recommendation="Verify that ACLs restrict inbound traffic to this NAT rule. "
                                     "Private networks should not be directly exposed without proper firewall rules."
                    ))
        
        # Check 5: Default routes (0.0.0.0/0) pointing to untrusted/outside interfaces (existing check)
        # Identify outside interfaces (typically named "outside" or have public IPs)
        outside_interfaces = set()
        for interface in interfaces:
            interface_name_lower = interface.name.lower()
            if ("outside" in interface_name_lower or 
                "external" in interface_name_lower or
                "internet" in interface_name_lower):
                outside_interfaces.add(interface.name)
            # Also check if interface has public IP
            if interface.ip_address and not self._is_private_ip(interface.ip_address):
                outside_interfaces.add(interface.name)
        
        for route in routes:
            if route.network == "0.0.0.0" or route.network == "0.0.0.0/0":
                if route.interface in outside_interfaces:
                    # Check if we already added DEFAULT_ROUTE_OUTSIDE finding
                    already_found = any(
                        f.code == "DEFAULT_ROUTE_OUTSIDE" and f"Route:{route.id}" in f.affected_objects
                        for f in findings
                    )
                    if not already_found:
                        findings.append(SecurityFinding(
                            severity="medium",
                            code="DEFAULT_ROUTE_UNTRUSTED",
                            description=f"Default route (0.0.0.0/0) points to interface '{route.interface}' "
                                       "which appears to be an external/untrusted interface.",
                            affected_objects=[f"Route:{route.id}", f"Interface:{route.interface}"],
                            recommendation="Verify this is intentional. Ensure proper firewall rules are in place "
                                         "to protect against unauthorized access. Consider adding specific routes "
                                         "before the default route for internal networks."
                        ))
        
        # Check 6: TELNET_ENABLED (high)
        # Detect Telnet management access in raw config text
        if raw_config_text:
            # Look for telnet-related patterns
            telnet_patterns = ["telnet ", "transport input telnet"]
            telnet_matches = []
            
            # Find all lines containing telnet patterns
            lines = raw_config_text.split('\n')
            for line in lines:
                for pattern in telnet_patterns:
                    if pattern in line:
                        telnet_matches.append(line.strip())
                        break
            
            # Check if telnet is enabled (not all matches are prefixed with "no ")
            if telnet_matches:
                # Check if all matches are disabled (prefixed with "no ")
                all_disabled = all(
                    match.startswith("no ") or " no " in " " + match
                    for match in telnet_matches
                )
                
                if not all_disabled:
                    # Extract affected lines (limit to first few for readability)
                    affected_objects = ["Line(s) containing 'telnet'"]
                    if telnet_matches:
                        affected_objects.extend(telnet_matches[:2])
                        if len(telnet_matches) > 2:
                            affected_objects.append(f"(and {len(telnet_matches) - 2} more)")
                    
                    findings.append(SecurityFinding(
                        severity="high",
                        code="TELNET_ENABLED",
                        description="Device allows Telnet for management access, exposing credentials and management sessions in cleartext.",
                        recommendation="Disable Telnet and allow only SSH for device management.",
                        affected_objects=affected_objects
                    ))
        
        # Check 7: WEAK_CRYPTO (medium)
        # Detect legacy/weak cryptographic algorithms
        if raw_config_text:
            weak_crypto_patterns = [" 3des", " md5", " sha1"]
            found_weak_crypto = False
            
            for pattern in weak_crypto_patterns:
                if pattern in raw_config_text:
                    found_weak_crypto = True
                    break
            
            if found_weak_crypto:
                findings.append(SecurityFinding(
                    severity="medium",
                    code="WEAK_CRYPTO",
                    description="Configuration uses legacy or weak cryptographic algorithms (3DES, MD5, or SHA1).",
                    recommendation="Migrate to stronger algorithms such as AES-GCM and SHA-256 or better for VPN, SSL, and authentication.",
                    affected_objects=["Crypto / VPN / SSL settings"]
                ))
        
        # ========== PHASE A: ADVANCED ASA SECURITY RULES ==========
        
        # A.1: ASA_INSPECTION_MISCONFIG (HIGH) - ASA only
        if raw_config_text and config_file.vendor == VendorType.CISCO_ASA:
            existing_codes = [f.code for f in findings]
            if "ASA_INSPECTION_MISCONFIG" not in existing_codes:
                has_global_policy = "policy-map global_policy" in raw_config_text
                has_service_policy = "service-policy global_policy global" in raw_config_text
                
                if has_global_policy:
                    # Check if policy-map has inspect lines in class inspection_default
                    lines = raw_config_text.split('\n')
                    in_policy_map = False
                    in_inspection_default = False
                    has_inspect_lines = False
                    
                    for line in lines:
                        line_stripped = line.strip()
                        line_lower = line_stripped.lower()
                        
                        if "policy-map global_policy" in line_lower:
                            in_policy_map = True
                        elif in_policy_map and "class inspection_default" in line_lower:
                            in_inspection_default = True
                        elif in_inspection_default:
                            if line_stripped and not (line_stripped.startswith(' ') or line_stripped.startswith('\t')):
                                if "class" not in line_lower and "policy-map" not in line_lower:
                                    in_inspection_default = False
                                    in_policy_map = False
                            elif "inspect" in line_lower:
                                has_inspect_lines = True
                                break
                    
                    # If policy-map exists but has no inspect lines, it's misconfigured
                    if not has_inspect_lines:
                        findings.append(SecurityFinding(
                            severity="high",
                            code="ASA_INSPECTION_MISCONFIG",
                            description="Global policy-map exists but class inspection_default has no inspect statements, disabling application-layer inspection.",
                            recommendation="Add appropriate inspect statements (e.g., inspect dns, inspect ftp, inspect http) to class inspection_default in policy-map global_policy.",
                            affected_objects=["policy-map global_policy", "class inspection_default"],
                        ))
                elif "no service-policy global_policy global" in raw_config_text:
                    findings.append(SecurityFinding(
                        severity="high",
                        code="ASA_INSPECTION_MISCONFIG",
                        description="Global service-policy is explicitly disabled, disabling application-layer inspection.",
                        recommendation="Enable service-policy: 'service-policy global_policy global' and configure appropriate inspection policies.",
                        affected_objects=["service-policy global_policy global"],
                    ))
        
        # A.2: ASA_WEAK_VPN_SUITE (HIGH) - ASA only
        if raw_config_text and config_file.vendor == VendorType.CISCO_ASA:
            existing_codes = [f.code for f in findings]
            if "ASA_WEAK_VPN_SUITE" not in existing_codes:
                # Check for weak VPN crypto (transform-sets and IKE policies)
                weak_vpn_found = False
                
                # Read original config for case preservation
                try:
                    config_path = Path(config_file.file_path)
                    if config_path.exists():
                        raw_config_original = config_path.read_text(encoding='utf-8', errors='ignore')
                    else:
                        raw_config_original = raw_config_text
                except Exception:
                    raw_config_original = raw_config_text
                
                lines = raw_config_original.split('\n')
                lines_lower = [l.lower() for l in lines]
                
                # Check for weak crypto in transform-sets and IKE policies
                for i, line_lower in enumerate(lines_lower):
                    if "crypto ipsec transform-set" in line_lower or "crypto ikev1 policy" in line_lower or "crypto ikev2 policy" in line_lower:
                        # Check for weak algorithms in the block
                        weak_algorithms = ["des", "3des", "md5", "sha1"]
                        weak_dh_groups = ["group 1", "group 2", "group 5", "dh group 1", "dh group 2", "dh group 5"]
                        
                        # Check current line and next few lines (crypto blocks are multi-line)
                        crypto_block = " ".join(lines_lower[max(0, i):min(len(lines_lower), i+10)])
                        if any(weak in crypto_block for weak in weak_algorithms + weak_dh_groups):
                            weak_vpn_found = True
                            break
                
                if weak_vpn_found:
                    findings.append(SecurityFinding(
                        severity="high",
                        code="ASA_WEAK_VPN_SUITE",
                        description="VPN/IPsec configuration uses weak cryptographic algorithms (DES, 3DES, MD5, SHA-1) or weak Diffie-Hellman groups (1, 2, 5).",
                        recommendation="Migrate to modern crypto suites: AES-256 or AES-GCM for encryption, SHA-256+ for hashing, and DH group 14+ or ECDH for key exchange.",
                        affected_objects=["VPN crypto configuration"],
                    ))
        
        # A.3: ASA_ANY_ANY_OBJECT_GROUP (CRITICAL) - ASA only
        if raw_config_text and config_file.vendor == VendorType.CISCO_ASA:
            existing_codes = [f.code for f in findings]
            if "ASA_ANY_ANY_OBJECT_GROUP" not in existing_codes:
                lines = raw_config_text.split('\n')
                any_any_object_groups = []
                current_group = None
                current_group_name = None
                
                for line in lines:
                    line_stripped = line.strip()
                    line_lower = line_stripped.lower()
                    
                    if line_lower.startswith("object-group network") or line_lower.startswith("object-group service"):
                        parts = line_lower.split()
                        if len(parts) >= 3:
                            current_group_name = parts[2]
                            current_group = line_lower
                    
                    elif current_group_name:
                        # Check for any-any patterns (0.0.0.0/0 or "any")
                        if ("network-object 0.0.0.0 0.0.0.0" in line_lower or
                            "network-object any" in line_lower or
                            "service-object any" in line_lower):
                            if current_group_name not in any_any_object_groups:
                                any_any_object_groups.append(current_group_name)
                    
                    # Reset on new top-level config
                    if line_stripped and not (line_stripped.startswith(' ') or line_stripped.startswith('\t')):
                        if not (line_lower.startswith("object-group network") or line_lower.startswith("object-group service")):
                            current_group = None
                            current_group_name = None
                
                # Check if any of these object-groups are used in ACLs
                if any_any_object_groups:
                    for group_name in any_any_object_groups:
                        # Check if referenced in ACL
                        for line in lines:
                            if "access-list" in line.lower() and group_name.lower() in line.lower():
                                findings.append(SecurityFinding(
                                    severity="critical",
                                    code="ASA_ANY_ANY_OBJECT_GROUP",
                                    description=f"Object-group '{group_name}' contains 'any' or '0.0.0.0/0' and is used in ACLs, creating unrestricted access.",
                                    recommendation="Replace object-group members with specific network/service definitions. Remove 'any' or '0.0.0.0/0' entries.",
                                    affected_objects=[f"Object-group: {group_name}"],
                                ))
                                break
        
        # A.4.1: ASA_MGMT_EXPOSED_OUTSIDE (CRITICAL) - ASA only
        if raw_config_text and config_file.vendor == VendorType.CISCO_ASA:
            existing_codes = [f.code for f in findings]
            if "ASA_MGMT_EXPOSED_OUTSIDE" not in existing_codes:
                lines = raw_config_text.split('\n')
                exposed_mgmt = []
                
                for line in lines:
                    line_stripped = line.strip()
                    line_lower = line_stripped.lower()
                    
                    # Check for management services on outside interface
                    # ssh 0.0.0.0 0.0.0.0 outside
                    # http 0.0.0.0 0.0.0.0 outside
                    # telnet 0.0.0.0 0.0.0.0 outside
                    mgmt_patterns = [
                        ("ssh", "ssh 0.0.0.0 0.0.0.0 outside"),
                        ("http", "http 0.0.0.0 0.0.0.0 outside"),
                        ("https", "https 0.0.0.0 0.0.0.0 outside"),
                        ("telnet", "telnet 0.0.0.0 0.0.0.0 outside"),
                    ]
                    
                    for service, pattern in mgmt_patterns:
                        if pattern in line_lower or (service in line_lower and "outside" in line_lower and ("0.0.0.0 0.0.0.0" in line_lower or "any" in line_lower)):
                            exposed_mgmt.append((service, line_stripped[:100]))
                            break
                
                if exposed_mgmt:
                    services_list = ", ".join([s[0].upper() for s in exposed_mgmt])
                    findings.append(SecurityFinding(
                        severity="critical",
                        code="ASA_MGMT_EXPOSED_OUTSIDE",
                        description=f"Management services ({services_list}) are exposed on the outside interface with unrestricted access (0.0.0.0/0).",
                        recommendation="Restrict management access to specific trusted IP addresses or networks. Use out-of-band management or VPN for administrative access. Remove 0.0.0.0/0 from outside interface management configuration.",
                        affected_objects=[f"{s[0]}: {s[1]}" for s in exposed_mgmt[:3]],
                    ))
        
        # A.4.2: ASA_SNMP_WEAK_COMMUNITY (MEDIUM) - ASA only
        if raw_config_text and config_file.vendor == VendorType.CISCO_ASA:
            existing_codes = [f.code for f in findings]
            if "ASA_SNMP_WEAK_COMMUNITY" not in existing_codes:
                lines = raw_config_text.split('\n')
                weak_snmp_found = False
                weak_communities = ["public", "private", "snmp", "community"]
                
                for line in lines:
                    line_stripped = line.strip()
                    line_lower = line_stripped.lower()
                    
                    if "snmp-server community" in line_lower:
                        # Check for weak default communities
                        for weak_comm in weak_communities:
                            if f"community {weak_comm}" in line_lower:
                                weak_snmp_found = True
                                findings.append(SecurityFinding(
                                    severity="medium",
                                    code="ASA_SNMP_WEAK_COMMUNITY",
                                    description=f"SNMP is configured with weak default community string '{weak_comm}', which is easily guessable.",
                                    recommendation="Use SNMPv3 with authentication and encryption, or use strong community strings. Remove SNMP from untrusted interfaces.",
                                    affected_objects=[f"SNMP community: {line_stripped[:80]}"],
                                ))
                                break
                        if weak_snmp_found:
                            break
        
        # A.5: ASA_SHADOWED_ACL (MEDIUM) - ASA only
        if raw_config_text and config_file.vendor == VendorType.CISCO_ASA:
            existing_codes = [f.code for f in findings]
            if "ASA_SHADOWED_ACL" not in existing_codes and acls:
                # Simplified shadow rule detection
                acl_groups = {}
                for acl in acls:
                    acl_name = getattr(acl, "name", None) or ""
                    if acl_name not in acl_groups:
                        acl_groups[acl_name] = []
                    acl_groups[acl_name].append(acl)
                
                shadowed_found = False
                for acl_name, acl_list in acl_groups.items():
                    if len(acl_list) < 2:
                        continue
                    
                    # Sort by rule_number if available
                    sorted_acls = sorted(acl_list, key=lambda x: getattr(x, "rule_number", 0) or 0)
                    
                    # Check if any later rule is shadowed by an earlier "any any" rule
                    for i, later_acl in enumerate(sorted_acls[1:], 1):
                        for earlier_acl in sorted_acls[:i]:
                            earlier_src = (getattr(earlier_acl, "source", "") or "").lower()
                            earlier_dst = (getattr(earlier_acl, "destination", "") or "").lower()
                            earlier_action = (getattr(earlier_acl, "action", "") or "").lower()
                            earlier_proto = (getattr(earlier_acl, "protocol", "") or "").lower()
                            
                            later_src = (getattr(later_acl, "source", "") or "").lower()
                            later_dst = (getattr(later_acl, "destination", "") or "").lower()
                            later_proto = (getattr(later_acl, "protocol", "") or "").lower()
                            
                            # If earlier rule is "any any" with permit/deny, later rules with same protocol are shadowed
                            if (earlier_src == "any" and earlier_dst == "any" and 
                                earlier_proto == later_proto and earlier_proto in ["ip", "tcp", "udp"]):
                                shadowed_found = True
                                findings.append(SecurityFinding(
                                    severity="medium",
                                    code="ASA_SHADOWED_ACL",
                                    description=f"ACL '{acl_name}' contains shadowed rules: rule at position {i+1} is unreachable due to earlier 'any any' rule.",
                                    recommendation="Remove or reorder ACL rules so that specific rules come before general 'any any' rules. Remove unreachable shadowed rules.",
                                    affected_objects=[f"ACL: {acl_name}", f"Shadowed rule: {getattr(later_acl, 'raw_config', 'N/A')[:60]}"],
                                ))
                                break
                        if shadowed_found:
                            break
                    if shadowed_found:
                        break
        
        # A.6: ASA_UNUSED_ACL (LOW) - ASA only
        if raw_config_text and config_file.vendor == VendorType.CISCO_ASA:
            existing_codes = [f.code for f in findings]
            if "ASA_UNUSED_ACL" not in existing_codes and acls:
                # Find all ACL names
                acl_names = set()
                for acl in acls:
                    acl_name = getattr(acl, "name", None) or ""
                    if acl_name:
                        acl_names.add(acl_name.lower())
                
                # Find all ACLs referenced by access-group commands
                lines = raw_config_text.split('\n')
                used_acl_names = set()
                for line in lines:
                    line_lower = line.strip().lower()
                    # access-group <acl_name> in interface <iface>
                    # access-group <acl_name> out interface <iface>
                    if "access-group" in line_lower:
                        parts = line_lower.split()
                        try:
                            acl_idx = parts.index("access-group")
                            if acl_idx + 1 < len(parts):
                                used_acl_names.add(parts[acl_idx + 1].lower())
                        except ValueError:
                            pass
                
                # Find unused ACLs
                unused_acls = acl_names - used_acl_names
                if unused_acls:
                    unused_list = list(unused_acls)[:5]  # Limit to first 5
                    findings.append(SecurityFinding(
                        severity="low",
                        code="ASA_UNUSED_ACL",
                        description=f"ACL(s) {', '.join(unused_list)} are defined but not applied to any interface via access-group.",
                        recommendation="Apply unused ACLs to appropriate interfaces using 'access-group <acl_name> in|out interface <iface>', or remove if no longer needed.",
                        affected_objects=[f"Unused ACL: {name}" for name in unused_list],
                    ))
        
        # A.7: ASA_OVERLAPPING_ACL (LOW) - ASA only
        if raw_config_text and config_file.vendor == VendorType.CISCO_ASA:
            existing_codes = [f.code for f in findings]
            if "ASA_OVERLAPPING_ACL" not in existing_codes and acls:
                # Group ACLs by name
                acl_groups = {}
                for acl in acls:
                    acl_name = getattr(acl, "name", None) or ""
                    if acl_name not in acl_groups:
                        acl_groups[acl_name] = []
                    acl_groups[acl_name].append(acl)
                
                overlapping_found = False
                for acl_name, acl_list in acl_groups.items():
                    if len(acl_list) < 2:
                        continue
                    
                    # Check for duplicate or very similar rules (same src/dst/proto/port)
                    seen_rules = {}
                    for acl in acl_list:
                        src = (getattr(acl, "source", "") or "").lower()
                        dst = (getattr(acl, "destination", "") or "").lower()
                        proto = (getattr(acl, "protocol", "") or "").lower()
                        port = (getattr(acl, "port", "") or "").lower()
                        action = (getattr(acl, "action", "") or "").lower()
                        
                        rule_key = (src, dst, proto, port, action)
                        if rule_key in seen_rules:
                            overlapping_found = True
                            findings.append(SecurityFinding(
                                severity="low",
                                code="ASA_OVERLAPPING_ACL",
                                description=f"ACL '{acl_name}' contains duplicate or overlapping rules with identical source, destination, protocol, and port conditions.",
                                recommendation="Consolidate duplicate rules. Remove redundant ACL entries to improve performance and maintainability.",
                                affected_objects=[f"ACL: {acl_name}", f"Overlapping rule: {getattr(acl, 'raw_config', 'N/A')[:60]}"],
                            ))
                            break
                        seen_rules[rule_key] = acl
                    if overlapping_found:
                        break
        
        # ========== END PHASE A CHECKS ==========
        
        # ========== PHASE D: ADDITIONAL SECURITY RULES ==========
        
        # D.1: Vendor-Agnostic Rules
        
        # MGMT_WEAK_PASSWORD_AUTH (HIGH)
        if raw_config_text:
            existing_codes = [f.code for f in findings]
            if "MGMT_WEAK_PASSWORD_AUTH" not in existing_codes:
                weak_auth_found = False
                
                # IOS: line vty with login but no transport input ssh / or password without AAA
                if vendor == "cisco_ios":
                    if "line vty" in combined_text:
                        lines = raw_config_text.split('\n')
                        in_vty = False
                        has_login = False
                        has_ssh_transport = False
                        has_aaa = False
                        
                        for line in lines:
                            line_lower = line.strip().lower()
                            if "line vty" in line_lower:
                                in_vty = True
                                has_login = False
                                has_ssh_transport = False
                                has_aaa = False
                            elif in_vty:
                                if "login" in line_lower and "no login" not in line_lower:
                                    has_login = True
                                if "transport input ssh" in line_lower or "transport input telnet ssh" in line_lower:
                                    has_ssh_transport = True
                                if "aaa authentication" in line_lower or "aaa authorization" in line_lower:
                                    has_aaa = True
                                if line_lower and not line_lower.startswith(' ') and not line_lower.startswith('\t'):
                                    if "line" not in line_lower:
                                        # End of vty block
                                        if has_login and not has_ssh_transport and not has_aaa:
                                            weak_auth_found = True
                                            break
                                        in_vty = False
                
                # Fortinet: set admin-auth weak or default
                elif vendor == "fortinet":
                    if ('set admin-auth weak' in combined_text or
                        'set admin-auth default' in combined_text):
                        weak_auth_found = True
                
                if weak_auth_found:
                    findings.append(SecurityFinding(
                        severity="high",
                        code="MGMT_WEAK_PASSWORD_AUTH",
                        description="Management access allows password-only authentication without key-based auth or AAA enforcement.",
                        recommendation="Enable key-based authentication (SSH keys) and enforce AAA (Authentication, Authorization, Accounting) for all management access. Disable password-only authentication.",
                        affected_objects=["Management access configuration"],
                    ))
        
        # PUBLIC_MGMT_INTERFACE (CRITICAL)
        if raw_config_text:
            existing_codes = [f.code for f in findings]
            if "PUBLIC_MGMT_INTERFACE" not in existing_codes:
                public_mgmt_found = False
                
                # Check if management is allowed on public-facing interfaces
                # ASA/IOS: SSH/HTTP on outside interface or interface with public IP
                if vendor in ["cisco_asa", "cisco_ios"]:
                    # Check for SSH/HTTP/Telnet on outside interface
                    mgmt_patterns = ["ssh", "http", "https", "telnet"]
                    outside_patterns = ["outside", "external", "internet"]
                    
                    for mgmt in mgmt_patterns:
                        for outside in outside_patterns:
                            if f"{mgmt} 0.0.0.0 0.0.0.0 {outside}" in combined_text:
                                public_mgmt_found = True
                                break
                        if public_mgmt_found:
                            break
                    
                    # Also check interfaces with public IPs
                    for interface in interfaces:
                        if interface.ip_address and not self._is_private_ip(interface.ip_address):
                            # Public IP interface - check if management is enabled
                            interface_name_lower = interface.name.lower()
                            for mgmt in mgmt_patterns:
                                if f"{mgmt}" in combined_text and interface_name_lower in combined_text:
                                    # Simple heuristic - if management command references this interface
                                    public_mgmt_found = True
                                    break
                            if public_mgmt_found:
                                break
                
                # Fortinet/Palo: similar logic via management objects
                elif vendor in ["fortinet", "palo_alto"]:
                    # Check for management on public interfaces
                    if ("config system admin" in combined_text or
                        "set mgmt-interface" in combined_text):
                        # Check if management interface has public IP
                        for interface in interfaces:
                            if interface.ip_address and not self._is_private_ip(interface.ip_address):
                                if interface.name.lower() in combined_text:
                                    public_mgmt_found = True
                                    break
                
                if public_mgmt_found:
                    findings.append(SecurityFinding(
                        severity="critical",
                        code="PUBLIC_MGMT_INTERFACE",
                        description="Management interface is reachable from public networks, exposing administrative access to the internet.",
                        recommendation="Restrict management access to VPN, out-of-band networks, or specific trusted IP addresses. Never expose management interfaces to public networks.",
                        affected_objects=["Management interface configuration"],
                    ))
        
        # D.2: Vendor-Specific Rules
        
        # ASA: ASA_INSECURE_SERVICE_OBJECT (MEDIUM)
        if raw_config_text and config_file.vendor == VendorType.CISCO_ASA:
            existing_codes = [f.code for f in findings]
            if "ASA_INSECURE_SERVICE_OBJECT" not in existing_codes:
                insecure_services = []
                insecure_ports = ["telnet", "http", "23", "80"]
                
                # Check for service-objects or object-groups using insecure ports
                lines = raw_config_text.split('\n')
                in_service_object = False
                current_service = None
                
                for line in lines:
                    line_lower = line.strip().lower()
                    if "service-object" in line_lower or "object-group service" in line_lower:
                        in_service_object = True
                        # Check for insecure ports
                        for port in insecure_ports:
                            if port in line_lower:
                                if current_service not in insecure_services:
                                    insecure_services.append(current_service or "service-object")
                                break
                    elif in_service_object and line_lower and not (line_lower.startswith(' ') or line_lower.startswith('\t')):
                        in_service_object = False
                        current_service = None
                
                if insecure_services:
                    findings.append(SecurityFinding(
                        severity="medium",
                        code="ASA_INSECURE_SERVICE_OBJECT",
                        description=f"Service objects or object-groups reference insecure ports (Telnet, HTTP) that should be replaced with secure alternatives.",
                        recommendation="Replace Telnet with SSH, HTTP with HTTPS. Use secure protocols for all management and data transmission.",
                        affected_objects=insecure_services[:5],  # Limit to first 5
                    ))
        
        # IOS: IOS_NO_LOGGING_BUFFERED (LOW/MEDIUM)
        if vendor == "cisco_ios":
            existing_codes = [f.code for f in findings]
            if "IOS_NO_LOGGING_BUFFERED" not in existing_codes:
                has_logging = False
                
                if raw_config_text:
                    # Check for logging configuration
                    if ("logging buffered" in combined_text or
                        "logging host" in combined_text or
                        "logging trap" in combined_text):
                        has_logging = True
                
                if not has_logging:
                    findings.append(SecurityFinding(
                        severity="medium",
                        code="IOS_NO_LOGGING_BUFFERED",
                        description="No logging configuration detected. This reduces observability and makes incident response difficult.",
                        recommendation="Configure logging: 'logging buffered <size>' for local logs and 'logging host <ip>' for syslog server. Enable appropriate log levels.",
                        affected_objects=["Logging configuration"],
                    ))
        
        # Fortinet: FGT_UNUSED_ADDRESS_OBJECTS (LOW)
        if vendor == "fortinet":
            existing_codes = [f.code for f in findings]
            if "FGT_UNUSED_ADDRESS_OBJECTS" not in existing_codes:
                # Simple heuristic: find address objects and check if referenced in policies
                if "config firewall address" in combined_text:
                    lines = raw_config_text.split('\n')
                    address_objects = []
                    in_address_config = False
                    current_object = None
                    
                    for line in lines:
                        line_lower = line.strip().lower()
                        if "config firewall address" in line_lower:
                            in_address_config = True
                        elif in_address_config and line_lower.startswith("edit "):
                            # Extract object name
                            parts = line_lower.split()
                            if len(parts) > 1:
                                current_object = parts[1].strip('"')
                        elif in_address_config and line_lower == "next":
                            if current_object:
                                address_objects.append(current_object)
                                current_object = None
                        elif in_address_config and line_lower.startswith("end"):
                            in_address_config = False
                    
                    # Check if objects are used in policies
                    unused_objects = []
                    for obj in address_objects[:10]:  # Limit check to first 10
                        # Check if object is referenced in firewall policies
                        if obj and f'"{obj}"' not in combined_text and f" {obj} " not in combined_text:
                            # Not found in policy context - might be unused
                            unused_objects.append(obj)
                    
                    if unused_objects:
                        findings.append(SecurityFinding(
                            severity="low",
                            code="FGT_UNUSED_ADDRESS_OBJECTS",
                            description=f"Address objects {', '.join(unused_objects[:5])} are defined but may not be referenced in firewall policies.",
                            recommendation="Review and remove unused address objects to reduce configuration complexity. Ensure all defined objects are used in policies.",
                            affected_objects=unused_objects[:5],
                        ))
        
        # Palo Alto: PA_ZONE_MISMATCH (MEDIUM)
        if vendor == "palo_alto":
            existing_codes = [f.code for f in findings]
            if "PA_ZONE_MISMATCH" not in existing_codes:
                # Simple heuristic: rules with internal zone to untrusted with broad access
                if ("rulebase security" in combined_text and
                    "source-zone" in combined_text and
                    "destination-zone" in combined_text):
                    lines = raw_config_text.split('\n')
                    suspicious_rules = []
                    
                    for i, line in enumerate(lines):
                        line_lower = line.strip().lower()
                        if "source-zone" in line_lower:
                            # Check next few lines for destination-zone and action
                            for j in range(i, min(i+5, len(lines))):
                                next_line_lower = lines[j].strip().lower()
                                if "destination-zone untrusted" in next_line_lower or "destination-zone dmz" in next_line_lower:
                                    # Check for action allow
                                    for k in range(j, min(j+3, len(lines))):
                                        if "action allow" in lines[k].strip().lower():
                                            suspicious_rules.append(f"Rule around line {i+1}")
                                            break
                                    break
                    
                    if suspicious_rules:
                        findings.append(SecurityFinding(
                            severity="medium",
                            code="PA_ZONE_MISMATCH",
                            description=f"Security rules may have zone mismatches: internal zones allowing traffic to untrusted/DMZ zones with broad access.",
                            recommendation="Review zone assignments and ensure rules follow the principle of least privilege. Verify that internal-to-untrusted rules are properly scoped.",
                            affected_objects=suspicious_rules[:3],
                        ))
        
        # ========== PHASE D CONTINUED: GENERIC ENTERPRISE RULES ==========
        
        # GEN_SHADOWED_RULE (MEDIUM) - Generic shadowed rule detection
        # Only run if vendor-specific shadowed rule didn't already catch it
        if raw_config_text and acls:
            existing_codes = [f.code for f in findings]
            # Skip if ASA_SHADOWED_ACL already found it (ASA-specific)
            if "GEN_SHADOWED_RULE" not in existing_codes and "ASA_SHADOWED_ACL" not in existing_codes:
                # Group ACLs by name/interface
                acl_groups = {}
                for acl in acls:
                    acl_name = getattr(acl, "name", None) or getattr(acl, "interface", None) or "default"
                    if acl_name not in acl_groups:
                        acl_groups[acl_name] = []
                    acl_groups[acl_name].append(acl)
                
                shadowed_found = False
                for acl_name, acl_list in acl_groups.items():
                    if len(acl_list) < 2:
                        continue
                    
                    # Sort by rule_number or sequence
                    sorted_acls = sorted(acl_list, key=lambda x: getattr(x, "rule_number", 0) or getattr(x, "id", 0))
                    
                    # Check if any later rule is shadowed by an earlier broad rule
                    for i, later_acl in enumerate(sorted_acls[1:], 1):
                        for earlier_acl in sorted_acls[:i]:
                            earlier_src = (getattr(earlier_acl, "source", "") or "").lower()
                            earlier_dst = (getattr(earlier_acl, "destination", "") or "").lower()
                            earlier_action = (getattr(earlier_acl, "action", "") or "").lower()
                            
                            later_src = (getattr(later_acl, "source", "") or "").lower()
                            later_dst = (getattr(later_acl, "destination", "") or "").lower()
                            
                            # If earlier rule is "any any" with permit, later more specific rules are shadowed
                            if (earlier_src == "any" and earlier_dst == "any" and 
                                earlier_action in ["permit", "allow"]):
                                # Later rule is shadowed if it's more specific (not "any any")
                                if later_src != "any" or later_dst != "any":
                                    shadowed_found = True
                                    findings.append(SecurityFinding(
                                        severity="medium",
                                        code="GEN_SHADOWED_RULE",
                                        description=f"ACL '{acl_name}' contains shadowed rules: rule at position {i+1} is unreachable due to earlier 'any any' permit rule.",
                                        recommendation="Reorder ACL rules so that specific rules come before general 'any any' rules. Remove unreachable shadowed rules.",
                                        affected_objects=[f"ACL: {acl_name}", f"Shadowed rule: {getattr(later_acl, 'raw_config', 'N/A')[:60]}"],
                                    ))
                                    break
                        if shadowed_found:
                            break
                    if shadowed_found:
                        break
        
        # GEN_OVERLAPPING_ACL (MEDIUM) - Generic overlapping rule detection
        if raw_config_text and acls:
            existing_codes = [f.code for f in findings]
            if "GEN_OVERLAPPING_ACL" not in existing_codes:
                # Group ACLs by name
                acl_groups = {}
                for acl in acls:
                    acl_name = getattr(acl, "name", None) or "default"
                    if acl_name not in acl_groups:
                        acl_groups[acl_name] = []
                    acl_groups[acl_name].append(acl)
                
                overlapping_found = False
                for acl_name, acl_list in acl_groups.items():
                    if len(acl_list) < 2:
                        continue
                    
                    # Check for duplicate or very similar rules
                    seen_rules = {}
                    for acl in acl_list:
                        src = (getattr(acl, "source", "") or "").lower()
                        dst = (getattr(acl, "destination", "") or "").lower()
                        proto = (getattr(acl, "protocol", "") or "").lower()
                        port = (getattr(acl, "port", "") or "").lower()
                        action = (getattr(acl, "action", "") or "").lower()
                        
                        rule_key = (src, dst, proto, port, action)
                        if rule_key in seen_rules:
                            overlapping_found = True
                            findings.append(SecurityFinding(
                                severity="medium",
                                code="GEN_OVERLAPPING_ACL",
                                description=f"ACL '{acl_name}' contains duplicate or overlapping rules with identical source, destination, protocol, and port conditions.",
                                recommendation="Consolidate duplicate rules. Remove redundant ACL entries to improve performance and maintainability.",
                                affected_objects=[f"ACL: {acl_name}", f"Overlapping rule: {getattr(acl, 'raw_config', 'N/A')[:60]}"],
                            ))
                            break
                        seen_rules[rule_key] = acl
                    if overlapping_found:
                        break
        
        # GEN_UNUSED_OBJECT (LOW) - Generic unused object detection
        if raw_config_text:
            existing_codes = [f.code for f in findings]
            if "GEN_UNUSED_OBJECT" not in existing_codes:
                unused_objects = []
                
                # ASA: Check for unused object-groups
                if vendor == "cisco_asa" and "object-group" in combined_text:
                    lines = raw_config_text.split('\n')
                    object_groups = []
                    current_group = None
                    
                    for line in lines:
                        line_lower = line.strip().lower()
                        if line_lower.startswith("object-group"):
                            parts = line_lower.split()
                            if len(parts) >= 3:
                                current_group = parts[2]
                                object_groups.append(current_group)
                        elif line_lower and not (line_lower.startswith(' ') or line_lower.startswith('\t')):
                            current_group = None
                    
                    # Check if object-groups are referenced in ACLs
                    for group in object_groups[:10]:  # Limit check
                        if group and f"object-group {group}" not in combined_text.replace(f"object-group {group}", "", 1):
                            # Check if referenced elsewhere
                            if group not in combined_text.replace(f"object-group {group}", "", 1):
                                unused_objects.append(f"object-group: {group}")
                
                # Fortinet/Palo: Similar logic for address objects
                elif vendor in ["fortinet", "palo_alto"]:
                    # Already handled in vendor-specific rules above
                    pass
                
                if unused_objects:
                    findings.append(SecurityFinding(
                        severity="low",
                        code="GEN_UNUSED_OBJECT",
                        description=f"Unused objects detected: {', '.join(unused_objects[:5])}. These may indicate configuration drift or abandoned changes.",
                        recommendation="Review and remove unused objects to reduce configuration complexity and potential security risks.",
                        affected_objects=unused_objects[:5],
                    ))
        
        # GEN_WEAK_CRYPTO_SUITE (HIGH) - Generic weak crypto detection
        if raw_config_text:
            existing_codes = [f.code for f in findings]
            if "GEN_WEAK_CRYPTO_SUITE" not in existing_codes:
                weak_crypto_found = False
                weak_patterns = [
                    "des", "3des", "md5", "sha1",
                    "dh group 1", "dh group 2", "dh group 5",
                    "group 1", "group 2", "group 5",
                ]
                
                # Check for weak crypto in config
                for pattern in weak_patterns:
                    if f" {pattern} " in combined_text or f" {pattern}\n" in combined_text:
                        weak_crypto_found = True
                        break
                
                if weak_crypto_found:
                    findings.append(SecurityFinding(
                        severity="high",
                        code="GEN_WEAK_CRYPTO_SUITE",
                        description="Configuration uses weak cryptographic algorithms (DES, 3DES, MD5, SHA-1) or weak Diffie-Hellman groups (1, 2, 5).",
                        recommendation="Migrate to modern crypto suites: AES-256 or AES-GCM for encryption, SHA-256+ for hashing, and DH group 14+ or ECDH for key exchange.",
                        affected_objects=["Crypto/VPN/SSL configuration"],
                    ))
        
        # GEN_NAT_MISCONFIG (HIGH) - NAT misconfiguration patterns
        if raw_config_text and nat_rules:
            existing_codes = [f.code for f in findings]
            if "GEN_NAT_MISCONFIG" not in existing_codes:
                nat_issues = []
                
                for nat in nat_rules:
                    # NAT to 0.0.0.0/0 (any)
                    if nat.destination_translated and ("0.0.0.0" in nat.destination_translated or "any" in nat.destination_translated.lower()):
                        nat_issues.append(f"NAT rule '{nat.rule_name or nat.id}' translates to 0.0.0.0/any")
                    
                    # NATting RFC1918 to public without proper ACL
                    if nat.source_original and self._is_private_network(nat.source_original):
                        if nat.source_translated and not self._is_private_network(nat.source_translated):
                            # Private to public NAT - check if there are restrictive ACLs
                            # Simple heuristic: if we have any-any rules, this is risky
                            if any("permit ip any any" in combined_text or "permit tcp any any" in combined_text for _ in [1]):
                                nat_issues.append(f"NAT rule '{nat.rule_name or nat.id}' exposes private network {nat.source_original} to public")
                
                if nat_issues:
                    findings.append(SecurityFinding(
                        severity="high",
                        code="GEN_NAT_MISCONFIG",
                        description=f"NAT misconfiguration detected: {', '.join(nat_issues[:3])}. This may expose internal networks or create routing issues.",
                        recommendation="Review NAT rules and ensure proper ACLs restrict traffic. Avoid NAT to 0.0.0.0/any. Verify private-to-public NAT has appropriate restrictions.",
                        affected_objects=nat_issues[:3],
                    ))
        
        # GEN_RFC1918_INBOUND_FROM_OUTSIDE (CRITICAL) - Inbound allow to RFC1918 from outside
        if raw_config_text and acls:
            existing_codes = [f.code for f in findings]
            if "GEN_RFC1918_INBOUND_FROM_OUTSIDE" not in existing_codes:
                rfc1918_inbound_found = False
                
                # Check ACLs for inbound rules allowing RFC1918 from outside
                for acl in acls:
                    acl_direction = (getattr(acl, "direction", "") or "").lower()
                    acl_action = (getattr(acl, "action", "") or "").lower()
                    acl_dst = (getattr(acl, "destination", "") or "")
                    
                    # Check if this is an inbound rule (in/inside direction)
                    if acl_direction in ["in", "inbound", "inside"] and acl_action in ["permit", "allow"]:
                        # Check if destination is RFC1918
                        if acl_dst and self._is_private_network(acl_dst):
                            # Check if source is outside/public
                            acl_src = (getattr(acl, "source", "") or "").lower()
                            if acl_src in ["any", "0.0.0.0/0"] or (acl_src and not self._is_private_network(acl_src)):
                                rfc1918_inbound_found = True
                                findings.append(SecurityFinding(
                                    severity="critical",
                                    code="GEN_RFC1918_INBOUND_FROM_OUTSIDE",
                                    description=f"Inbound ACL rule allows traffic to private network {acl_dst} from outside/public source {acl_src}. This exposes internal resources to the internet.",
                                    recommendation="Remove or restrict inbound rules allowing access to RFC1918 addresses from outside. Use VPN or out-of-band management instead.",
                                    affected_objects=[f"ACL: {getattr(acl, 'name', 'unnamed')}", f"Rule: {getattr(acl, 'raw_config', 'N/A')[:60]}"],
                                ))
                                break
                
                # Also check raw config for patterns
                if not rfc1918_inbound_found and raw_config_text:
                    # Look for permit rules with private IPs as destination
                    lines = raw_config_text.split('\n')
                    for line in lines:
                        line_lower = line.strip().lower()
                        if ("permit" in line_lower or "allow" in line_lower) and "access-list" in line_lower:
                            # Check for private IP patterns
                            import re
                            private_patterns = [
                                r"10\.\d+\.\d+\.\d+",
                                r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+",
                                r"192\.168\.\d+\.\d+",
                            ]
                            for pattern in private_patterns:
                                if re.search(pattern, line):
                                    # Check if source is any/outside
                                    if "any" in line_lower or "0.0.0.0" in line_lower:
                                        rfc1918_inbound_found = True
                                        findings.append(SecurityFinding(
                                            severity="critical",
                                            code="GEN_RFC1918_INBOUND_FROM_OUTSIDE",
                                            description="Inbound ACL rule allows traffic to private network from outside/public source (any/0.0.0.0). This exposes internal resources to the internet.",
                                            recommendation="Remove or restrict inbound rules allowing access to RFC1918 addresses from outside. Use VPN or out-of-band management instead.",
                                            affected_objects=[f"Config line: {line[:60]}"],
                                        ))
                                        break
                            if rfc1918_inbound_found:
                                break
        
        # ========== END PHASE D CHECKS ==========
        
        # Evaluate custom rules from database
        custom_findings = self._evaluate_custom_rules(config_file, acls, nat_rules, routes, interfaces, raw_config_text)
        findings.extend(custom_findings)
        
        return findings
    
    def _run_ai_analysis(
        self,
        config_text: str,
        vendor: str,
        rule_based_summary: Dict[str, Any],
        existing_findings: List[SecurityFinding],
    ) -> Dict[str, Any]:
        """
        Run AI analysis on configuration using OpenAI.
        
        Args:
            config_text: Raw configuration text (may be truncated)
            vendor: Vendor type
            rule_based_summary: Summary of rule-based findings
            existing_findings: List of existing rule-based findings
            
        Returns:
            Dictionary with 'summary' and 'additional_findings' keys
        """
        if not settings.is_openai_available():
            return {"summary": "", "additional_findings": []}
        
        try:
            from openai import OpenAI
            
            client = OpenAI(api_key=settings.OPENAI_API_KEY)
            
            # Truncate config text if too long (keep first 8000 chars for context)
            config_truncated = config_text[:8000] if len(config_text) > 8000 else config_text
            if len(config_text) > 8000:
                config_truncated += "\n... (truncated)"
            
            # Build rule-based summary
            severity_counts = {
                "critical": sum(1 for f in existing_findings if f.severity == "critical"),
                "high": sum(1 for f in existing_findings if f.severity == "high"),
                "medium": sum(1 for f in existing_findings if f.severity == "medium"),
                "low": sum(1 for f in existing_findings if f.severity == "low"),
            }
            finding_codes = [f.code for f in existing_findings[:10]]  # First 10 codes
            
            # Prepare prompt
            prompt = f"""You are a network security expert analyzing a {vendor} firewall/router configuration.

Rule-based analysis has already identified the following:
- Critical findings: {severity_counts['critical']}
- High findings: {severity_counts['high']}
- Medium findings: {severity_counts['medium']}
- Low findings: {severity_counts['low']}
- Finding codes: {', '.join(finding_codes) if finding_codes else 'None'}

Configuration (truncated):
```
{config_truncated}
```

Analyze this configuration and provide:
1. A 1-2 paragraph summary of overall security posture
2. Additional security findings that the rule-based engine may have missed

Return JSON in this exact format:
{{
    "summary": "1-2 paragraph summary of security posture...",
    "additional_findings": [
        {{
            "severity": "critical|high|medium|low",
            "code": "AI_SUGGESTED_<DESCRIPTION>",
            "description": "Detailed description of the issue",
            "recommendation": "Recommended remediation steps",
            "affected_objects": ["object1", "object2"]
        }}
    ]
}}

Focus on:
- Advanced attack vectors
- Configuration inconsistencies
- Best practices not covered by rules
- Vendor-specific security considerations
- Compliance and governance issues
"""
            
            response = client.chat.completions.create(
                model=settings.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a network security expert. Always return valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                response_format={"type": "json_object"} if hasattr(client.chat.completions, "create") else None,
            )
            
            import json
            content = response.choices[0].message.content
            
            # Parse JSON response
            try:
                ai_data = json.loads(content)
            except json.JSONDecodeError:
                # Try to extract JSON from markdown code blocks
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    ai_data = json.loads(content[json_start:json_end])
                else:
                    logger.warning("AI response did not contain valid JSON")
                    return {"summary": "", "additional_findings": []}
            
            return {
                "summary": ai_data.get("summary", ""),
                "additional_findings": ai_data.get("additional_findings", [])
            }
        except Exception as e:
            logger.error(f"AI analysis error: {e}", exc_info=True)
            return {"summary": "", "additional_findings": []}
    
    def _get_ai_findings(
        self,
        config_file: ConfigFile,
        acls: List[ACL],
        nat_rules: List[NATRule],
        vpns: List[VPN],
    ) -> List[SecurityFinding]:
        """
        Get AI-powered security findings using OpenAI.
        
        This method should only be called if OPENAI_API_KEY is configured.
        Uses the enhanced _run_ai_analysis method.
        
        Args:
            config_file: Configuration file model
            acls: List of ACLs
            nat_rules: List of NAT rules
            vpns: List of VPNs
            
        Returns:
            List of SecurityFinding objects from AI analysis
        """
        if not settings.is_openai_available():
            return []
        
        try:
            # Read raw config text
            from pathlib import Path
            raw_config_text = ""
            try:
                config_path = Path(config_file.file_path)
                if config_path.exists():
                    raw_config_text = config_path.read_text(encoding='utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"Could not read config file for AI analysis: {e}")
                return []
            
            # Get rule-based findings summary (will be passed to AI)
            # Note: This is called before rule-based findings are complete, so we pass empty list
            # In practice, AI analysis happens after rule-based, so this is a placeholder
            rule_summary = {
                "acls_count": len(acls),
                "nat_rules_count": len(nat_rules),
                "vpns_count": len(vpns),
            }
            
            # Run AI analysis
            ai_result = self._run_ai_analysis(
                config_text=raw_config_text,
                vendor=config_file.vendor.value,
                rule_based_summary=rule_summary,
                existing_findings=[],  # Will be populated in audit_config method
            )
            
            # Convert AI findings to SecurityFinding objects
            findings = []
            for finding_data in ai_result.get("additional_findings", []):
                try:
                    findings.append(SecurityFinding(
                        severity=finding_data.get("severity", "low"),
                        code=finding_data.get("code", "AI_SUGGESTED_ISSUE"),
                        description=finding_data.get("description", "AI-identified security concern"),
                        recommendation=finding_data.get("recommendation", "Review and remediate"),
                        affected_objects=finding_data.get("affected_objects", []),
                    ))
                except Exception as e:
                    logger.warning(f"Failed to create SecurityFinding from AI data: {e}")
            
            return findings
        except Exception as e:
            logger.error(f"AI analysis error: {e}", exc_info=True)
        
        return []
    
    # Severity weights for risk scoring (additive, max 100)
    SEVERITY_WEIGHTS = {
        "critical": 40,
        "high": 25,
        "medium": 15,
        "low": 5,
    }
    
    def _calculate_risk_score(self, findings: List[SecurityFinding]) -> int:
        """
        Calculate overall risk score (0-100) based on findings using severity weights.
        
        Args:
            findings: List of SecurityFinding objects
            
        Returns:
            Risk score (0-100), capped at 100
        """
        score = 0
        for finding in findings:
            severity = finding.severity if isinstance(finding, SecurityFinding) else finding.get("severity", "low")
            weight = self.SEVERITY_WEIGHTS.get(severity.lower(), 0)
            score += weight
        
        return min(score, 100)
    
    def _calculate_breakdown(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """
        Calculate breakdown of findings by severity.
        
        Args:
            findings: List of SecurityFinding objects
            
        Returns:
            Dictionary with counts for each severity level
        """
        breakdown = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        
        for finding in findings:
            severity = finding.severity if isinstance(finding, SecurityFinding) else finding.get("severity", "low")
            severity_lower = severity.lower()
            if severity_lower in breakdown:
                breakdown[severity_lower] += 1
        
        return breakdown
    
    def _generate_summary(self, findings: List[SecurityFinding], risk_score: int) -> str:
        """Generate human-readable summary of audit results."""
        if not findings:
            return "No security issues detected. Configuration appears secure."
        
        critical_count = sum(1 for f in findings if (f.severity if isinstance(f, SecurityFinding) else f.get("severity")) == "critical")
        high_count = sum(1 for f in findings if (f.severity if isinstance(f, SecurityFinding) else f.get("severity")) == "high")
        medium_count = sum(1 for f in findings if (f.severity if isinstance(f, SecurityFinding) else f.get("severity")) == "medium")
        
        parts = []
        if critical_count > 0:
            parts.append(f"{critical_count} critical")
        if high_count > 0:
            parts.append(f"{high_count} high")
        if medium_count > 0:
            parts.append(f"{medium_count} medium")
        
        severity_str = ", ".join(parts) if parts else "low"
        return f"Found {len(findings)} security finding(s) ({severity_str} severity). Risk score: {risk_score}/100."
    
    def _is_private_network(self, network_str: str) -> bool:
        """Check if a network string represents a private network."""
        try:
            # Handle CIDR notation
            if '/' in network_str:
                net = ipaddress.ip_network(network_str, strict=False)
            else:
                # Try as IP address
                ip = ipaddress.ip_address(network_str)
                # Check if it's in private ranges
                for private_net in self.PRIVATE_NETWORKS:
                    if ip in private_net:
                        return True
                return False
            
            # Check if network overlaps with private ranges
            for private_net in self.PRIVATE_NETWORKS:
                if net.overlaps(private_net):
                    return True
            return False
        except (ValueError, ipaddress.AddressValueError):
            # If parsing fails, assume it's not a private network format we recognize
            return False
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if an IP address is private."""
        try:
            ip = ipaddress.ip_address(ip_str.split('/')[0])  # Handle CIDR if present
            for private_net in self.PRIVATE_NETWORKS:
                if ip in private_net:
                    return True
            return False
        except (ValueError, ipaddress.AddressValueError):
            return False
    
    def _evaluate_custom_rules(
        self,
        config_file: ConfigFile,
        acls: List[ACL],
        nat_rules: List[NATRule],
        routes: List[Route],
        interfaces: List[Interface],
        raw_config_text: str,
    ) -> List[SecurityFinding]:
        """
        Evaluate custom rules from database against the configuration.
        
        Returns list of SecurityFinding objects for matching rules.
        """
        findings = []
        
        try:
            # Load enabled rules that match this vendor (or are vendor-agnostic)
            vendor_str = config_file.vendor.value if config_file.vendor else None
            query = self.db.query(Rule).filter(Rule.enabled == True)
            
            # Filter by vendor if rule specifies one, or include vendor-agnostic rules
            if vendor_str:
                query = query.filter(
                    (Rule.vendor == vendor_str) | (Rule.vendor.is_(None))
                )
            else:
                query = query.filter(Rule.vendor.is_(None))
            
            custom_rules = query.all()
            
            for rule in custom_rules:
                try:
                    if self._rule_matches(rule, config_file, acls, nat_rules, routes, interfaces, raw_config_text):
                        findings.append(
                            SecurityFinding(
                                severity=rule.severity.value,
                                code=f"CUSTOM_RULE_{rule.id}",
                                description=rule.description or f"Custom rule violation: {rule.name}",
                                recommendation=f"Review and fix configuration to comply with rule: {rule.name}",
                                affected_objects=[f"Rule: {rule.name}"],
                            )
                        )
                except Exception as e:
                    logger.warning(f"Error evaluating custom rule {rule.id} ({rule.name}): {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error loading custom rules: {e}", exc_info=True)
        
        return findings
    
    def _rule_matches(
        self,
        rule: Rule,
        config_file: ConfigFile,
        acls: List[ACL],
        nat_rules: List[NATRule],
        routes: List[Route],
        interfaces: List[Interface],
        raw_config_text: str,
    ) -> bool:
        """
        Check if a custom rule matches the configuration.
        
        Returns True if the rule matches (violation detected).
        """
        match_criteria = rule.match_criteria or {}
        raw_lower = (raw_config_text or "").lower()
        
        # Pattern matching (most common)
        pattern = match_criteria.get("pattern")
        pattern_type = match_criteria.get("pattern_type", "contains")
        
        if pattern:
            pattern_lower = pattern.lower()
            if pattern_type == "contains":
                if pattern_lower in raw_lower:
                    return True
            elif pattern_type == "equals":
                if pattern_lower == raw_lower.strip():
                    return True
            elif pattern_type == "starts_with":
                if raw_lower.startswith(pattern_lower):
                    return True
            elif pattern_type == "ends_with":
                if raw_lower.endswith(pattern_lower):
                    return True
            elif pattern_type == "regex":
                import re
                try:
                    if re.search(pattern, raw_lower, re.IGNORECASE):
                        return True
                except re.error:
                    logger.warning(f"Invalid regex pattern in rule {rule.id}: {pattern}")
        
        # ACL-specific matching
        acl_source = match_criteria.get("acl_source")
        acl_destination = match_criteria.get("acl_destination")
        acl_protocol = match_criteria.get("acl_protocol")
        acl_action = match_criteria.get("acl_action")
        
        if acl_source or acl_destination or acl_protocol or acl_action:
            for acl in acls:
                # Simple matching - can be enhanced
                if acl_action and acl_action.lower() not in str(acl.action or "").lower():
                    continue
                if acl_protocol and acl_protocol.lower() not in str(acl.protocol or "").lower():
                    continue
                if acl_source and acl_source.lower() not in str(acl.source or "").lower():
                    continue
                if acl_destination and acl_destination.lower() not in str(acl.destination or "").lower():
                    continue
                # If we get here, all specified criteria match
                return True
        
        # NAT-specific matching
        nat_source = match_criteria.get("nat_source")
        nat_destination = match_criteria.get("nat_destination")
        
        if nat_source or nat_destination:
            for nat in nat_rules:
                if nat_source and nat_source.lower() not in str(nat.source or "").lower():
                    continue
                if nat_destination and nat_destination.lower() not in str(nat.destination or "").lower():
                    continue
                return True
        
        # Interface-specific matching
        interface_name = match_criteria.get("interface_name")
        interface_type = match_criteria.get("interface_type")
        
        if interface_name or interface_type:
            for interface in interfaces:
                if interface_name and interface_name.lower() not in str(interface.name or "").lower():
                    continue
                if interface_type and interface_type.lower() not in str(interface.interface_type or "").lower():
                    continue
                return True
        
        # Default: if no specific criteria match, return False
        return False
    
    def _analyze_policy_hygiene(
        self,
        config_file: ConfigFile,
        acls: List[ACL],
        nat_rules: List[NATRule],
        routes: List[Route],
        interfaces: List[Interface],
    ) -> Dict[str, Any]:
        """
        Analyze policy hygiene and return metrics.
        
        Detects:
        - Redundant rules (duplicate rules)
        - Shadowed rules (rules that can never be reached)
        - Unused/disabled objects
        - Unreferenced groups
        
        Returns:
            Dictionary with hygiene metrics
        """
        metrics = {
            "redundant_rules": 0,
            "shadowed_rules": 0,
            "unused_objects": 0,
            "unreferenced_groups": 0,
            "total_rules": len(acls),
            "details": [],
        }
        
        if not acls:
            return metrics
        
        # Group ACLs by name for analysis
        acl_groups = {}
        for acl in acls:
            acl_name = acl.name or "default"
            if acl_name not in acl_groups:
                acl_groups[acl_name] = []
            acl_groups[acl_name].append(acl)
        
        # Analyze each ACL group
        for acl_name, acl_list in acl_groups.items():
            if len(acl_list) < 2:
                continue
            
            # Sort by rule_number if available
            sorted_acls = sorted(acl_list, key=lambda x: getattr(x, "rule_number", 0) or 0)
            
            # 1. Detect redundant rules (exact duplicates)
            seen_rules = set()
            for acl in sorted_acls:
                rule_key = (
                    str(acl.source or "").lower(),
                    str(acl.destination or "").lower(),
                    str(acl.protocol or "").lower(),
                    str(acl.port or "").lower(),
                    str(acl.action or "").lower(),
                )
                if rule_key in seen_rules:
                    metrics["redundant_rules"] += 1
                    metrics["details"].append({
                        "type": "redundant",
                        "acl": acl_name,
                        "rule": getattr(acl, "raw_config", "N/A")[:60] if hasattr(acl, "raw_config") else "N/A",
                    })
                else:
                    seen_rules.add(rule_key)
            
            # 2. Detect shadowed rules (rules that can never be reached)
            for i, later_acl in enumerate(sorted_acls[1:], 1):
                for earlier_acl in sorted_acls[:i]:
                    earlier_src = (getattr(earlier_acl, "source", "") or "").lower()
                    earlier_dst = (getattr(earlier_acl, "destination", "") or "").lower()
                    earlier_proto = (getattr(earlier_acl, "protocol", "") or "").lower()
                    earlier_action = (getattr(earlier_acl, "action", "") or "").lower()
                    
                    later_src = (getattr(later_acl, "source", "") or "").lower()
                    later_dst = (getattr(later_acl, "destination", "") or "").lower()
                    later_proto = (getattr(later_acl, "protocol", "") or "").lower()
                    
                    # Check if earlier rule shadows later rule
                    # Shadowing occurs when earlier rule matches everything later rule matches
                    if earlier_action == "permit" and earlier_proto in ["ip", "tcp", "udp"]:
                        # If earlier is "any any" and protocols match, later is shadowed
                        if (earlier_src == "any" and earlier_dst == "any" and 
                            earlier_proto == later_proto):
                            metrics["shadowed_rules"] += 1
                            metrics["details"].append({
                                "type": "shadowed",
                                "acl": acl_name,
                                "rule": getattr(later_acl, "raw_config", "N/A")[:60] if hasattr(later_acl, "raw_config") else "N/A",
                                "shadowed_by": getattr(earlier_acl, "raw_config", "N/A")[:60] if hasattr(earlier_acl, "raw_config") else "N/A",
                            })
                            break
                        # If earlier rule is more general (any source/dest) and protocols match
                        elif (earlier_src == "any" or earlier_dst == "any") and earlier_proto == later_proto:
                            # Check if later rule is more specific but still matches
                            if ((earlier_src == "any" or earlier_src == later_src) and
                                (earlier_dst == "any" or earlier_dst == later_dst)):
                                metrics["shadowed_rules"] += 1
                                metrics["details"].append({
                                    "type": "shadowed",
                                    "acl": acl_name,
                                    "rule": getattr(later_acl, "raw_config", "N/A")[:60] if hasattr(later_acl, "raw_config") else "N/A",
                                    "shadowed_by": getattr(earlier_acl, "raw_config", "N/A")[:60] if hasattr(earlier_acl, "raw_config") else "N/A",
                                })
                                break
        
        # 3. Detect unused/disabled objects (simplified - check for disabled interfaces)
        for interface in interfaces:
            # Check if interface is shutdown/disabled
            if hasattr(interface, "raw_config") and interface.raw_config:
                raw_lower = interface.raw_config.lower()
                if "shutdown" in raw_lower or "disabled" in raw_lower:
                    # Check if any ACL references this interface
                    interface_referenced = False
                    for acl in acls:
                        if hasattr(acl, "raw_config") and acl.raw_config:
                            if interface.name and interface.name.lower() in acl.raw_config.lower():
                                interface_referenced = True
                                break
                    if not interface_referenced:
                        metrics["unused_objects"] += 1
                        metrics["details"].append({
                            "type": "unused_object",
                            "object": f"Interface: {interface.name}",
                        })
        
        # 4. Unreferenced groups (simplified - would need to parse group definitions)
        # For now, we'll skip this as it requires parsing group/object-group definitions
        
        return metrics
    
    def _calculate_hygiene_score(self, hygiene_metrics: Dict[str, Any]) -> float:
        """
        Calculate policy hygiene score (0-100).
        
        Higher score = better hygiene.
        Penalties:
        - Redundant rule: -2 points
        - Shadowed rule: -3 points
        - Unused object: -1 point
        - Unreferenced group: -1 point (not implemented yet)
        
        Base score: 100
        """
        base_score = 100.0
        total_rules = hygiene_metrics.get("total_rules", 1)
        
        # Normalize penalties by total rules to avoid excessive penalties for large configs
        penalty_per_redundant = 2.0 / max(total_rules, 10)  # Max 2 points per rule, normalized
        penalty_per_shadowed = 3.0 / max(total_rules, 10)  # Max 3 points per rule, normalized
        penalty_per_unused = 1.0 / max(total_rules, 10)  # Max 1 point per object, normalized
        
        redundant_count = hygiene_metrics.get("redundant_rules", 0)
        shadowed_count = hygiene_metrics.get("shadowed_rules", 0)
        unused_count = hygiene_metrics.get("unused_objects", 0)
        
        # Calculate penalties
        redundant_penalty = redundant_count * penalty_per_redundant * min(total_rules, 10)
        shadowed_penalty = shadowed_count * penalty_per_shadowed * min(total_rules, 10)
        unused_penalty = unused_count * penalty_per_unused * min(total_rules, 10)
        
        total_penalty = redundant_penalty + shadowed_penalty + unused_penalty
        
        # Calculate final score (clamp to 0-100)
        score = max(0.0, min(100.0, base_score - total_penalty))
        
        return round(score, 1)
