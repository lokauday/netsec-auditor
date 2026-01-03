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
    
    def audit_config(self, config_file_id: int) -> Dict[str, Any]:
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
        
        # Run rule-based security checks
        findings = self._run_rule_based_checks(config_file, acls, nat_rules, routes, interfaces)
        
        # If OpenAI API key is configured, enhance with AI analysis
        if settings.is_openai_available():
            try:
                logger.info(f"Running AI-enhanced audit for config file {config_file_id}")
                ai_findings = self._get_ai_findings(config_file, acls, nat_rules, vpns)
                findings.extend(ai_findings)
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
        
        # Generate summary
        summary = self._generate_summary(findings, risk_score)
        
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
        
        logger.info(f"Saved audit record {audit_record.id} for config_file_id={config_file_id}")
        
        return {
            "config_file_id": config_file_id,
            "vendor": config_file.vendor.value,
            "filename": config_file.filename,
            "risk_score": risk_score,
            "total_findings": len(findings),
            "breakdown": breakdown,
            "summary": summary,
            "findings": findings_dict,
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
        
        # ========= ACL_PERMIT_ANY_ANY (CRITICAL) =========
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
        
        # Check if any pattern exists in combined text
        if any(pattern in combined_acl_text for pattern in any_any_patterns):
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
        
        return findings
    
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
            from openai import OpenAI
            
            client = OpenAI(api_key=settings.OPENAI_API_KEY)
            
            # Prepare context for AI
            context = f"""
            Analyze the following network security configuration:
            Vendor: {config_file.vendor.value}
            ACLs: {len(acls)} rules
            NAT Rules: {len(nat_rules)} rules
            VPNs: {len(vpns)} configurations
            
            Identify security risks and provide recommendations. Return JSON format:
            {{
                "findings": [
                    {{
                        "severity": "critical|high|medium|low",
                        "code": "RISK_CODE",
                        "description": "Detailed description",
                        "affected_objects": ["object1", "object2"],
                        "recommendation": "Recommended fix"
                    }}
                ]
            }}
            """
            
            response = client.chat.completions.create(
                model=settings.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a network security expert analyzing firewall and router configurations."},
                    {"role": "user", "content": context}
                ],
                temperature=0.3,
            )
            
            import json
            content = response.choices[0].message.content
            # Try to extract JSON from response
            json_start = content.find('{')
            json_end = content.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                ai_data = json.loads(content[json_start:json_end])
                findings = []
                for finding_data in ai_data.get("findings", []):
                    findings.append(SecurityFinding(**finding_data))
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
