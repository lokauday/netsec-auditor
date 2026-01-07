"""
Vendor detection utility.
"""
import logging
from typing import Optional

from app.models.config_file import VendorType

logger = logging.getLogger(__name__)


def detect_vendor(config_content: str) -> Optional[VendorType]:
    """
    Detect the vendor type from config file content.
    Uses robust heuristics to classify vendor types.
    
    Args:
        config_content: The configuration file content
        
    Returns:
        VendorType if detected, None otherwise
    """
    config_lower = config_content.lower()
    
    # Cisco ASA indicators (check first, more specific)
    asa_indicators = [
        "cisco adaptive security appliance",
        "asa version",
        "object-group network",
        "same-security-traffic",
        "nat (inside",
        "nat (outside",
    ]
    if any(indicator in config_lower for indicator in asa_indicators):
        # Also check for ASA-specific access-list patterns
        if "access-list" in config_lower and ("extended" in config_lower or "object-group" in config_lower):
            return VendorType.CISCO_ASA
        if "access-list" in config_lower:
            # Could be ASA or IOS, check for ASA-specific patterns
            if "object-group" in config_lower or "same-security-traffic" in config_lower:
                return VendorType.CISCO_ASA
    
    # Fortinet indicators (check before Palo Alto as they both use "set")
    fortinet_indicators = [
        "config firewall policy",
        "set srcintf",
        "set dstintf",
        "set action accept",
        "set action deny",
    ]
    if any(indicator in config_lower for indicator in fortinet_indicators):
        return VendorType.FORTINET
    # Additional Fortinet patterns
    if "config firewall" in config_lower and ("edit " in config_lower or "set " in config_lower):
        if "fortinet" in config_lower or "fortigate" in config_lower:
            return VendorType.FORTINET
    
    # Palo Alto indicators
    palo_alto_indicators = [
        "palo alto",
        "pan-os",
        "set rulebase security rules",
        "set address",
        "set address-group",
        "set zone",
    ]
    if any(indicator in config_lower for indicator in palo_alto_indicators):
        return VendorType.PALO_ALTO
    # Additional Palo Alto pattern
    if "set rulebase" in config_lower and "security" in config_lower:
        return VendorType.PALO_ALTO
    
    # Cisco IOS indicators (check last, least specific)
    ios_indicators = [
        "interface gigabitethernet",
        "interface fastethernet",
        "interface ethernet",
        "ip access-list",
        "ip route",
    ]
    if any(indicator in config_lower for indicator in ios_indicators):
        # Make sure it's not ASA
        if "asa version" not in config_lower and "object-group network" not in config_lower:
            return VendorType.CISCO_IOS
    # Additional IOS pattern - simpler access-list format
    if "access-list" in config_lower and "ip route" in config_lower:
        if "extended" not in config_lower and "object-group" not in config_lower:
            return VendorType.CISCO_IOS
    
    logger.warning("Could not detect vendor type from config content")
    return None

