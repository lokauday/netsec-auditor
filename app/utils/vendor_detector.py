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
    
    Args:
        config_content: The configuration file content
        
    Returns:
        VendorType if detected, None otherwise
    """
    config_lower = config_content.lower()
    
    # Cisco ASA indicators
    if any(indicator in config_lower for indicator in [
        "cisco adaptive security appliance",
        "asa version",
        "access-list ",
        "object network",
        "nat (",
    ]):
        return VendorType.CISCO_ASA
    
    # Cisco IOS indicators
    if any(indicator in config_lower for indicator in [
        "cisco ios software",
        "version ",
        "interface ",
        "ip route",
        "access-list ",
    ]) and "asa version" not in config_lower:
        return VendorType.CISCO_IOS
    
    # Fortinet indicators
    if any(indicator in config_lower for indicator in [
        "config system",
        "config firewall",
        "edit ",
        "set ",
        "next",
        "end",
    ]) and "fortinet" in config_lower or "fortigate" in config_lower:
        return VendorType.FORTINET
    
    # Palo Alto indicators
    if any(indicator in config_lower for indicator in [
        "palo alto",
        "pan-os",
        "set deviceconfig",
        "set network",
        "set rulebase",
    ]):
        return VendorType.PALO_ALTO
    
    logger.warning("Could not detect vendor type from config content")
    return None

