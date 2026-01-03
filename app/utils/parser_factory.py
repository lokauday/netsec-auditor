"""
Parser factory for creating appropriate parser based on vendor type.
"""
import logging

from app.models.config_file import VendorType
from app.utils.parsers.cisco_asa_parser import CiscoASAParser
from app.utils.parsers.cisco_ios_parser import CiscoIOSParser
from app.utils.parsers.fortinet_parser import FortinetParser
from app.utils.parsers.palo_alto_parser import PaloAltoParser

logger = logging.getLogger(__name__)


def create_parser(vendor: VendorType, config_content: str):
    """
    Create appropriate parser based on vendor type.
    
    Args:
        vendor: VendorType enum value
        config_content: Configuration file content
        
    Returns:
        Parser instance
    """
    parsers = {
        VendorType.CISCO_ASA: CiscoASAParser,
        VendorType.CISCO_IOS: CiscoIOSParser,
        VendorType.FORTINET: FortinetParser,
        VendorType.PALO_ALTO: PaloAltoParser,
    }
    
    parser_class = parsers.get(vendor)
    if not parser_class:
        raise ValueError(f"Unsupported vendor type: {vendor}")
    
    return parser_class(config_content)

