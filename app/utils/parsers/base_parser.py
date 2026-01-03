"""
Base parser class for configuration files.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """Base class for configuration parsers."""
    
    def __init__(self, config_content: str):
        """
        Initialize parser with config content.
        
        Args:
            config_content: The configuration file content as string
        """
        self.config_content = config_content
        self.lines = config_content.split('\n')
    
    @abstractmethod
    def parse_acls(self) -> List[Dict[str, Any]]:
        """Parse Access Control Lists from config."""
        pass
    
    @abstractmethod
    def parse_nat_rules(self) -> List[Dict[str, Any]]:
        """Parse NAT rules from config."""
        pass
    
    @abstractmethod
    def parse_vpns(self) -> List[Dict[str, Any]]:
        """Parse VPN configurations from config."""
        pass
    
    @abstractmethod
    def parse_interfaces(self) -> List[Dict[str, Any]]:
        """Parse network interfaces from config."""
        pass
    
    @abstractmethod
    def parse_routes(self) -> List[Dict[str, Any]]:
        """Parse routing table entries from config."""
        pass
    
    def parse_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Parse all configuration elements.
        
        Returns:
            Dictionary with parsed elements
        """
        return {
            "acls": self.parse_acls(),
            "nat_rules": self.parse_nat_rules(),
            "vpns": self.parse_vpns(),
            "interfaces": self.parse_interfaces(),
            "routes": self.parse_routes(),
        }

