"""
Cisco IOS configuration parser.
"""
import re
import logging
from typing import Dict, List, Any

from app.utils.parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)


class CiscoIOSParser(BaseParser):
    """Parser for Cisco IOS configuration files."""
    
    def parse_acls(self) -> List[Dict[str, Any]]:
        """Parse ACLs from Cisco IOS config."""
        acls = []
        
        # Pattern for standard and extended ACLs
        # access-list <number> <action> <protocol> <source> [destination] [port]
        pattern = re.compile(
            r'access-list\s+(\d+)\s+(permit|deny)\s+(\S+)\s+(\S+)(?:\s+(\S+))?(?:\s+eq\s+(\S+))?',
            re.IGNORECASE
        )
        
        for line in self.lines:
            line = line.strip()
            if line.startswith('access-list '):
                match = pattern.match(line)
                if match:
                    acls.append({
                        "name": match.group(1),
                        "direction": "inbound",  # Context-dependent
                        "action": match.group(2),
                        "protocol": match.group(3),
                        "source": match.group(4),
                        "destination": match.group(5) if match.group(5) else None,
                        "port": match.group(6) if match.group(6) else None,
                        "raw_config": line,
                        "rule_number": int(match.group(1)),
                    })
        
        return acls
    
    def parse_nat_rules(self) -> List[Dict[str, Any]]:
        """Parse NAT rules from Cisco IOS config."""
        nat_rules = []
        
        # Pattern for NAT (inside/outside)
        # ip nat inside source static <local> <global>
        # ip nat inside source list <acl> interface <interface> overload
        pattern = re.compile(
            r'ip nat (inside|outside) source (static|list)\s+(\S+)\s+(\S+)(?:\s+(\S+))?',
            re.IGNORECASE
        )
        
        for line in self.lines:
            line = line.strip()
            if 'ip nat' in line:
                match = pattern.match(line)
                if match:
                    nat_rules.append({
                        "source_original": match.group(3),
                        "source_translated": match.group(4),
                        "rule_name": f"nat_{match.group(1)}_{len(nat_rules) + 1}",
                        "raw_config": line,
                        "rule_number": len(nat_rules) + 1,
                    })
        
        return nat_rules
    
    def parse_vpns(self) -> List[Dict[str, Any]]:
        """Parse VPN configurations from Cisco IOS config."""
        vpns = []
        
        # Pattern for crypto map (VPN)
        crypto_map_pattern = re.compile(
            r'crypto map\s+(\S+)\s+(\d+)\s+\S+\s+set peer\s+(\S+)',
            re.IGNORECASE
        )
        
        for line in self.lines:
            line = line.strip()
            crypto_match = crypto_map_pattern.match(line)
            if crypto_match:
                vpns.append({
                    "vpn_name": crypto_match.group(1),
                    "vpn_type": "site-to-site",
                    "peer_address": crypto_match.group(3),
                    "raw_config": line,
                })
        
        return vpns
    
    def parse_interfaces(self) -> List[Dict[str, Any]]:
        """Parse interfaces from Cisco IOS config."""
        interfaces = []
        
        current_interface = None
        for line in self.lines:
            line = line.strip()
            
            # Interface definition
            if line.startswith('interface '):
                if current_interface:
                    interfaces.append(current_interface)
                
                interface_name = ' '.join(line.split()[1:])
                current_interface = {
                    "name": interface_name,
                    "status": "up",
                    "is_shutdown": False,
                    "raw_config": line,
                }
            elif current_interface:
                # Interface properties
                if line.startswith('description '):
                    current_interface["description"] = line.split(' ', 1)[1] if len(line.split(' ', 1)) > 1 else None
                elif line.startswith('ip address '):
                    parts = line.split()
                    if len(parts) >= 3:
                        current_interface["ip_address"] = parts[2]
                        current_interface["subnet_mask"] = parts[3] if len(parts) > 3 else None
                elif line.startswith('shutdown'):
                    current_interface["is_shutdown"] = True
                    current_interface["status"] = "down"
                elif line.startswith('speed '):
                    current_interface["speed"] = line.split()[1]
                elif line.startswith('duplex '):
                    current_interface["duplex"] = line.split()[1]
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def parse_routes(self) -> List[Dict[str, Any]]:
        """Parse routes from Cisco IOS config."""
        routes = []
        
        # Pattern for static routes
        # ip route <network> <mask> <next-hop> [distance]
        pattern = re.compile(
            r'ip route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+))?',
            re.IGNORECASE
        )
        
        for line in self.lines:
            line = line.strip()
            if line.startswith('ip route '):
                match = pattern.match(line)
                if match:
                    routes.append({
                        "network": match.group(1),
                        "subnet_mask": match.group(2),
                        "next_hop": match.group(3),
                        "protocol": "static",
                        "administrative_distance": int(match.group(4)) if match.group(4) else 1,
                        "raw_config": line,
                    })
        
        return routes

