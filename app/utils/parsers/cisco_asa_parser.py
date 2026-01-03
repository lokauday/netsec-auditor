"""
Cisco ASA configuration parser.
"""
import re
import logging
from typing import Dict, List, Any, Union

from app.utils.parsers.base_parser import BaseParser
from app.utils.parsers.acl_models import ParsedACLEntry

logger = logging.getLogger(__name__)


class CiscoASAParser(BaseParser):
    """Parser for Cisco ASA configuration files."""
    
    def parse_acls(self) -> List[Union[Dict[str, Any], ParsedACLEntry]]:
        """
        Parse ACLs from Cisco ASA config.
        
        Returns structured ParsedACLEntry objects for Cisco ASA.
        Format: access-list <name> extended permit|deny <protocol> <src> <dst> [operator port]
        """
        acls = []
        
        # Pattern for extended access-list entries
        # access-list OUTSIDE-IN extended permit tcp any host 1.2.3.4 eq 443
        # access-list INSIDE extended permit ip 192.168.1.0 255.255.255.0 any
        # access-list ACL_NAME extended deny tcp any any eq 80
        pattern = re.compile(
            r'access-list\s+(\S+)\s+(?:extended|standard)?\s*(permit|deny)\s+(\S+)\s+'
            r'(\S+)\s+(\S+)\s+(\S+)?(?:\s+(eq|lt|gt|neq|range)\s+(\S+)(?:\s+(\S+))?)?\s*(.*)?',
            re.IGNORECASE
        )
        
        sequence = 0
        for line in self.lines:
            line = line.strip()
            if line.startswith('access-list') and 'extended' in line.lower():
                match = pattern.match(line)
                if match:
                    sequence += 1
                    name = match.group(1)
                    action = match.group(2).lower()
                    protocol = match.group(3).lower()
                    src = match.group(4)
                    dst = match.group(5)
                    
                    # Extract port information
                    src_port = None
                    dst_port = None
                    
                    # Check for port operators (eq, lt, gt, neq, range)
                    if match.group(7):  # port operator exists
                        operator = match.group(7).lower()
                        port_value = match.group(8)
                        port_value2 = match.group(9) if match.group(9) else None
                        
                        # Format port string
                        if operator == 'range' and port_value2:
                            port_str = f"{operator} {port_value} {port_value2}"
                        else:
                            port_str = f"{operator} {port_value}"
                        
                        # Destination port is more common, but could be source in some cases
                        # For simplicity, assume destination port
                        dst_port = port_str
                    
                    acl_entry = ParsedACLEntry(
                        name=name,
                        sequence=sequence,
                        action=action,
                        protocol=protocol,
                        src=src,
                        src_port=src_port,
                        dst=dst,
                        dst_port=dst_port,
                        raw_line=line,
                    )
                    acls.append(acl_entry)
            elif line.startswith('access-list'):
                # Handle standard ACLs (simpler format) - convert to dict for compatibility
                parts = line.split()
                if len(parts) >= 4:
                    sequence += 1
                    acls.append({
                        "name": parts[1],
                        "sequence": sequence,
                        "action": parts[2].lower(),
                        "protocol": "ip",  # Standard ACLs are IP-based
                        "src": parts[3] if len(parts) > 3 else "any",
                        "src_port": None,
                        "dst": "any",
                        "dst_port": None,
                        "raw_line": line,
                    })
        
        return acls
    
    def parse_nat_rules(self) -> List[Dict[str, Any]]:
        """Parse NAT rules from Cisco ASA config."""
        nat_rules = []
        
        # Pattern for NAT rules
        # nat (<interface>) <source> <translated> <static|dynamic>
        pattern = re.compile(
            r'nat\s*\((\S+)\)\s+(\S+)\s+(\S+)\s+(\S+)',
            re.IGNORECASE
        )
        
        for line in self.lines:
            line = line.strip()
            if line.startswith('nat ') and '(' in line:
                match = pattern.match(line)
                if match:
                    nat_rules.append({
                        "interface": match.group(1),
                        "source_original": match.group(2),
                        "source_translated": match.group(3),
                        "rule_name": f"nat_{match.group(1)}_{len(nat_rules) + 1}",
                        "raw_config": line,
                        "rule_number": len(nat_rules) + 1,
                    })
        
        return nat_rules
    
    def parse_vpns(self) -> List[Dict[str, Any]]:
        """Parse VPN configurations from Cisco ASA config."""
        vpns = []
        
        # Pattern for crypto map (site-to-site VPN)
        crypto_map_pattern = re.compile(
            r'crypto map\s+(\S+)\s+(\d+)\s+\S+\s+set peer\s+(\S+)',
            re.IGNORECASE
        )
        
        current_vpn = None
        for line in self.lines:
            line = line.strip()
            
            # Crypto map entry
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
        """Parse interfaces from Cisco ASA config."""
        interfaces = []
        
        current_interface = None
        for line in self.lines:
            line = line.strip()
            
            # Interface definition
            if line.startswith('interface '):
                if current_interface:
                    interfaces.append(current_interface)
                
                interface_name = line.split()[1]
                current_interface = {
                    "name": interface_name,
                    "status": "up",
                    "is_shutdown": False,
                    "raw_config": line,
                }
            elif current_interface:
                # Interface properties
                if line.startswith('nameif '):
                    current_interface["description"] = line.split(' ', 1)[1] if len(line.split(' ', 1)) > 1 else None
                elif line.startswith('ip address '):
                    parts = line.split()
                    if len(parts) >= 3:
                        current_interface["ip_address"] = parts[2]
                        current_interface["subnet_mask"] = parts[3] if len(parts) > 3 else None
                elif line.startswith('shutdown'):
                    current_interface["is_shutdown"] = True
                    current_interface["status"] = "down"
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def parse_routes(self) -> List[Dict[str, Any]]:
        """Parse routes from Cisco ASA config."""
        routes = []
        
        # Pattern for static routes
        # route <interface> <network> <mask> <gateway> [distance]
        pattern = re.compile(
            r'route\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+))?',
            re.IGNORECASE
        )
        
        for line in self.lines:
            line = line.strip()
            if line.startswith('route '):
                match = pattern.match(line)
                if match:
                    routes.append({
                        "network": match.group(2),
                        "subnet_mask": match.group(3),
                        "next_hop": match.group(4),
                        "interface": match.group(1),
                        "protocol": "static",
                        "administrative_distance": int(match.group(5)) if match.group(5) else 1,
                        "raw_config": line,
                    })
        
        return routes

