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
        
        # Pattern for standard and extended ACLs (numbered)
        # access-list <number> <action> <protocol> <source> [destination] [port]
        numbered_pattern = re.compile(
            r'access-list\s+(\d+)\s+(permit|deny)\s+(\S+)\s+(\S+)(?:\s+(\S+))?(?:\s+eq\s+(\S+))?',
            re.IGNORECASE
        )
        
        # Pattern for named IP ACLs (IOS)
        # ip access-list extended <name>
        #  <action> <protocol> <source> <destination> [port]
        named_acl_pattern = re.compile(
            r'ip access-list (?:extended|standard)\s+(\S+)',
            re.IGNORECASE
        )
        
        current_named_acl = None
        sequence = 0
        
        for line in self.lines:
            line_stripped = line.strip()
            
            # Check for named ACL definition
            named_match = named_acl_pattern.match(line_stripped)
            if named_match:
                current_named_acl = named_match.group(1)
                sequence = 0
                continue
            
            # Check if we're in a named ACL block (starts with space/tab or is a permit/deny line)
            if current_named_acl and (line_stripped.startswith(('permit', 'deny', ' ')) or line_stripped.startswith('\t')):
                # Parse permit/deny line in named ACL
                permit_deny_pattern = re.compile(
                    r'(permit|deny)\s+(\S+)\s+(\S+)(?:\s+(\S+))?(?:\s+eq\s+(\S+))?',
                    re.IGNORECASE
                )
                permit_match = permit_deny_pattern.match(line_stripped)
                if permit_match:
                    sequence += 1
                    acls.append({
                        "name": current_named_acl,
                        "direction": "inbound",
                        "action": permit_match.group(1).lower(),
                        "protocol": permit_match.group(2).lower(),
                        "source": permit_match.group(3),
                        "destination": permit_match.group(4) if permit_match.group(4) else None,
                        "port": permit_match.group(5) if permit_match.group(5) else None,
                        "raw_config": line_stripped,
                        "rule_number": sequence,
                    })
                # Reset if we hit a new config section
                if line_stripped and not line_stripped.startswith((' ', '\t', 'permit', 'deny')):
                    current_named_acl = None
                continue
            
            # Check for numbered ACLs
            if line_stripped.startswith('access-list '):
                numbered_match = numbered_pattern.match(line_stripped)
                if numbered_match:
                    sequence += 1
                    acls.append({
                        "name": numbered_match.group(1),
                        "direction": "inbound",
                        "action": numbered_match.group(2).lower(),
                        "protocol": numbered_match.group(3).lower(),
                        "source": numbered_match.group(4),
                        "destination": numbered_match.group(5) if numbered_match.group(5) else None,
                        "port": numbered_match.group(6) if numbered_match.group(6) else None,
                        "raw_config": line_stripped,
                        "rule_number": sequence,
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

