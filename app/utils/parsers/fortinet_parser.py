"""
Fortinet (FortiGate) configuration parser.
"""
import re
import logging
from typing import Dict, List, Any

from app.utils.parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)


class FortinetParser(BaseParser):
    """Parser for Fortinet FortiGate configuration files."""
    
    def parse_acls(self) -> List[Dict[str, Any]]:
        """Parse firewall policies (ACLs) from Fortinet config."""
        acls = []
        
        # Fortinet uses firewall policies
        # config firewall policy
        #   edit <id>
        #     set srcintf <interface>
        #     set dstintf <interface>
        #     set srcaddr <address>
        #     set dstaddr <address>
        #     set action <allow/deny>
        #     set service <service>
        
        in_policy_section = False
        current_policy = None
        policy_id = 0
        
        for line in self.lines:
            line = line.strip()
            
            if line.startswith('config firewall policy'):
                in_policy_section = True
                continue
            elif in_policy_section and line.startswith('config '):
                in_policy_section = False
                if current_policy:
                    acls.append(current_policy)
                    current_policy = None
                continue
            elif in_policy_section and line.startswith('edit '):
                if current_policy:
                    acls.append(current_policy)
                policy_id = line.split()[1] if len(line.split()) > 1 else str(len(acls) + 1)
                current_policy = {
                    "name": f"policy_{policy_id}",
                    "direction": "inbound",
                    "action": "allow",
                    "raw_config": "",
                    "rule_number": int(policy_id) if policy_id.isdigit() else len(acls) + 1,
                }
                current_policy["raw_config"] = line + "\n"
            elif in_policy_section and current_policy and line.startswith('set '):
                parts = line.split()
                if len(parts) >= 3:
                    key = parts[1]
                    value = ' '.join(parts[2:])
                    current_policy["raw_config"] += line + "\n"
                    
                    if key == 'action':
                        current_policy["action"] = value
                    elif key == 'srcaddr':
                        current_policy["source"] = value
                    elif key == 'dstaddr':
                        current_policy["destination"] = value
                    elif key == 'service':
                        current_policy["port"] = value
                    elif key == 'protocol':
                        current_policy["protocol"] = value
        
        if current_policy:
            acls.append(current_policy)
        
        return acls
    
    def parse_nat_rules(self) -> List[Dict[str, Any]]:
        """Parse NAT rules from Fortinet config."""
        nat_rules = []
        
        # config firewall central-nat
        #   edit <id>
        #     set original-source <address>
        #     set translated-source <address>
        
        in_nat_section = False
        current_nat = None
        nat_id = 0
        
        for line in self.lines:
            line = line.strip()
            
            if 'config firewall' in line and 'nat' in line.lower():
                in_nat_section = True
                continue
            elif in_nat_section and line.startswith('config '):
                in_nat_section = False
                if current_nat:
                    nat_rules.append(current_nat)
                    current_nat = None
                continue
            elif in_nat_section and line.startswith('edit '):
                if current_nat:
                    nat_rules.append(current_nat)
                nat_id = line.split()[1] if len(line.split()) > 1 else str(len(nat_rules) + 1)
                current_nat = {
                    "rule_name": f"nat_{nat_id}",
                    "raw_config": line + "\n",
                    "rule_number": int(nat_id) if str(nat_id).isdigit() else len(nat_rules) + 1,
                }
            elif in_nat_section and current_nat and line.startswith('set '):
                parts = line.split()
                if len(parts) >= 3:
                    key = parts[1].replace('-', '_')
                    value = ' '.join(parts[2:])
                    current_nat["raw_config"] += line + "\n"
                    
                    if 'original_source' in key:
                        current_nat["source_original"] = value
                    elif 'translated_source' in key:
                        current_nat["source_translated"] = value
        
        if current_nat:
            nat_rules.append(current_nat)
        
        return nat_rules
    
    def parse_vpns(self) -> List[Dict[str, Any]]:
        """Parse VPN configurations from Fortinet config."""
        vpns = []
        
        # config vpn ipsec phase1-interface
        #   edit <name>
        #     set remote-gw <address>
        
        in_vpn_section = False
        current_vpn = None
        
        for line in self.lines:
            line = line.strip()
            
            if 'config vpn' in line.lower():
                in_vpn_section = True
                continue
            elif in_vpn_section and line.startswith('config '):
                in_vpn_section = False
                if current_vpn:
                    vpns.append(current_vpn)
                    current_vpn = None
                continue
            elif in_vpn_section and line.startswith('edit '):
                if current_vpn:
                    vpns.append(current_vpn)
                vpn_name = line.split()[1] if len(line.split()) > 1 else f"vpn_{len(vpns) + 1}"
                current_vpn = {
                    "vpn_name": vpn_name,
                    "vpn_type": "site-to-site",
                    "raw_config": line + "\n",
                }
            elif in_vpn_section and current_vpn and line.startswith('set '):
                parts = line.split()
                if len(parts) >= 3:
                    key = parts[1]
                    value = ' '.join(parts[2:])
                    current_vpn["raw_config"] += line + "\n"
                    
                    if 'remote-gw' in key or 'remote_gw' in key:
                        current_vpn["peer_address"] = value
                    elif 'psk' in key.lower() or 'pre-shared-key' in key.lower():
                        current_vpn["pre_shared_key"] = value
        
        if current_vpn:
            vpns.append(current_vpn)
        
        return vpns
    
    def parse_interfaces(self) -> List[Dict[str, Any]]:
        """Parse interfaces from Fortinet config."""
        interfaces = []
        
        # config system interface
        #   edit <name>
        #     set ip <ip> <mask>
        #     set status up/down
        
        in_interface_section = False
        current_interface = None
        
        for line in self.lines:
            line = line.strip()
            
            if line.startswith('config system interface'):
                in_interface_section = True
                continue
            elif in_interface_section and line.startswith('config '):
                in_interface_section = False
                if current_interface:
                    interfaces.append(current_interface)
                    current_interface = None
                continue
            elif in_interface_section and line.startswith('edit '):
                if current_interface:
                    interfaces.append(current_interface)
                interface_name = line.split()[1] if len(line.split()) > 1 else f"interface_{len(interfaces) + 1}"
                current_interface = {
                    "name": interface_name,
                    "status": "up",
                    "is_shutdown": False,
                    "raw_config": line + "\n",
                }
            elif in_interface_section and current_interface and line.startswith('set '):
                parts = line.split()
                if len(parts) >= 3:
                    key = parts[1]
                    value = ' '.join(parts[2:])
                    current_interface["raw_config"] += line + "\n"
                    
                    if key == 'ip':
                        ip_parts = value.split()
                        if len(ip_parts) >= 1:
                            current_interface["ip_address"] = ip_parts[0]
                            current_interface["subnet_mask"] = ip_parts[1] if len(ip_parts) > 1 else None
                    elif key == 'status':
                        current_interface["status"] = value
                        current_interface["is_shutdown"] = (value == "down")
                    elif key == 'description':
                        current_interface["description"] = value
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def parse_routes(self) -> List[Dict[str, Any]]:
        """Parse routes from Fortinet config."""
        routes = []
        
        # config router static
        #   edit <id>
        #     set dst <network>
        #     set gateway <next-hop>
        
        in_route_section = False
        current_route = None
        
        for line in self.lines:
            line = line.strip()
            
            if 'config router' in line.lower() and 'static' in line.lower():
                in_route_section = True
                continue
            elif in_route_section and line.startswith('config '):
                in_route_section = False
                if current_route:
                    routes.append(current_route)
                    current_route = None
                continue
            elif in_route_section and line.startswith('edit '):
                if current_route:
                    routes.append(current_route)
                route_id = line.split()[1] if len(line.split()) > 1 else str(len(routes) + 1)
                current_route = {
                    "network": "0.0.0.0",
                    "protocol": "static",
                    "raw_config": line + "\n",
                }
            elif in_route_section and current_route and line.startswith('set '):
                parts = line.split()
                if len(parts) >= 3:
                    key = parts[1]
                    value = ' '.join(parts[2:])
                    current_route["raw_config"] += line + "\n"
                    
                    if key == 'dst' or key == 'dstaddr':
                        current_route["network"] = value
                    elif key == 'gateway':
                        current_route["next_hop"] = value
                    elif key == 'device':
                        current_route["interface"] = value
        
        if current_route:
            routes.append(current_route)
        
        return routes

