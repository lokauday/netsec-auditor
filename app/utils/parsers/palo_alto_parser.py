"""
Palo Alto Networks configuration parser.
"""
import re
import logging
from typing import Dict, List, Any

from app.utils.parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)


class PaloAltoParser(BaseParser):
    """Parser for Palo Alto Networks configuration files."""
    
    def parse_acls(self) -> List[Dict[str, Any]]:
        """Parse security policies (ACLs) from Palo Alto config."""
        acls = []
        
        # Palo Alto uses security policies
        # set rulebase security rules <rule-name> <property> <value>
        
        # Simplified parser - in real XML/config, would parse structured format
        rule_pattern = re.compile(
            r'set rulebase security rules\s+(\S+)\s+(\S+)\s+(.+)',
            re.IGNORECASE
        )
        
        rules = {}
        for line in self.lines:
            line = line.strip()
            match = rule_pattern.match(line)
            if match:
                rule_name = match.group(1)
                property_name = match.group(2)
                value = match.group(3)
                
                if rule_name not in rules:
                    rules[rule_name] = {
                        "name": rule_name,
                        "direction": "inbound",
                        "action": "allow",
                        "raw_config": "",
                        "rule_number": len(rules) + 1,
                    }
                
                rules[rule_name]["raw_config"] += line + "\n"
                
                if property_name == "action":
                    rules[rule_name]["action"] = value
                elif property_name == "source":
                    rules[rule_name]["source"] = value
                elif property_name == "destination":
                    rules[rule_name]["destination"] = value
                elif property_name == "service":
                    rules[rule_name]["port"] = value
                elif property_name == "application":
                    rules[rule_name]["protocol"] = value
        
        return list(rules.values())
    
    def parse_nat_rules(self) -> List[Dict[str, Any]]:
        """Parse NAT rules from Palo Alto config."""
        nat_rules = []
        
        # set rulebase nat rules <rule-name> <property> <value>
        rule_pattern = re.compile(
            r'set rulebase nat rules\s+(\S+)\s+(\S+)\s+(.+)',
            re.IGNORECASE
        )
        
        rules = {}
        for line in self.lines:
            line = line.strip()
            match = rule_pattern.match(line)
            if match:
                rule_name = match.group(1)
                property_name = match.group(2)
                value = match.group(3)
                
                if rule_name not in rules:
                    rules[rule_name] = {
                        "rule_name": rule_name,
                        "raw_config": "",
                        "rule_number": len(rules) + 1,
                    }
                
                rules[rule_name]["raw_config"] += line + "\n"
                
                if "source-translation" in property_name:
                    rules[rule_name]["source_translated"] = value
                elif "destination-translation" in property_name:
                    rules[rule_name]["destination_translated"] = value
                elif "source-address" in property_name:
                    rules[rule_name]["source_original"] = value
                elif "destination-address" in property_name:
                    rules[rule_name]["destination_original"] = value
        
        return list(rules.values())
    
    def parse_vpns(self) -> List[Dict[str, Any]]:
        """Parse VPN configurations from Palo Alto config."""
        vpns = []
        
        # set network ike crypto-profile <name> <property> <value>
        # set network ike gateway <name> peer-address <address>
        
        ike_pattern = re.compile(
            r'set network ike (?:crypto-profile|gateway)\s+(\S+)\s+(\S+)\s+(.+)',
            re.IGNORECASE
        )
        
        vpn_dict = {}
        for line in self.lines:
            line = line.strip()
            match = ike_pattern.match(line)
            if match:
                vpn_name = match.group(1)
                property_name = match.group(2)
                value = match.group(3)
                
                if vpn_name not in vpn_dict:
                    vpn_dict[vpn_name] = {
                        "vpn_name": vpn_name,
                        "vpn_type": "site-to-site",
                        "raw_config": "",
                    }
                
                vpn_dict[vpn_name]["raw_config"] += line + "\n"
                
                if "peer-address" in property_name or "peer_address" in property_name:
                    vpn_dict[vpn_name]["peer_address"] = value
                elif "pre-shared-key" in property_name or "pre_shared_key" in property_name:
                    vpn_dict[vpn_name]["pre_shared_key"] = value
        
        return list(vpn_dict.values())
    
    def parse_interfaces(self) -> List[Dict[str, Any]]:
        """Parse interfaces from Palo Alto config."""
        interfaces = []
        
        # set network interface ethernet <name> <property> <value>
        interface_pattern = re.compile(
            r'set network interface (?:ethernet|vlan|tunnel)\s+(\S+)\s+(\S+)\s+(.+)',
            re.IGNORECASE
        )
        
        interface_dict = {}
        for line in self.lines:
            line = line.strip()
            match = interface_pattern.match(line)
            if match:
                interface_name = match.group(1)
                property_name = match.group(2)
                value = match.group(3)
                
                if interface_name not in interface_dict:
                    interface_dict[interface_name] = {
                        "name": interface_name,
                        "status": "up",
                        "is_shutdown": False,
                        "raw_config": "",
                    }
                
                interface_dict[interface_name]["raw_config"] += line + "\n"
                
                if "ip" in property_name and "static-ip" in property_name:
                    # Parse IP address and mask
                    ip_parts = value.split()
                    if len(ip_parts) >= 1:
                        interface_dict[interface_name]["ip_address"] = ip_parts[0]
                        interface_dict[interface_name]["subnet_mask"] = ip_parts[1] if len(ip_parts) > 1 else None
                elif property_name == "tag":
                    interface_dict[interface_name]["description"] = value
        
        return list(interface_dict.values())
    
    def parse_routes(self) -> List[Dict[str, Any]]:
        """Parse routes from Palo Alto config."""
        routes = []
        
        # set network virtual-router <vr-name> routing-table ip static-route <name> <property> <value>
        route_pattern = re.compile(
            r'set network virtual-router\s+\S+\s+routing-table ip static-route\s+(\S+)\s+(\S+)\s+(.+)',
            re.IGNORECASE
        )
        
        route_dict = {}
        for line in self.lines:
            line = line.strip()
            match = route_pattern.match(line)
            if match:
                route_name = match.group(1)
                property_name = match.group(2)
                value = match.group(3)
                
                if route_name not in route_dict:
                    route_dict[route_name] = {
                        "network": "0.0.0.0",
                        "protocol": "static",
                        "raw_config": "",
                    }
                
                route_dict[route_name]["raw_config"] += line + "\n"
                
                if "destination" in property_name:
                    route_dict[route_name]["network"] = value
                elif "nexthop" in property_name:
                    route_dict[route_name]["next_hop"] = value
                elif "interface" in property_name:
                    route_dict[route_name]["interface"] = value
        
        return list(route_dict.values())

