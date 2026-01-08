"""
Service for handling configuration file operations.
"""
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from sqlalchemy.orm import Session

from app.models.config_file import ConfigFile, VendorType
from app.models.acl import ACL, ACLDirection
from app.models.nat_rule import NATRule
from app.models.vpn import VPN
from app.models.interface import Interface
from app.models.routing import Route
from app.utils.vendor_detector import detect_vendor
from app.utils.parser_factory import create_parser
from app.core.config import settings

logger = logging.getLogger(__name__)


class ConfigService:
    """Service for configuration file processing."""
    
    def __init__(self, db: Session):
        """
        Initialize config service.
        
        Args:
            db: Database session
        """
        self.db = db
        self.upload_dir = Path(settings.UPLOAD_DIR)
        try:
            self.upload_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create upload directory {self.upload_dir}: {e}")
            raise ValueError(f"Cannot create upload directory: {e}")
    
    def save_config_file(
        self,
        filename: str,
        content: bytes,
        vendor: Optional[VendorType] = None,
        device_name: Optional[str] = None,
        device_ip: Optional[str] = None,
        environment: Optional[str] = None,
        location: Optional[str] = None,
        device_id: Optional[int] = None,
    ) -> ConfigFile:
        """
        Save uploaded configuration file.
        
        Args:
            filename: Original filename
            content: File content as bytes
            vendor: Optional vendor type (will detect if not provided)
            device_name: Optional device name or hostname
            device_ip: Optional device IP address
            environment: Optional environment (e.g., prod, dev, lab)
            location: Optional location or data center name
            
        Returns:
            ConfigFile model instance
        """
        # Detect vendor if not provided
        config_content = content.decode('utf-8', errors='ignore')
        if not vendor:
            vendor = detect_vendor(config_content)
            if not vendor:
                raise ValueError("Could not detect vendor type from configuration")
        
        # Save file to disk
        file_path = self.upload_dir / f"{vendor.value}_{filename}"
        try:
            file_path.write_bytes(content)
        except Exception as e:
            logger.error(f"Failed to write file to {file_path}: {e}")
            raise ValueError(f"Cannot save file to disk: {e}")
        
        # Create database record
        # Handle device_id gracefully - if the column doesn't exist in the DB schema, set it to None
        config_file = ConfigFile(
            filename=file_path.name,
            vendor=vendor,
            original_filename=filename,
            file_path=str(file_path),
            file_size=len(content),
            device_name=device_name,
            device_ip=device_ip,
            environment=environment,
            location=location,
            device_id=device_id,  # Will be None if device lookup failed or wasn't provided
        )
        try:
            self.db.add(config_file)
            self.db.commit()
            self.db.refresh(config_file)
        except Exception as e:
            # If commit fails due to device_id column missing, try without device_id
            error_str = str(e).lower()
            if "device_id" in error_str and ("no such column" in error_str or "no column" in error_str):
                logger.warning(f"Database schema mismatch for device_id column, retrying without device_id: {e}")
                self.db.rollback()
                # Create a new object without device_id (set it to None explicitly)
                # SQLAlchemy will skip None values if the column doesn't exist
                config_file = ConfigFile(
                    filename=file_path.name,
                    vendor=vendor,
                    original_filename=filename,
                    file_path=str(file_path),
                    file_size=len(content),
                    device_name=device_name,
                    device_ip=device_ip,
                    environment=environment,
                    location=location,
                    device_id=None,  # Set to None - SQLAlchemy should handle this gracefully
                )
                # Remove device_id from the object's dict to prevent SQLAlchemy from trying to insert it
                # Actually, we can't easily do that with SQLAlchemy ORM, so we'll rely on the model
                # But if the column truly doesn't exist, we need to not set it at all
                # The issue is that SQLAlchemy will try to insert None into a non-existent column
                # So we need to check if the column exists first, or handle it differently
                # For now, let's try setting device_id to None and see if SQLAlchemy handles it
                # If it still fails, we'll need a different approach
                try:
                    self.db.add(config_file)
                    self.db.commit()
                    self.db.refresh(config_file)
                except Exception as e2:
                    # If it still fails, the column truly doesn't exist and we can't use it
                    # In this case, we need to create the object without device_id in the insert
                    # But SQLAlchemy ORM doesn't easily support this
                    # So we'll just log and re-raise - the real fix is to ensure the DB schema is up to date
                    logger.error(f"Failed to save config file even without device_id: {e2}")
                    raise ValueError(f"Database schema error: device_id column missing. Please run migrations. Original error: {e}")
            else:
                # Re-raise if it's a different error
                raise
        
        logger.info(f"Saved config file: {filename} (ID: {config_file.id}, Vendor: {vendor.value})")
        return config_file
    
    def parse_config_file(self, config_file_id: int) -> ConfigFile:
        """
        Parse configuration file and extract network elements.
        
        Args:
            config_file_id: Configuration file ID
            
        Returns:
            Updated ConfigFile model instance
        """
        config_file = self.db.query(ConfigFile).filter(ConfigFile.id == config_file_id).first()
        if not config_file:
            raise ValueError(f"Config file not found: {config_file_id}")
        
        # Read config content
        file_path = Path(config_file.file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Config file not found on disk: {file_path}")
        
        config_content = file_path.read_text(encoding='utf-8', errors='ignore')
        
        # Create parser and parse
        parser = create_parser(config_file.vendor, config_content)
        parsed_data = parser.parse_all()
        
        # Save ACLs
        from app.utils.parsers.acl_models import ParsedACLEntry
        
        for acl_data in parsed_data.get("acls", []):
            # Handle both ParsedACLEntry objects and dicts (for backward compatibility)
            if isinstance(acl_data, ParsedACLEntry):
                # Convert ParsedACLEntry to dict format for database storage
                acl_dict = {
                    "name": acl_data.name,
                    "direction": "inbound",  # Default for ASA
                    "rule_number": acl_data.sequence,
                    "source": acl_data.src,
                    "destination": acl_data.dst,
                    "protocol": acl_data.protocol,
                    "port": acl_data.dst_port or acl_data.src_port,  # Prefer dst_port
                    "action": acl_data.action,
                    "raw_config": acl_data.raw_line,
                }
            else:
                # Handle dict format (for other vendors)
                acl_dict = acl_data
            
            acl = ACL(
                config_file_id=config_file.id,
                name=acl_dict.get("name", ""),
                direction=ACLDirection(acl_dict.get("direction", "inbound")),
                rule_number=acl_dict.get("rule_number") or acl_dict.get("sequence"),
                source=acl_dict.get("source") or acl_dict.get("src"),
                destination=acl_dict.get("destination") or acl_dict.get("dst"),
                protocol=acl_dict.get("protocol"),
                port=acl_dict.get("port") or acl_dict.get("dst_port") or acl_dict.get("src_port"),
                action=acl_dict.get("action", "deny"),
                description=acl_dict.get("description"),
                raw_config=acl_dict.get("raw_config") or acl_dict.get("raw_line"),
            )
            self.db.add(acl)
        
        # Save NAT rules
        for nat_data in parsed_data.get("nat_rules", []):
            nat_rule = NATRule(
                config_file_id=config_file.id,
                rule_name=nat_data.get("rule_name"),
                rule_number=nat_data.get("rule_number"),
                source_original=nat_data.get("source_original"),
                source_translated=nat_data.get("source_translated"),
                destination_original=nat_data.get("destination_original"),
                destination_translated=nat_data.get("destination_translated"),
                interface=nat_data.get("interface"),
                protocol=nat_data.get("protocol"),
                port=nat_data.get("port"),
                description=nat_data.get("description"),
                raw_config=nat_data.get("raw_config"),
            )
            self.db.add(nat_rule)
        
        # Save VPNs
        for vpn_data in parsed_data.get("vpns", []):
            vpn = VPN(
                config_file_id=config_file.id,
                vpn_name=vpn_data.get("vpn_name", ""),
                vpn_type=vpn_data.get("vpn_type"),
                peer_address=vpn_data.get("peer_address"),
                pre_shared_key=vpn_data.get("pre_shared_key"),
                encryption=vpn_data.get("encryption"),
                authentication=vpn_data.get("authentication"),
                description=vpn_data.get("description"),
                raw_config=vpn_data.get("raw_config"),
            )
            self.db.add(vpn)
        
        # Save interfaces
        for interface_data in parsed_data.get("interfaces", []):
            interface = Interface(
                config_file_id=config_file.id,
                name=interface_data.get("name", ""),
                ip_address=interface_data.get("ip_address"),
                subnet_mask=interface_data.get("subnet_mask"),
                vlan_id=interface_data.get("vlan_id"),
                speed=interface_data.get("speed"),
                duplex=interface_data.get("duplex"),
                status=interface_data.get("status"),
                description=interface_data.get("description"),
                is_shutdown=interface_data.get("is_shutdown", False),
                raw_config=interface_data.get("raw_config"),
            )
            self.db.add(interface)
        
        # Save routes
        for route_data in parsed_data.get("routes", []):
            route = Route(
                config_file_id=config_file.id,
                network=route_data.get("network", "0.0.0.0"),
                subnet_mask=route_data.get("subnet_mask"),
                next_hop=route_data.get("next_hop"),
                interface=route_data.get("interface"),
                protocol=route_data.get("protocol", "static"),
                administrative_distance=route_data.get("administrative_distance"),
                metric=route_data.get("metric"),
                description=route_data.get("description"),
                raw_config=route_data.get("raw_config"),
            )
            self.db.add(route)
        
        # Update config file parsed timestamp
        config_file.parsed_at = datetime.now(timezone.utc)
        
        self.db.commit()
        self.db.refresh(config_file)
        
        logger.info(f"Parsed config file {config_file_id}: {len(parsed_data.get('acls', []))} ACLs, "
                   f"{len(parsed_data.get('nat_rules', []))} NAT rules, "
                   f"{len(parsed_data.get('vpns', []))} VPNs, "
                   f"{len(parsed_data.get('interfaces', []))} interfaces, "
                   f"{len(parsed_data.get('routes', []))} routes")
        
        return config_file

