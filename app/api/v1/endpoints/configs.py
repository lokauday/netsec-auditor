"""
Config list and detail endpoints.
"""
import logging
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.auth import require_role
from app.models.config_file import ConfigFile
from app.models.acl import ACL
from app.models.nat_rule import NATRule
from app.models.vpn import VPN
from app.models.interface import Interface
from app.models.routing import Route
from app.models.audit_record import AuditRecord
from app.schemas.config import (
    ConfigListResponse,
    ConfigListItem,
    ConfigDetailResponse,
    ParsedDataDetail,
)
from app.schemas.audit import AuditHistoryResponse, AuditRecordSummary, AuditBreakdown
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=ConfigListResponse)
async def list_configs(
    limit: int = Query(default=20, ge=1, le=100, description="Number of items per page"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    _client = Depends(require_role("read_only")),
    db: Session = Depends(get_db),
):
    """
    List all configuration files with pagination.
    
    Returns a paginated list of configs with summary information including
    whether they have been parsed and can be audited.
    """
    try:
        # Get total count
        total = db.query(ConfigFile).count()
        
        # Get paginated configs
        configs = (
            db.query(ConfigFile)
            .order_by(ConfigFile.uploaded_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        
        # Build response items
        items = []
        for config in configs:
            items.append(
                ConfigListItem(
                    id=config.id,
                    filename=config.filename,
                    vendor=config.vendor.value,
                    created_at=config.uploaded_at,
                    has_parsed_data=config.parsed_at is not None,
                    has_audit_result=config.parsed_at is not None,  # Can be audited if parsed
                    device_name=config.device_name,
                    device_ip=config.device_ip,
                    environment=config.environment,
                    location=config.location,
                )
            )
        
        logger.info(f"Listed {len(items)} configs (offset={offset}, limit={limit}, total={total})")
        
        return ConfigListResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
        )
    except Exception as e:
        logger.error(f"Error listing configs: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list configuration files"
        )


@router.get("/{config_id}", response_model=ConfigDetailResponse)
async def get_config_detail(
    config_id: int,
    db: Session = Depends(get_db),
):
    """
    Get detailed information about a specific configuration file.
    
    Returns full metadata, raw content (truncated if too long), parsed data,
    and audit results if available.
    """
    try:
        # Get config file
        config = db.query(ConfigFile).filter(ConfigFile.id == config_id).first()
        if not config:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Config file with id {config_id} not found"
            )
        
        # Read raw content (truncated if necessary)
        raw_content = None
        raw_content_truncated = False
        max_content_length = 5000
        
        file_path = Path(config.file_path)
        if file_path.exists():
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                if len(content) > max_content_length:
                    raw_content = content[:max_content_length]
                    raw_content_truncated = True
                else:
                    raw_content = content
            except Exception as e:
                logger.warning(f"Could not read config file content: {e}")
                raw_content = None
        
        # Get parsed data if available
        parsed_data = None
        if config.parsed_at is not None:
            acls = db.query(ACL).filter(ACL.config_file_id == config_id).all()
            nat_rules = db.query(NATRule).filter(NATRule.config_file_id == config_id).all()
            vpns = db.query(VPN).filter(VPN.config_file_id == config_id).all()
            interfaces = db.query(Interface).filter(Interface.config_file_id == config_id).all()
            routes = db.query(Route).filter(Route.config_file_id == config_id).all()
            
            parsed_data = ParsedDataDetail(
                acls=[{
                    "id": acl.id,
                    "name": acl.name,
                    "direction": acl.direction.value,
                    "action": acl.action,
                    "source": acl.source,
                    "destination": acl.destination,
                    "protocol": acl.protocol,
                    "port": acl.port,
                } for acl in acls],
                nat_rules=[{
                    "id": nat.id,
                    "rule_name": nat.rule_name,
                    "source_original": nat.source_original,
                    "source_translated": nat.source_translated,
                    "destination_original": nat.destination_original,
                    "destination_translated": nat.destination_translated,
                } for nat in nat_rules],
                vpns=[{
                    "id": vpn.id,
                    "vpn_name": vpn.vpn_name,
                    "vpn_type": vpn.vpn_type,
                    "peer_address": vpn.peer_address,
                } for vpn in vpns],
                interfaces=[{
                    "id": interface.id,
                    "name": interface.name,
                    "ip_address": interface.ip_address,
                    "status": interface.status,
                } for interface in interfaces],
                routes=[{
                    "id": route.id,
                    "network": route.network,
                    "next_hop": route.next_hop,
                    "protocol": route.protocol,
                } for route in routes],
            )
        
        # Get audit result if available (run audit on demand)
        audit_result = None
        if config.parsed_at is not None:
            try:
                audit_service = AuditService(db)
                audit_result = audit_service.audit_config(config_id)
            except Exception as e:
                logger.warning(f"Could not generate audit result: {e}")
                audit_result = None
        
        logger.info(f"Retrieved config detail for id {config_id}")
        
        return ConfigDetailResponse(
            id=config.id,
            filename=config.filename,
            vendor=config.vendor.value,
            original_filename=config.original_filename,
            file_size=config.file_size,
            created_at=config.uploaded_at,
            parsed_at=config.parsed_at,
            device_name=config.device_name,
            device_ip=config.device_ip,
            environment=config.environment,
            location=config.location,
            raw_content=raw_content,
            raw_content_truncated=raw_content_truncated,
            parsed_data=parsed_data,
            audit_result=audit_result,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving config detail: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve configuration file details"
        )


@router.get("/{config_id}/audits", response_model=AuditHistoryResponse)
async def get_config_audit_history(
    config_id: int,
    _client = Depends(require_role("read_only")),
    db: Session = Depends(get_db),
):
    """
    Get audit history for a specific configuration file.
    
    Returns a list of all past audit records for this config, sorted by newest first.
    """
    try:
        # Verify config exists
        config = db.query(ConfigFile).filter(ConfigFile.id == config_id).first()
        if not config:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Config file with id {config_id} not found"
            )
        
        # Get all audit records for this config
        audit_records = (
            db.query(AuditRecord)
            .filter(AuditRecord.config_file_id == config_id)
            .order_by(AuditRecord.created_at.desc())
            .all()
        )
        
        # Convert to response models (summary only - no findings/breakdown)
        items = [
            AuditRecordSummary(
                id=record.id,
                config_file_id=record.config_file_id,
                risk_score=record.risk_score,
                summary=record.summary,
                created_at=record.created_at,
            )
            for record in audit_records
        ]
        
        logger.info(f"Retrieved {len(items)} audit records for config_id={config_id}")
        
        return AuditHistoryResponse(
            items=items,
            total=len(items),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving audit history: config_id={config_id}, error={e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve audit history"
        )

