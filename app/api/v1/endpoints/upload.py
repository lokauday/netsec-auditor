"""
Upload endpoint for configuration files.

ROUTE ALIGNMENT (Critical for production):
- FastAPI route: POST /api/v1/upload/ (with trailing slash)
- Streamlit UI calls: POST /api/v1/upload/ (with trailing slash)
- Router prefix: /upload (from app/api/v1/router.py)
- Full path: /api/v1/upload/ (from app/main.py prefix + router prefix + route path)

This route must match exactly what the UI calls to prevent "Method Not Allowed" errors.
See tests/test_routes_upload_path.py and tests/test_upload_ui_flow.py for verification.
"""
import logging
from typing import Optional
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, status, Security, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.auth import require_role, get_current_api_client, APIClient
from app.services.config_service import ConfigService
from app.services.activity_service import log_activity, ActivityAction, ResourceType
from app.schemas.config import ConfigFileResponse, ConfigParseResponse
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/", response_model=ConfigFileResponse, status_code=status.HTTP_201_CREATED)
async def upload_config_file(
    file: UploadFile = File(...),
    device_name: Optional[str] = Form(None, description="Device name or hostname"),
    device_ip: Optional[str] = Form(None, description="Device IP address"),
    environment: Optional[str] = Form(None, description="Environment (e.g., prod, dev, lab)"),
    location: Optional[str] = Form(None, description="Location or data center name"),
    device_id: Optional[int] = Form(None, description="Existing device ID to link config to"),
    client: APIClient = Depends(require_role("operator")),  # Changed from read_only to operator
    request: Request = None,
    db: Session = Depends(get_db)
):
    """
    Upload a router/firewall configuration file.
    
    Supports: Cisco ASA, Cisco IOS, Fortinet, Palo Alto
    
    Optional metadata fields:
    - device_name: Device name or hostname
    - device_ip: Device IP address
    - environment: Environment type (prod, dev, lab, etc.)
    - location: Location or data center name
    """
    try:
        # Validate file type
        if not file.filename.endswith('.txt'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only .txt files are supported"
            )
        
        # Read file content
        content = await file.read()
        
        # Validate file size
        if len(content) > settings.MAX_UPLOAD_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File size exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE} bytes"
            )
        
        # Handle device linking
        from app.models.device import Device
        
        linked_device_id = device_id
        
        # If device_id not provided but device_name is, try to find existing device
        # Wrap in try/except to handle case where devices table doesn't exist (e.g., in tests or migrations)
        if not linked_device_id and device_name:
            try:
                existing_device = db.query(Device).filter(Device.hostname == device_name).first()
                if existing_device:
                    linked_device_id = existing_device.id
            except Exception as e:
                # If device lookup fails (e.g., table doesn't exist), log and continue without device linking
                logger.debug(f"Could not lookup device by name '{device_name}': {e}. Continuing without device linking.")
                linked_device_id = None
        
        # Save and parse
        service = ConfigService(db)
        config_file = service.save_config_file(
            filename=file.filename,
            content=content,
            device_name=device_name,
            device_ip=device_ip,
            environment=environment,
            location=location,
            device_id=linked_device_id,
        )
        
        logger.info(
            f"Config uploaded successfully: filename='{file.filename}', "
            f"vendor={config_file.vendor.value}, config_id={config_file.id}, "
            f"file_size={config_file.file_size} bytes, "
            f"device_name={device_name}, environment={environment}"
        )
        
        # Log activity (non-critical - if it fails, don't fail the upload)
        try:
            log_activity(
                db=db,
                client=client,
                action=ActivityAction.CONFIG_UPLOAD,
                resource_type=ResourceType.CONFIG_FILE,
                resource_id=config_file.id,
                details={
                    "filename": file.filename,
                    "vendor": config_file.vendor.value,
                    "file_size": config_file.file_size,
                    "device_name": device_name,
                    "environment": environment,
                },
                request=request,
            )
        except Exception as e:
            # Activity logging is non-critical - log error but don't fail the upload
            logger.warning(f"Failed to log activity for upload (config_id={config_file.id}): {e}")
        
        return ConfigFileResponse(
            id=config_file.id,
            filename=config_file.filename,
            vendor=config_file.vendor.value,
            original_filename=config_file.original_filename,
            file_size=config_file.file_size,
            uploaded_at=config_file.uploaded_at,
            parsed_at=config_file.parsed_at,
            device_name=config_file.device_name,
            device_ip=config_file.device_ip,
            environment=config_file.environment,
            location=config_file.location,
            device_id=config_file.device_id,
        )
    except HTTPException:
        # Re-raise HTTPExceptions (like validation errors) as-is
        raise
    except ValueError as e:
        logger.error(f"Validation error during upload: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        error_type = type(e).__name__
        error_msg = str(e)
        logger.error(
            f"Error during config upload (type: {error_type}): {error_msg}",
            exc_info=True
        )
        # In debug mode, return more detailed error information
        if settings.DEBUG:
            detail = f"Failed to upload configuration file: {error_type}: {error_msg}"
        else:
            detail = "Failed to upload configuration file. Check server logs for details."
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )


@router.post("/{config_file_id}/parse", response_model=ConfigParseResponse)
async def parse_config_file(
    config_file_id: int,
    client: APIClient = Depends(require_role("operator")),  # Changed from read_only to operator
    request: Request = None,
    db: Session = Depends(get_db)
):
    """
    Parse an uploaded configuration file to extract network elements.
    """
    try:
        service = ConfigService(db)
        config_file = service.parse_config_file(config_file_id)
        
        # Get counts
        from app.models.acl import ACL
        from app.models.nat_rule import NATRule
        from app.models.vpn import VPN
        from app.models.interface import Interface
        from app.models.routing import Route
        
        acl_count = db.query(ACL).filter(ACL.config_file_id == config_file_id).count()
        nat_count = db.query(NATRule).filter(NATRule.config_file_id == config_file_id).count()
        vpn_count = db.query(VPN).filter(VPN.config_file_id == config_file_id).count()
        interface_count = db.query(Interface).filter(Interface.config_file_id == config_file_id).count()
        route_count = db.query(Route).filter(Route.config_file_id == config_file_id).count()
        
        logger.info(
            f"Config parsed successfully: config_id={config_file_id}, "
            f"vendor={config_file.vendor.value}, "
            f"elements=[ACLs:{acl_count}, NAT:{nat_count}, VPNs:{vpn_count}, "
            f"Interfaces:{interface_count}, Routes:{route_count}]"
        )
        
        # Log activity
        log_activity(
            db=db,
            client=client,
            action=ActivityAction.CONFIG_PARSE,
            resource_type=ResourceType.CONFIG_FILE,
            resource_id=config_file_id,
            details={
                "vendor": config_file.vendor.value,
                "elements_parsed": {
                    "acls": acl_count,
                    "nat_rules": nat_count,
                    "vpns": vpn_count,
                    "interfaces": interface_count,
                    "routes": route_count,
                }
            },
            request=request,
        )
        
        return ConfigParseResponse(
            config_file_id=config_file.id,
            parsed=True,
            parsed_at=config_file.parsed_at,
            elements_parsed={
                "acls": acl_count,
                "nat_rules": nat_count,
                "vpns": vpn_count,
                "interfaces": interface_count,
                "routes": route_count,
            }
        )
    except ValueError as e:
        logger.error(f"Parser failed for config_id={config_file_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except FileNotFoundError as e:
        logger.error(f"Config file not found on disk: config_id={config_file_id}, error={e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Parser error for config_id={config_file_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to parse configuration file"
        )

