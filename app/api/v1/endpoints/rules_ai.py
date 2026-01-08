"""
AI rule suggestion endpoint.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.auth import require_role, APIClient
from app.core.roles import Role
from app.services.ai_service import AIService

logger = logging.getLogger(__name__)

router = APIRouter()


class RuleSuggestionRequest(BaseModel):
    """Request for AI rule suggestion."""
    description: str = Field(..., min_length=1, max_length=500, description="Natural language description of the rule to create")
    vendor_hint: str = Field(None, description="Optional vendor hint (e.g., 'cisco_asa', 'fortinet', 'palo_alto')")


class RuleSuggestionResponse(BaseModel):
    """Response with AI-suggested rule definition."""
    name: str
    description: str
    vendor: str = None
    category: str
    severity: str
    match_criteria: dict


@router.post("/ai-suggest", response_model=RuleSuggestionResponse)
async def suggest_rule_with_ai(
    request: RuleSuggestionRequest,
    client: APIClient = Depends(require_role("security_analyst")),  # security_analyst or above
    db: Session = Depends(get_db),
):
    """
    Generate AI-suggested rule definition from natural language description.
    
    Security Analyst or Admin role required.
    """
    try:
        ai_service = AIService()
        
        if not ai_service.is_available():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OpenAI API key not configured. AI rule suggestions are not available."
            )
        
        suggestion = ai_service.suggest_rule(
            description=request.description,
            vendor_hint=request.vendor_hint,
        )
        
        logger.info(f"AI rule suggestion generated for: '{request.description}'")
        
        return RuleSuggestionResponse(**suggestion)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error generating AI rule suggestion: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate rule suggestion"
        )

