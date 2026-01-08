"""
AI service for generating explanations and rule suggestions.
"""
import logging
import json
from typing import Optional, Dict, Any, List
from app.core.config import settings

logger = logging.getLogger(__name__)


class AIService:
    """Service for AI-powered explanations and suggestions."""
    
    def __init__(self):
        """Initialize AI service."""
        self._client = None
    
    @property
    def client(self):
        """Lazy-load OpenAI client."""
        if self._client is None and settings.is_openai_available():
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=settings.OPENAI_API_KEY)
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI client: {e}")
                return None
        return self._client
    
    def is_available(self) -> bool:
        """Check if AI service is available."""
        return settings.is_openai_available() and self.client is not None
    
    def explain_finding(
        self,
        finding_code: str,
        finding_description: str,
        finding_severity: str,
        affected_objects: List[str],
        config_context: Optional[str] = None,
    ) -> Dict[str, Optional[str]]:
        """
        Generate AI explanation for a security finding.
        
        Args:
            finding_code: Finding code (e.g., "ACL_ANY_ANY_INBOUND")
            finding_description: Finding description
            finding_severity: Finding severity
            affected_objects: List of affected objects
            config_context: Optional configuration context (relevant config snippet)
            
        Returns:
            Dictionary with ai_explanation, business_impact, attack_path, remediation_steps
        """
        if not self.is_available():
            return {
                "ai_explanation": None,
                "business_impact": None,
                "attack_path": None,
                "remediation_steps": None,
            }
        
        try:
            prompt = f"""You are a network security expert. Analyze this security finding and provide a detailed explanation.

Finding Code: {finding_code}
Severity: {finding_severity}
Description: {finding_description}
Affected Objects: {', '.join(affected_objects[:5])}
{f'Config Context: {config_context[:500]}' if config_context else ''}

Provide a JSON response with the following fields:
1. "ai_explanation": A clear, technical explanation of why this finding is a security concern (2-3 sentences)
2. "business_impact": The business/operational impact if this vulnerability is exploited (2-3 sentences)
3. "attack_path": A realistic attack scenario describing how an attacker could exploit this (2-3 sentences)
4. "remediation_steps": Step-by-step remediation guidance (numbered list, 3-5 steps)

Return only valid JSON, no markdown formatting."""

            response = self.client.chat.completions.create(
                model=settings.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a network security expert. Always return valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                response_format={"type": "json_object"},
            )
            
            content = response.choices[0].message.content
            
            # Parse JSON response
            try:
                ai_data = json.loads(content)
            except json.JSONDecodeError:
                # Try to extract JSON from markdown code blocks
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    ai_data = json.loads(content[json_start:json_end])
                else:
                    logger.warning(f"AI response did not contain valid JSON for finding {finding_code}")
                    return {
                        "ai_explanation": None,
                        "business_impact": None,
                        "attack_path": None,
                        "remediation_steps": None,
                    }
            
            return {
                "ai_explanation": ai_data.get("ai_explanation"),
                "business_impact": ai_data.get("business_impact"),
                "attack_path": ai_data.get("attack_path"),
                "remediation_steps": ai_data.get("remediation_steps"),
            }
        except Exception as e:
            logger.error(f"AI explanation error for finding {finding_code}: {e}", exc_info=True)
            return {
                "ai_explanation": None,
                "business_impact": None,
                "attack_path": None,
                "remediation_steps": None,
            }
    
    def suggest_rule(
        self,
        description: str,
        vendor_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate AI suggestion for a security rule based on natural language description.
        
        Args:
            description: Natural language description (e.g., "Detect outbound DNS tunnels")
            vendor_hint: Optional vendor hint (e.g., "cisco_asa", "fortinet")
            
        Returns:
            Dictionary with suggested rule fields:
            - name: Rule name
            - description: Rule description
            - vendor: Suggested vendor (or None for vendor-agnostic)
            - category: Suggested category
            - severity: Suggested severity
            - match_criteria: Suggested match criteria (JSON structure)
        """
        if not self.is_available():
            raise ValueError("OpenAI API key not configured")
        
        try:
            prompt = f"""You are a network security expert specializing in firewall and network device configuration analysis.

A user wants to create a security rule with this description: "{description}"
{f'Target vendor: {vendor_hint}' if vendor_hint else 'Vendor-agnostic (works for all vendors)'}

Generate a security rule definition. Return a JSON object with:
1. "name": A concise rule name (e.g., "Outbound DNS Tunnel Detection")
2. "description": A detailed description of what the rule detects
3. "vendor": The vendor type (e.g., "cisco_asa", "fortinet", "palo_alto", or null for vendor-agnostic)
4. "category": One of: "acl", "nat", "vpn", "routing", "interface", "crypto", "authentication", "general"
5. "severity": One of: "critical", "high", "medium", "low"
6. "match_criteria": A JSON object with pattern matching criteria. Common fields:
   - "pattern": Text pattern to search for (regex or literal)
   - "pattern_type": One of: "regex", "contains", "equals", "starts_with", "ends_with"
   - "acl_name": ACL name pattern (if applicable)
   - "acl_source": Source address pattern (if applicable)
   - "acl_destination": Destination address pattern (if applicable)
   - "acl_protocol": Protocol (tcp, udp, ip, etc.) (if applicable)
   - "acl_port": Port or service name (if applicable)
   - "acl_action": Action (permit, deny) (if applicable)

Example match_criteria for "permit any any":
{{"pattern": "permit ip any any", "pattern_type": "contains"}}

Example match_criteria for "SSH from internet":
{{"pattern": "permit tcp.*eq 22", "pattern_type": "regex", "acl_protocol": "tcp", "acl_port": "22"}}

Return only valid JSON, no markdown formatting."""

            response = self.client.chat.completions.create(
                model=settings.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a network security expert. Always return valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.5,  # Slightly higher for creativity
                response_format={"type": "json_object"},
            )
            
            content = response.choices[0].message.content
            
            # Parse JSON response
            try:
                ai_data = json.loads(content)
            except json.JSONDecodeError:
                # Try to extract JSON from markdown code blocks
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    ai_data = json.loads(content[json_start:json_end])
                else:
                    logger.warning("AI response did not contain valid JSON for rule suggestion")
                    raise ValueError("AI did not return valid rule suggestion")
            
            return {
                "name": ai_data.get("name", description),
                "description": ai_data.get("description", description),
                "vendor": ai_data.get("vendor"),
                "category": ai_data.get("category", "general"),
                "severity": ai_data.get("severity", "medium"),
                "match_criteria": ai_data.get("match_criteria", {}),
            }
        except Exception as e:
            logger.error(f"AI rule suggestion error: {e}", exc_info=True)
            raise ValueError(f"Failed to generate rule suggestion: {e}")

