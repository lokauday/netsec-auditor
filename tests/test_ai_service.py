"""
Tests for AI service with mocked OpenAI client.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from app.services.ai_service import AIService
from app.core.config import settings


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client."""
    with patch('app.services.ai_service.OpenAI') as mock_openai:
        mock_client = MagicMock()
        mock_openai.return_value = mock_client
        yield mock_client


@pytest.fixture
def ai_service():
    """Create AI service instance."""
    return AIService()


class TestAIService:
    """Test AI service functionality."""
    
    def test_is_available_without_openai_key(self, ai_service):
        """Test that AI service is not available without OpenAI key."""
        with patch.object(settings, 'is_openai_available', return_value=False):
            assert ai_service.is_available() is False
    
    def test_is_available_with_openai_key(self, ai_service, mock_openai_client):
        """Test that AI service is available with OpenAI key."""
        with patch.object(settings, 'is_openai_available', return_value=True):
            with patch.object(settings, 'OPENAI_API_KEY', 'test-key'):
                assert ai_service.is_available() is True
    
    def test_explain_finding_success(self, ai_service, mock_openai_client):
        """Test successful finding explanation."""
        with patch.object(settings, 'is_openai_available', return_value=True):
            with patch.object(settings, 'OPENAI_API_KEY', 'test-key'):
                with patch.object(settings, 'OPENAI_MODEL', 'gpt-4'):
                    # Mock OpenAI response
                    mock_response = MagicMock()
                    mock_response.choices = [MagicMock()]
                    mock_response.choices[0].message.content = '{"ai_explanation": "Test explanation", "business_impact": "Test impact", "attack_path": "Test path", "remediation_steps": "Test steps"}'
                    mock_openai_client.chat.completions.create.return_value = mock_response
                    
                    result = ai_service.explain_finding(
                        finding_code="TEST_CODE",
                        finding_description="Test finding",
                        finding_severity="high",
                        affected_objects=["obj1", "obj2"]
                    )
                    
                    assert result["ai_explanation"] == "Test explanation"
                    assert result["business_impact"] == "Test impact"
                    assert result["attack_path"] == "Test path"
                    assert result["remediation_steps"] == "Test steps"
    
    def test_explain_finding_handles_errors(self, ai_service, mock_openai_client):
        """Test that explain_finding handles errors gracefully."""
        with patch.object(settings, 'is_openai_available', return_value=True):
            with patch.object(settings, 'OPENAI_API_KEY', 'test-key'):
                # Mock OpenAI to raise exception
                mock_openai_client.chat.completions.create.side_effect = Exception("API Error")
                
                result = ai_service.explain_finding(
                    finding_code="TEST_CODE",
                    finding_description="Test finding",
                    finding_severity="high",
                    affected_objects=["obj1"]
                )
                
                # Should return None values on error
                assert result["ai_explanation"] is None
                assert result["business_impact"] is None
                assert result["attack_path"] is None
                assert result["remediation_steps"] is None
    
    def test_suggest_rule_success(self, ai_service, mock_openai_client):
        """Test successful rule suggestion."""
        with patch.object(settings, 'is_openai_available', return_value=True):
            with patch.object(settings, 'OPENAI_API_KEY', 'test-key'):
                with patch.object(settings, 'OPENAI_MODEL', 'gpt-4'):
                    # Mock OpenAI response
                    mock_response = MagicMock()
                    mock_response.choices = [MagicMock()]
                    mock_response.choices[0].message.content = '{"name": "Test Rule", "description": "Test desc", "vendor": "cisco_asa", "category": "acl", "severity": "high", "match_criteria": {"pattern": "test", "pattern_type": "contains"}}'
                    mock_openai_client.chat.completions.create.return_value = mock_response
                    
                    result = ai_service.suggest_rule("Detect test patterns")
                    
                    assert result["name"] == "Test Rule"
                    assert result["description"] == "Test desc"
                    assert result["vendor"] == "cisco_asa"
                    assert result["category"] == "acl"
                    assert result["severity"] == "high"
                    assert "match_criteria" in result
    
    def test_suggest_rule_without_openai_key(self, ai_service):
        """Test that suggest_rule raises error without OpenAI key."""
        with patch.object(settings, 'is_openai_available', return_value=False):
            with pytest.raises(ValueError, match="OpenAI API key not configured"):
                ai_service.suggest_rule("Test description")
    
    def test_suggest_rule_handles_errors(self, ai_service, mock_openai_client):
        """Test that suggest_rule handles errors."""
        with patch.object(settings, 'is_openai_available', return_value=True):
            with patch.object(settings, 'OPENAI_API_KEY', 'test-key'):
                # Mock OpenAI to raise exception
                mock_openai_client.chat.completions.create.side_effect = Exception("API Error")
                
                with pytest.raises(ValueError, match="Failed to generate rule suggestion"):
                    ai_service.suggest_rule("Test description")

