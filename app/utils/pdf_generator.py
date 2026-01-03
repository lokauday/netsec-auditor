"""
PDF report generation utilities.
"""
import logging
from io import BytesIO
from datetime import datetime, timezone
from typing import Dict, Any, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus.flowables import HRFlowable

logger = logging.getLogger(__name__)


class PDFReportBuilder:
    """Builder class for creating professional PDF audit reports."""
    
    # Severity colors
    SEVERITY_COLORS = {
        'critical': colors.HexColor('#c0392b'),  # Dark red
        'high': colors.HexColor('#e74c3c'),      # Red
        'medium': colors.HexColor('#f39c12'),    # Orange
        'low': colors.HexColor('#3498db'),       # Blue
    }
    
    # Severity order for sorting
    SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    
    def __init__(self, config_file: Any, audit_result: Dict[str, Any]):
        """
        Initialize PDF report builder.
        
        Args:
            config_file: ConfigFile model instance
            audit_result: Dictionary containing audit results
        """
        self.config_file = config_file
        self.audit_result = audit_result
        self.buffer = BytesIO()
        self.story = []
        self._setup_document()
        self._setup_styles()
    
    def _setup_document(self):
        """Set up the PDF document with margins and footer."""
        self.doc = SimpleDocTemplate(
            self.buffer,
            pagesize=letter,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch,
            leftMargin=0.75*inch,
            rightMargin=0.75*inch
        )
    
    def _setup_styles(self):
        """Define custom paragraph styles for the report."""
        styles = getSampleStyleSheet()
        
        # Title style
        self.title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=20,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            leading=34
        )
        
        # Subtitle style
        self.subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#7f8c8d'),
            alignment=TA_CENTER,
            spaceAfter=15
        )
        
        # Section heading style
        self.section_style = ParagraphStyle(
            'SectionStyle',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold',
            leftIndent=0
        )
        
        # Risk score style
        self.risk_score_style = ParagraphStyle(
            'RiskScoreStyle',
            parent=styles['Normal'],
            fontSize=48,
            textColor=colors.HexColor('#2c3e50'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            spaceAfter=10
        )
        
        # Normal text style
        self.normal_style = ParagraphStyle(
            'NormalStyle',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            alignment=TA_LEFT
        )
        
        # Finding code style
        self.finding_code_style = ParagraphStyle(
            'FindingCodeStyle',
            parent=styles['Normal'],
            fontSize=11,
            fontName='Helvetica-Bold',
            spaceAfter=6
        )
        
        # Finding description style
        self.finding_desc_style = ParagraphStyle(
            'FindingDescStyle',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            alignment=TA_JUSTIFY,
            spaceAfter=8
        )
        
        # Footer style
        self.footer_style = ParagraphStyle(
            'FooterStyle',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#95a5a6'),
            alignment=TA_CENTER,
            spaceBefore=20
        )
    
    def _add_title_page(self):
        """Add professional title page header."""
        # Main title
        self.story.append(Spacer(1, 0.3*inch))
        self.story.append(Paragraph("Network Security Audit Report", self.title_style))
        self.story.append(Spacer(1, 0.4*inch))
        
        # Horizontal separator line
        self.story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#34495e'), spaceBefore=5, spaceAfter=15))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Device metadata (compact format)
        metadata_items = []
        if self.config_file.device_name:
            metadata_items.append(f"<b>Device:</b> {self.config_file.device_name}")
        if self.config_file.device_ip:
            metadata_items.append(f"<b>IP Address:</b> {self.config_file.device_ip}")
        if self.config_file.environment:
            metadata_items.append(f"<b>Environment:</b> {self.config_file.environment.title()}")
        if self.config_file.location:
            metadata_items.append(f"<b>Location:</b> {self.config_file.location}")
        
        metadata_items.append(f"<b>Vendor:</b> {self.config_file.vendor.value.replace('_', ' ').title()}")
        
        if metadata_items:
            metadata_text = " | ".join(metadata_items)
            self.story.append(Paragraph(metadata_text, self.normal_style))
            self.story.append(Spacer(1, 0.15*inch))
        
        # Timestamp
        timestamp = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M:%S UTC")
        self.story.append(Paragraph(f"<i>Generated: {timestamp}</i>", self.subtitle_style))
        self.story.append(Spacer(1, 0.4*inch))
    
    def _add_risk_score_section(self):
        """Add prominent risk score display."""
        risk_score = self.audit_result.get('risk_score', 0)
        
        # Determine risk level and color
        if risk_score >= 70:
            risk_level = "HIGH RISK"
            risk_color = colors.HexColor('#c0392b')
        elif risk_score >= 40:
            risk_level = "MEDIUM RISK"
            risk_color = colors.HexColor('#f39c12')
        else:
            risk_level = "LOW RISK"
            risk_color = colors.HexColor('#27ae60')
        
        # Risk score display box
        risk_score_text = f"{risk_score}/100"
        self.story.append(Paragraph(risk_score_text, self.risk_score_style))
        
        # Risk level label
        risk_level_style = ParagraphStyle(
            'RiskLevelStyle',
            parent=self.normal_style,
            fontSize=14,
            textColor=risk_color,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            spaceAfter=15
        )
        self.story.append(Paragraph(risk_level, risk_level_style))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Breakdown summary
        breakdown = self.audit_result.get('breakdown', {})
        if breakdown:
            breakdown_text = (
                f"Critical: {breakdown.get('critical', 0)} | "
                f"High: {breakdown.get('high', 0)} | "
                f"Medium: {breakdown.get('medium', 0)} | "
                f"Low: {breakdown.get('low', 0)}"
            )
            breakdown_style = ParagraphStyle(
                'BreakdownStyle',
                parent=self.normal_style,
                fontSize=10,
                alignment=TA_CENTER,
                spaceAfter=15
            )
            self.story.append(Paragraph(breakdown_text, breakdown_style))
        
        self.story.append(Spacer(1, 0.3*inch))
        
        # Summary
        summary = self.audit_result.get('summary', 'No summary available.')
        summary_style = ParagraphStyle(
            'SummaryStyle',
            parent=self.normal_style,
            fontSize=11,
            alignment=TA_JUSTIFY,
            spaceAfter=20,
            backColor=colors.HexColor('#ecf0f1'),
            borderPadding=10,
            leftIndent=10,
            rightIndent=10
        )
        self.story.append(Paragraph(f"<b>Executive Summary:</b><br/>{summary}", summary_style))
        self.story.append(Spacer(1, 0.2*inch))
    
    def _group_findings_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by severity level."""
        grouped = {'critical': [], 'high': [], 'medium': [], 'low': []}
        
        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            if severity in grouped:
                grouped[severity].append(finding)
            else:
                grouped['low'].append(finding)
        
        return grouped
    
    def _add_finding_item(self, finding: Dict[str, Any], index: int):
        """Add a single finding to the report."""
        severity = finding.get('severity', 'low').lower()
        code = finding.get('code', 'N/A')
        description = finding.get('description', 'No description provided.')
        recommendation = finding.get('recommendation', 'No recommendation provided.')
        affected_objects = finding.get('affected_objects', [])
        
        # Map severity to hex color strings for inline font tags
        severity_hex_map = {
            "critical": "#e74c3c",
            "high": "#e67e22",
            "medium": "#f1c40f",
            "low": "#3498db",
        }
        
        # Get hex color string for this severity
        severity_key = (severity or "").lower()
        severity_hex = severity_hex_map.get(severity_key, "#7f8c8d")
        
        # Finding code header with severity badge (using plain hex strings)
        code_text = (
            f"<font color='{severity_hex}'>{code}</font> "
            f"<font color='#7f8c8d'>({severity.upper()})</font>"
        )
        self.story.append(Paragraph(code_text, self.finding_code_style))
        self.story.append(Spacer(1, 0.05*inch))
        
        # Description
        desc_para = Paragraph(f"<b>Description:</b> {description}", self.finding_desc_style)
        self.story.append(desc_para)
        self.story.append(Spacer(1, 0.1*inch))
        
        # Affected objects (if any)
        if affected_objects:
            objects_text = ", ".join(affected_objects[:5])  # Limit to 5 for readability
            if len(affected_objects) > 5:
                objects_text += f" <i>(and {len(affected_objects) - 5} more)</i>"
            objects_para = Paragraph(f"<b>Affected Objects:</b> {objects_text}", self.finding_desc_style)
            self.story.append(objects_para)
            self.story.append(Spacer(1, 0.1*inch))
        
        # Recommendation
        rec_style = ParagraphStyle(
            'RecommendationStyle',
            parent=self.finding_desc_style,
            backColor=colors.HexColor('#f8f9fa'),
            borderPadding=8,
            leftIndent=5,
            rightIndent=5,
            spaceAfter=15
        )
        rec_para = Paragraph(f"<b>Recommendation:</b> {recommendation}", rec_style)
        self.story.append(rec_para)
        self.story.append(Spacer(1, 0.15*inch))
        
        # Separator line between findings (except last)
        self.story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#bdc3c7'), spaceBefore=5, spaceAfter=10))
    
    def _add_findings_section(self):
        """Add formatted findings section grouped by severity."""
        findings = self.audit_result.get('findings', [])
        
        if not findings:
            self.story.append(Paragraph(
                "No security findings detected. Configuration appears secure.",
                self.normal_style
            ))
            return
        
        # Section header
        self.story.append(Paragraph("Security Findings", self.section_style))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Group findings by severity
        grouped_findings = self._group_findings_by_severity(findings)
        
        # Process each severity group in order
        finding_index = 1
        for severity in ['critical', 'high', 'medium', 'low']:
            severity_findings = grouped_findings.get(severity, [])
            
            if not severity_findings:
                continue
            
            # Severity group header
            severity_color = self.SEVERITY_COLORS.get(severity, colors.black)
            severity_title = f"{severity.upper()} SEVERITY ({len(severity_findings)} finding{'s' if len(severity_findings) != 1 else ''})"
            
            severity_style = ParagraphStyle(
                'SeverityHeaderStyle',
                parent=self.section_style,
                fontSize=13,
                textColor=severity_color,
                spaceBefore=15 if finding_index > 1 else 0,
                spaceAfter=10
            )
            
            self.story.append(Paragraph(severity_title, severity_style))
            self.story.append(Spacer(1, 0.1*inch))
            
            # Add each finding in this severity group
            for finding in severity_findings:
                self._add_finding_item(finding, finding_index)
                finding_index += 1
    
    def _add_footer(self):
        """Add footer with generator info and timestamp."""
        self.story.append(Spacer(1, 0.3*inch))
        self.story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#ecf0f1'), spaceBefore=10, spaceAfter=10))
        
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        footer_text = f"Generated by NetSec Auditor | {timestamp}"
        self.story.append(Paragraph(footer_text, self.footer_style))
    
    def build(self) -> bytes:
        """
        Build the complete PDF report and return PDF bytes.
        
        Returns:
            bytes: Raw PDF bytes
        """
        # Add all sections
        self._add_title_page()
        self._add_risk_score_section()
        self._add_findings_section()
        self._add_footer()
        
        # Build PDF
        try:
            self.doc.build(self.story)
            # Get PDF bytes from buffer
            pdf_bytes = self.buffer.getvalue()
            # Close the buffer
            self.buffer.close()
            return pdf_bytes
        except Exception as e:
            logger.error(f"Error generating PDF: {e}", exc_info=True)
            # Ensure buffer is closed even on error
            try:
                self.buffer.close()
            except Exception:
                pass
            raise


def generate_audit_report_pdf(
    config_file: Any,
    audit_result: Dict[str, Any]
) -> bytes:
    """
    Generate a professional PDF report for a security audit.
    
    Args:
        config_file: ConfigFile model instance
        audit_result: Dictionary containing audit results (from AuditService.audit_config)
        
    Returns:
        bytes: Raw PDF bytes
    """
    builder = PDFReportBuilder(config_file, audit_result)
    return builder.build()
