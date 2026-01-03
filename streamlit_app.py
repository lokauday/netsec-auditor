"""
Streamlit UI for NetSec Auditor - Security Dashboard.

Connects to the FastAPI backend to upload, parse, and audit network configurations.
"""
import streamlit as st
import requests
from io import BytesIO
from typing import Optional, Dict, Any
import time

# Page config
st.set_page_config(
    page_title="NetSec Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if "config_id" not in st.session_state:
    st.session_state.config_id = None
if "audit_result" not in st.session_state:
    st.session_state.audit_result = None
if "last_error" not in st.session_state:
    st.session_state.last_error = None


def get_headers(api_key: Optional[str] = None) -> Dict[str, str]:
    """Get request headers with optional API key."""
    headers = {}
    if api_key and api_key.strip():
        headers["X-API-Key"] = api_key.strip()
    return headers


def upload_config(
    base_url: str,
    file: BytesIO,
    filename: str,
    device_name: Optional[str] = None,
    device_ip: Optional[str] = None,
    environment: Optional[str] = None,
    location: Optional[str] = None,
    api_key: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Upload configuration file to backend."""
    url = f"{base_url}/api/v1/upload/"
    headers = get_headers(api_key)
    
    files = {"file": (filename, file, "text/plain")}
    data = {}
    if device_name:
        data["device_name"] = device_name
    if device_ip:
        data["device_ip"] = device_ip
    if environment:
        data["environment"] = environment
    if location:
        data["location"] = location
    
    try:
        response = requests.post(url, files=files, data=data, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Upload failed: {e}")


def parse_config(base_url: str, config_id: int, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Parse uploaded configuration."""
    url = f"{base_url}/api/v1/upload/{config_id}/parse"
    headers = get_headers(api_key)
    
    try:
        response = requests.post(url, headers=headers, timeout=60)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Parse failed: {e}")


def audit_config(base_url: str, config_id: int, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Run security audit on parsed configuration."""
    url = f"{base_url}/api/v1/audit/{config_id}"
    headers = get_headers(api_key)
    
    try:
        response = requests.post(url, headers=headers, timeout=120)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Audit failed: {e}")


def get_pdf_report(base_url: str, config_id: int, api_key: Optional[str] = None) -> Optional[BytesIO]:
    """Download PDF audit report."""
    url = f"{base_url}/api/v1/audit/{config_id}/report"
    headers = get_headers(api_key)
    
    try:
        response = requests.get(url, headers=headers, timeout=60, stream=True)
        response.raise_for_status()
        return BytesIO(response.content)
    except requests.exceptions.RequestException as e:
        raise Exception(f"PDF download failed: {e}")


def format_risk_score_color(risk_score: int) -> str:
    """Get color for risk score."""
    if risk_score >= 70:
        return "🔴"
    elif risk_score >= 40:
        return "🟠"
    else:
        return "🟢"


# Sidebar - Settings
with st.sidebar:
    st.header("⚙️ Settings")
    
    api_base_url = st.text_input(
        "API Base URL",
        value="http://localhost:8000",
        help="Base URL of the FastAPI backend"
    )
    
    api_key = st.text_input(
        "API Key",
        type="password",
        help="API key for authentication (optional, leave empty if not required)",
        value=""
    )
    
    st.markdown("---")
    st.markdown("### 📚 Help")
    st.markdown("""
    1. Upload a network configuration file (.txt)
    2. Fill in optional device metadata
    3. Click "Upload → Parse → Audit"
    4. Review results and download PDF report
    """)


# Main UI
st.title("🛡️ NetSec Auditor — Security Dashboard")
st.markdown("Upload, parse, and audit network security configurations")

# Create two columns for left and right panels
col1, col2 = st.columns([1, 1])

with col1:
    st.header("📤 Upload Configuration")
    
    uploaded_file = st.file_uploader(
        "Choose a configuration file",
        type=["txt"],
        help="Upload router/firewall configuration file (Cisco ASA, IOS, Fortinet, Palo Alto)"
    )
    
    st.markdown("#### Device Metadata (Optional)")
    
    device_name = st.text_input("Device Name", value="")
    device_ip = st.text_input("Device IP Address", value="")
    
    environment = st.selectbox(
        "Environment",
        options=["", "prod", "dev", "lab", "test"],
        format_func=lambda x: "Select environment..." if x == "" else x.upper(),
        index=0
    )
    
    location = st.text_input("Location", value="")
    
    # Upload, Parse, Audit button
    if st.button("🚀 Upload → Parse → Audit", type="primary", use_container_width=True):
        if not uploaded_file:
            st.error("⚠️ Please upload a configuration file first")
        else:
            try:
                # Reset state
                st.session_state.last_error = None
                
                # Step 1: Upload
                with st.spinner("📤 Uploading configuration..."):
                    file_bytes = BytesIO(uploaded_file.read())
                    upload_result = upload_config(
                        api_base_url,
                        file_bytes,
                        uploaded_file.name,
                        device_name if device_name else None,
                        device_ip if device_ip else None,
                        environment if environment else None,
                        location if location else None,
                        api_key if api_key else None
                    )
                    
                    if not upload_result or "id" not in upload_result:
                        raise Exception("Upload failed: Invalid response from server")
                    
                    config_id = upload_result["id"]
                    st.session_state.config_id = config_id
                    st.success(f"✅ Uploaded! Config ID: {config_id}")
                
                # Step 2: Parse
                with st.spinner("🔍 Parsing configuration..."):
                    parse_result = parse_config(api_base_url, config_id, api_key if api_key else None)
                    if not parse_result or not parse_result.get("parsed"):
                        raise Exception("Parse failed: Configuration could not be parsed")
                    st.success("✅ Parsed successfully!")
                
                # Step 3: Audit
                with st.spinner("🔒 Running security audit..."):
                    audit_result = audit_config(api_base_url, config_id, api_key if api_key else None)
                    if not audit_result:
                        raise Exception("Audit failed: No results returned")
                    
                    st.session_state.audit_result = audit_result
                    st.success("✅ Audit complete!")
                
                # Trigger rerun to show results
                st.rerun()
                
            except Exception as e:
                error_msg = str(e)
                st.session_state.last_error = error_msg
                st.error(f"❌ Error: {error_msg}")
    
    # Display last error if any
    if st.session_state.last_error:
        st.error(f"❌ Last Error: {st.session_state.last_error}")
    
    # Show current config ID if available
    if st.session_state.config_id:
        st.info(f"📄 Current Config ID: {st.session_state.config_id}")


with col2:
    st.header("📊 Audit Results")
    
    if st.session_state.audit_result:
        audit_result = st.session_state.audit_result
        
        # Risk Score
        risk_score = audit_result.get("risk_score", 0)
        risk_emoji = format_risk_score_color(risk_score)
        
        st.markdown("### Risk Assessment")
        st.metric(
            label=f"{risk_emoji} Risk Score",
            value=f"{risk_score}/100",
            delta=None
        )
        
        # Breakdown
        breakdown = audit_result.get("breakdown", {})
        if breakdown:
            st.markdown("#### Severity Breakdown")
            breakdown_cols = st.columns(4)
            
            with breakdown_cols[0]:
                st.metric("🔴 Critical", breakdown.get("critical", 0))
            with breakdown_cols[1]:
                st.metric("🟠 High", breakdown.get("high", 0))
            with breakdown_cols[2]:
                st.metric("🟡 Medium", breakdown.get("medium", 0))
            with breakdown_cols[3]:
                st.metric("🔵 Low", breakdown.get("low", 0))
        
        # Total Findings
        total_findings = audit_result.get("total_findings", 0)
        st.markdown(f"**Total Findings:** {total_findings}")
        
        # Summary
        summary = audit_result.get("summary", "")
        if summary:
            st.markdown("#### Executive Summary")
            st.info(summary)
        
        # Findings List
        findings = audit_result.get("findings", [])
        if findings:
            st.markdown("#### Security Findings")
            
            # Group findings by severity
            severity_groups = {
                "critical": [],
                "high": [],
                "medium": [],
                "low": []
            }
            
            for finding in findings:
                severity = finding.get("severity", "low").lower()
                if severity in severity_groups:
                    severity_groups[severity].append(finding)
            
            # Display findings by severity
            severity_order = ["critical", "high", "medium", "low"]
            severity_emojis = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵"
            }
            
            for severity in severity_order:
                group_findings = severity_groups[severity]
                if group_findings:
                    st.markdown(f"##### {severity_emojis[severity]} {severity.upper()} SEVERITY ({len(group_findings)})")
                    
                    for idx, finding in enumerate(group_findings, 1):
                        with st.expander(
                            f"**{finding.get('code', 'N/A')}** - {finding.get('severity', 'unknown').upper()}",
                            expanded=(severity in ["critical", "high"])
                        ):
                            st.markdown(f"**Description:**")
                            st.write(finding.get("description", "No description provided."))
                            
                            affected_objects = finding.get("affected_objects", [])
                            if affected_objects:
                                st.markdown(f"**Affected Objects:**")
                                st.write(", ".join(affected_objects))
                            
                            st.markdown(f"**Recommendation:**")
                            st.success(finding.get("recommendation", "No recommendation provided."))
        
        # PDF Download Button
        if st.session_state.config_id:
            st.markdown("---")
            try:
                pdf_bytes = get_pdf_report(
                    api_base_url,
                    st.session_state.config_id,
                    api_key if api_key else None
                )
                
                if pdf_bytes:
                    st.download_button(
                        label="📄 Download PDF Report",
                        data=pdf_bytes.getvalue(),
                        file_name=f"netsec_audit_{st.session_state.config_id}.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                        type="primary"
                    )
            except Exception as e:
                st.warning(f"⚠️ PDF download not available: {e}")
        
    else:
        st.info("👈 Upload and audit a configuration file to see results here")
        
        # Show example structure
        with st.expander("📋 Example Output Structure"):
            st.json({
                "risk_score": 65,
                "total_findings": 3,
                "breakdown": {
                    "critical": 1,
                    "high": 1,
                    "medium": 1,
                    "low": 0
                },
                "summary": "Found 3 security findings...",
                "findings": [
                    {
                        "severity": "critical",
                        "code": "ACL_ANY_ANY_INBOUND",
                        "description": "Inbound ACL allows any-to-any traffic",
                        "recommendation": "Restrict ACL rules to specific sources and destinations"
                    }
                ]
            })


# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #666;'>"
    "🛡️ NetSec Auditor — Network Security Configuration Analyzer"
    "</div>",
    unsafe_allow_html=True
)

