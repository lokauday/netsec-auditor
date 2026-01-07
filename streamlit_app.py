"""
Streamlit UI for NetSec Auditor - Security Dashboard.

Connects to the FastAPI backend to upload, parse, and audit network configurations.
"""
import streamlit as st
import requests
from io import BytesIO
from typing import Optional, Dict, Any, List
import time
import os
import pandas as pd

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
if "current_config" not in st.session_state:
    st.session_state.current_config = None
if "audit_result" not in st.session_state:
    st.session_state.audit_result = None
if "config_history" not in st.session_state:
    st.session_state.config_history = []


# ============= API Client Helpers =============

def get_base_url() -> str:
    """Get backend base URL from session state, environment, or default."""
    # Check session state first (set from sidebar)
    if "backend_url" in st.session_state:
        return st.session_state.backend_url
    # Fall back to environment variable
    return os.getenv("BACKEND_URL", "http://localhost:8000")


def get_api_key() -> Optional[str]:
    """Get API key from session state (set in sidebar)."""
    return st.session_state.get("api_key", None)


def get_headers() -> Dict[str, str]:
    """Get request headers with API key if available."""
    headers = {}
    api_key = get_api_key()
    if api_key and api_key.strip():
        headers["X-API-Key"] = api_key.strip()
    return headers


def upload_config(
    file: BytesIO,
    filename: str,
    device_name: Optional[str] = None,
    device_ip: Optional[str] = None,
    environment: Optional[str] = None,
    location: Optional[str] = None
) -> Dict[str, Any]:
    """Upload configuration file to backend."""
    url = f"{get_base_url()}/api/v1/upload/"
    headers = get_headers()
    
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
        raise Exception(f"Upload failed: {str(e)}")


def parse_config(config_id: int) -> Dict[str, Any]:
    """Parse uploaded configuration."""
    url = f"{get_base_url()}/api/v1/upload/{config_id}/parse"
    headers = get_headers()
    
    try:
        response = requests.post(url, headers=headers, timeout=60)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Parse failed: {str(e)}")


def run_audit(config_id: int) -> Dict[str, Any]:
    """Run security audit on parsed configuration."""
    url = f"{get_base_url()}/api/v1/audit/{config_id}"
    headers = get_headers()
    
    try:
        response = requests.post(url, headers=headers, timeout=120)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Audit failed: {str(e)}")


def get_config_detail(config_id: int) -> Dict[str, Any]:
    """Get detailed information about a configuration."""
    url = f"{get_base_url()}/api/v1/configs/{config_id}"
    headers = get_headers()
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to get config details: {str(e)}")


def get_audit_report_pdf(config_id: int) -> BytesIO:
    """Download PDF audit report."""
    url = f"{get_base_url()}/api/v1/audit/{config_id}/report"
    headers = get_headers()
    
    try:
        response = requests.get(url, headers=headers, timeout=60, stream=True)
        response.raise_for_status()
        return BytesIO(response.content)
    except requests.exceptions.RequestException as e:
        raise Exception(f"PDF download failed: {str(e)}")


def list_configs(limit: int = 20, offset: int = 0) -> Dict[str, Any]:
    """List configuration files with pagination."""
    url = f"{get_base_url()}/api/v1/configs/"
    headers = get_headers()
    params = {"limit": limit, "offset": offset}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to list configs: {str(e)}")


def get_config_audits(config_id: int) -> Dict[str, Any]:
    """Get audit history for a configuration."""
    url = f"{get_base_url()}/api/v1/configs/{config_id}/audits"
    headers = get_headers()
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to get audit history: {str(e)}")


# ============= UI Helper Functions =============

def get_risk_score_color(risk_score: int) -> str:
    """Get color name for risk score."""
    if risk_score <= 20:
        return "green"
    elif risk_score <= 50:
        return "yellow"
    elif risk_score <= 80:
        return "orange"
    else:
        return "red"


def format_severity_badge(severity: str) -> str:
    """Format severity as colored badge."""
    colors = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵"
    }
    emoji = colors.get(severity.lower(), "⚪")
    return f"{emoji} {severity.upper()}"


# ============= Sidebar =============

with st.sidebar:
    st.header("⚙️ Settings")
    
    backend_url = st.text_input(
        "Backend URL",
        value=get_base_url(),
        help="Base URL of the FastAPI backend",
        key="backend_url"
    )
    if backend_url != get_base_url():
        os.environ["BACKEND_URL"] = backend_url
    
    api_key = st.text_input(
        "API Key (Optional)",
        type="password",
        help="API key for authentication (leave empty if not required)",
        key="api_key"
    )
    
    st.markdown("---")
    st.header("📤 Upload Configuration")
    
    uploaded_file = st.file_uploader(
        "Choose a configuration file",
        type=["txt"],
        help="Upload router/firewall configuration file (up to 200MB)",
        key="uploaded_file"
    )
    
    st.markdown("#### Device Metadata (Optional)")
    
    device_name = st.text_input("Device Name", key="device_name")
    device_ip = st.text_input("Device IP Address", key="device_ip")
    
    environment = st.selectbox(
        "Environment",
        options=["", "Prod", "Dev", "Test", "DMZ", "Other"],
        index=0,
        key="environment"
    )
    
    location = st.text_input("Location", key="location")
    
    # Upload & Analyze button
    if st.button("🚀 Upload & Analyze", type="primary", use_container_width=True):
        if not uploaded_file:
            st.error("⚠️ Please upload a configuration file first")
        else:
            try:
                # Validate file size (200MB limit)
                file_bytes = BytesIO(uploaded_file.read())
                file_size = len(file_bytes.getvalue())
                if file_size > 200 * 1024 * 1024:
                    st.error("⚠️ File size exceeds 200MB limit")
                else:
                    file_bytes.seek(0)  # Reset to beginning
                    
                    # Upload
                    with st.spinner("📤 Uploading configuration..."):
                        upload_result = upload_config(
                            file_bytes,
                            uploaded_file.name,
                            device_name if device_name else None,
                            device_ip if device_ip else None,
                            environment if environment else None,
                            location if location else None
                        )
                        
                        if not upload_result or "id" not in upload_result:
                            raise Exception("Upload failed: Invalid response")
                        
                        config_id = upload_result["id"]
                        st.session_state.config_id = config_id
                        
                        # Get full config details
                        config_detail = get_config_detail(config_id)
                        st.session_state.current_config = config_detail
                    
                    # Parse
                    with st.spinner("🔍 Parsing configuration..."):
                        parse_result = parse_config(config_id)
                        if not parse_result or not parse_result.get("parsed"):
                            raise Exception("Parse failed: Configuration could not be parsed")
                        
                        # Refresh config details after parse
                        config_detail = get_config_detail(config_id)
                        st.session_state.current_config = config_detail
                    
                    # Audit
                    with st.spinner("🔒 Running security audit..."):
                        audit_result = run_audit(config_id)
                        if not audit_result:
                            raise Exception("Audit failed: No results returned")
                        
                        st.session_state.audit_result = audit_result
                    
                    st.success("✅ Analysis complete!")
                    st.rerun()
                    
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
    
    st.markdown("---")
    st.markdown("### 📚 Help")
    st.markdown("""
    1. Upload a network configuration file (.txt)
    2. Optionally fill in device metadata
    3. Click "Upload & Analyze"
    4. Review results in the main area
    5. Download PDF report if needed
    """)


# ============= Main Area =============

st.title("🛡️ NetSec Auditor — Security Dashboard")
st.markdown("Upload, parse, and audit network security configurations")

# Load config history if available
if st.session_state.config_id and not st.session_state.config_history:
    try:
        history = list_configs(limit=10)
        if history and "items" in history:
            st.session_state.config_history = history["items"]
    except Exception:
        pass  # Fail silently if history can't be loaded

# Tabs for organization
tab1, tab2, tab3 = st.tabs(["📊 Overview", "📋 Findings", "📜 History"])

with tab1:
    # Section 1: Current Config
    if st.session_state.config_id and st.session_state.current_config:
        st.header("📄 Current Configuration")
        
        config = st.session_state.current_config
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Config ID", config.get("id", "N/A"))
            st.metric("Vendor", config.get("vendor", "N/A").upper())
        
        with col2:
            st.metric("Device Name", config.get("device_name", "N/A"))
            st.metric("Environment", config.get("environment", "N/A"))
        
        with col3:
            st.metric("Device IP", config.get("device_ip", "N/A"))
            st.metric("Location", config.get("location", "N/A"))
        
        # Action buttons
        btn_col1, btn_col2, btn_col3 = st.columns(3)
        
        with btn_col1:
            if st.button("🔄 Re-run Parse", use_container_width=True):
                try:
                    with st.spinner("Parsing..."):
                        parse_result = parse_config(st.session_state.config_id)
                        st.success("✅ Parse complete!")
                        config_detail = get_config_detail(st.session_state.config_id)
                        st.session_state.current_config = config_detail
                        st.rerun()
                except Exception as e:
                    st.error(f"❌ Parse failed: {str(e)}")
        
        with btn_col2:
            if st.button("🔒 Re-run Audit", use_container_width=True):
                try:
                    with st.spinner("Running audit..."):
                        audit_result = run_audit(st.session_state.config_id)
                        st.session_state.audit_result = audit_result
                        st.success("✅ Audit complete!")
                        st.rerun()
                except Exception as e:
                    st.error(f"❌ Audit failed: {str(e)}")
        
        with btn_col3:
            try:
                pdf_bytes = get_audit_report_pdf(st.session_state.config_id)
                st.download_button(
                    "📄 Download PDF Report",
                    data=pdf_bytes.getvalue(),
                    file_name=f"netsec_audit_{st.session_state.config_id}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            except Exception as e:
                st.button("📄 Download PDF Report", disabled=True, use_container_width=True)
                st.caption(f"PDF not available: {str(e)}")
        
        st.markdown("---")
    
    # Section 2: Risk Overview
    if st.session_state.audit_result:
        st.header("📊 Risk Overview")
        
        audit_result = st.session_state.audit_result
        risk_score = audit_result.get("risk_score", 0)
        risk_color = get_risk_score_color(risk_score)
        
        # Risk Score Metric
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.metric(
                label="Risk Score",
                value=f"{risk_score}/100",
                delta=None
            )
            # Color indicator
            color_hex = {
                "green": "#28a745",
                "yellow": "#ffc107",
                "orange": "#fd7e14",
                "red": "#dc3545"
            }[risk_color]
            st.markdown(
                f'<div style="width: 100%; height: 20px; background-color: {color_hex}; border-radius: 5px;"></div>',
                unsafe_allow_html=True
            )
        
        with col2:
            # Severity Breakdown Chart
            breakdown = audit_result.get("breakdown", {})
            if breakdown:
                severity_data = {
                    "Critical": breakdown.get("critical", 0),
                    "High": breakdown.get("high", 0),
                    "Medium": breakdown.get("medium", 0),
                    "Low": breakdown.get("low", 0)
                }
                
                # Create bar chart using Streamlit native charting
                chart_df = pd.DataFrame({
                    "Severity": list(severity_data.keys()),
                    "Count": list(severity_data.values())
                })
                st.bar_chart(chart_df.set_index("Severity"), height=300)
                
                # Also show counts as metrics
                metric_cols = st.columns(4)
                with metric_cols[0]:
                    st.metric("🔴 Critical", severity_data["Critical"])
                with metric_cols[1]:
                    st.metric("🟠 High", severity_data["High"])
                with metric_cols[2]:
                    st.metric("🟡 Medium", severity_data["Medium"])
                with metric_cols[3]:
                    st.metric("🔵 Low", severity_data["Low"])
        
        # Summary
        summary = audit_result.get("summary", "")
        if summary:
            st.info(f"**Summary:** {summary}")
    
    else:
        st.info("👈 Upload and analyze a configuration file to see risk overview")

with tab2:
    # Section 3: Findings Table
    if st.session_state.audit_result:
        st.header("🔍 Security Findings")
        
        audit_result = st.session_state.audit_result
        findings = audit_result.get("findings", [])
        
        if findings:
            # Severity filter
            all_severities = ["All"] + list(set(f.get("severity", "unknown").lower() for f in findings))
            selected_severity = st.selectbox(
                "Filter by Severity",
                options=all_severities,
                index=0
            )
            
            # Filter findings
            filtered_findings = findings
            if selected_severity != "All":
                filtered_findings = [f for f in findings if f.get("severity", "").lower() == selected_severity.lower()]
            
            # Create DataFrame
            findings_data = []
            for finding in filtered_findings:
                findings_data.append({
                    "Severity": format_severity_badge(finding.get("severity", "unknown")),
                    "Code": finding.get("code", "N/A"),
                    "Description": finding.get("description", "No description"),
                    "Recommendation": finding.get("recommendation", "No recommendation")
                })
            
            df = pd.DataFrame(findings_data)
            
            # Display table
            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                height=400
            )
            
            st.caption(f"Showing {len(filtered_findings)} of {len(findings)} findings")
        else:
            st.success("✅ No security findings detected!")
    else:
        st.info("👈 Upload and analyze a configuration file to see findings")

with tab3:
    # Section 4: Recent History
    st.header("📜 Configuration History")
    
    try:
        history_result = list_configs(limit=20)
        
        if history_result and "items" in history_result and history_result["items"]:
            configs = history_result["items"]
            
            # Create DataFrame
            history_data = []
            for config in configs:
                history_data.append({
                    "Config ID": config.get("id"),
                    "Filename": config.get("filename", "N/A"),
                    "Vendor": config.get("vendor", "N/A").upper(),
                    "Device Name": config.get("device_name", "N/A"),
                    "Environment": config.get("environment", "N/A"),
                    "Uploaded": config.get("created_at", "N/A")[:19] if config.get("created_at") else "N/A",
                    "Parsed": "✅" if config.get("has_parsed_data") else "❌"
                })
            
            df_history = pd.DataFrame(history_data)
            
            # Display table
            st.dataframe(
                df_history,
                use_container_width=True,
                hide_index=True
            )
            
            # Config selector
            config_options = {f"{c.get('id')} - {c.get('filename', 'N/A')}": c.get("id") for c in configs}
            selected_config_label = st.selectbox(
                "Select a configuration to load:",
                options=[""] + list(config_options.keys()),
                index=0
            )
            
            if selected_config_label and selected_config_label in config_options:
                selected_config_id = config_options[selected_config_label]
                
                if st.button(f"📂 Load Config {selected_config_id}", use_container_width=True):
                    try:
                        with st.spinner(f"Loading config {selected_config_id}..."):
                            config_detail = get_config_detail(selected_config_id)
                            st.session_state.current_config = config_detail
                            st.session_state.config_id = selected_config_id
                            
                            # Try to get audit result
                            try:
                                audit_history = get_config_audits(selected_config_id)
                                if audit_history and "audits" in audit_history and audit_history["audits"]:
                                    # Get latest audit
                                    latest_audit = audit_history["audits"][0]
                                    st.info(f"Config {selected_config_id} loaded. Click 'Re-run Audit' to see results.")
                            except Exception:
                                st.info(f"Config {selected_config_id} loaded. Run audit to see results.")
                            
                            st.rerun()
                    except Exception as e:
                        st.error(f"Failed to load config: {str(e)}")
        else:
            st.info("No configuration history found")
            
    except Exception as e:
        st.error(f"Failed to load history: {str(e)}")

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #666;'>"
    "🛡️ NetSec Auditor — Network Security Configuration Analyzer"
    "</div>",
    unsafe_allow_html=True
)
