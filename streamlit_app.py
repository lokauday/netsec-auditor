"""
Streamlit UI for NetSec Auditor - Security Dashboard.

Connects to the FastAPI backend to upload, parse, and audit network configurations.
"""
import streamlit as st
import requests
from io import BytesIO
from typing import Optional, Dict, Any, List
from datetime import datetime
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
if "api_key" not in st.session_state:
    st.session_state.api_key = None
if "is_admin" not in st.session_state:
    st.session_state.is_admin = False
# ============= API Client Helpers =============

def get_api_base_url() -> str:
    """
    Normalize API base URL from environment variable.
    
    Handles both bare hostnames and full URLs:
    - Empty env var -> http://localhost:8000 (local dev)
    - Full URL (http:// or https://) -> use as-is
    - Bare hostname -> prepend https://
    """
    raw = os.getenv("API_BASE_URL", "").strip().rstrip("/")
    
    # If the env var is empty, default to local dev
    if not raw:
        return "http://localhost:8000"
    
    # If it already looks like a full URL, trust it
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    
    # Otherwise treat it as a bare host and make it HTTPS by default
    return f"https://{raw}"


# Set global constant for API base URL
API_BASE_URL = get_api_base_url()

# Debug print at startup
print(f"[NetSec Auditor UI] Using API_BASE_URL = {API_BASE_URL}")


def get_api_key() -> Optional[str]:
    """Get API key from session state (set in sidebar)."""
    return st.session_state.get("api_key", None)


def check_admin_status() -> bool:
    """Check if current user is admin by calling /auth/me endpoint."""
    try:
        url = f"{API_BASE_URL}/api/v1/auth/me"
        headers = get_headers()
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("is_admin", False)
    except Exception:
        pass
    return False


def get_headers() -> Dict[str, str]:
    """Get request headers with API key if available."""
    headers = {}
    api_key = get_api_key()
    if api_key and api_key.strip():
        headers["X-API-Key"] = api_key.strip()
    return headers


def get_activity_logs(
    limit: int = 50,
    offset: int = 0,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    actor_id: Optional[int] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Fetch activity logs from the API."""
    try:
        url = f"{API_BASE_URL}/api/v1/activity/"
        headers = get_headers()
        params = {
            "limit": limit,
            "offset": offset,
        }
        if start_date:
            params["start_date"] = start_date.isoformat()
        if end_date:
            params["end_date"] = end_date.isoformat()
        if actor_id:
            params["actor_id"] = actor_id
        if action:
            params["action"] = action
        if resource_type:
            params["resource_type"] = resource_type
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"Failed to fetch activity logs: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        handle_api_error(e)
        return None


def handle_api_error(e: requests.exceptions.RequestException) -> None:
    """Handle API errors with user-friendly messages."""
    if isinstance(e, requests.exceptions.HTTPError):
        if e.response.status_code == 401:
            st.error("❌ Authentication failed. Please check your API key.")
        elif e.response.status_code == 403:
            st.error("❌ Access denied. You don't have permission to perform this action.")
        elif e.response.status_code == 404:
            st.error("❌ Resource not found.")
        elif e.response.status_code >= 500:
            st.error("❌ Server error. Please try again later.")
        else:
            try:
                error_detail = e.response.json().get("detail", str(e))
                st.error(f"❌ Error: {error_detail}")
            except:
                st.error(f"❌ Error: {str(e)}")
    else:
        st.error(f"❌ Request failed: {str(e)}")


def upload_config(
    file: BytesIO,
    filename: str,
    device_name: Optional[str] = None,
    device_ip: Optional[str] = None,
    environment: Optional[str] = None,
    location: Optional[str] = None
) -> Dict[str, Any]:
    """Upload configuration file to backend."""
    url = f"{API_BASE_URL}/api/v1/upload/"
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
        if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code in [401, 403]:
            handle_api_error(e)
        raise Exception(f"Upload failed: {str(e)}")


def parse_config(config_id: int) -> Dict[str, Any]:
    """Parse uploaded configuration."""
    url = f"{API_BASE_URL}/api/v1/upload/{config_id}/parse"
    headers = get_headers()
    
    try:
        response = requests.post(url, headers=headers, timeout=60)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Parse failed: {str(e)}")


def run_audit(config_id: int, ai_enabled: bool = False) -> Dict[str, Any]:
    """Run security audit on parsed configuration."""
    url = f"{API_BASE_URL}/api/v1/audit/{config_id}"
    headers = get_headers()
    
    try:
        response = requests.post(
            url,
            headers=headers,
            json={"ai_enabled": ai_enabled},
            timeout=120
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code in [401, 403]:
            handle_api_error(e)
        raise Exception(f"Audit failed: {str(e)}")


def get_config_detail(config_id: int) -> Dict[str, Any]:
    """Get detailed information about a configuration."""
    url = f"{API_BASE_URL}/api/v1/configs/{config_id}"
    headers = get_headers()
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to get config details: {str(e)}")


def get_audit_report_pdf(config_id: int) -> BytesIO:
    """Download PDF audit report."""
    url = f"{API_BASE_URL}/api/v1/audit/{config_id}/report"
    headers = get_headers()
    
    try:
        response = requests.get(url, headers=headers, timeout=60, stream=True)
        response.raise_for_status()
        return BytesIO(response.content)
    except requests.exceptions.RequestException as e:
        raise Exception(f"PDF download failed: {str(e)}")


def list_configs(limit: int = 20, offset: int = 0) -> Dict[str, Any]:
    """List configuration files with pagination."""
    url = f"{API_BASE_URL}/api/v1/configs/"
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
    url = f"{API_BASE_URL}/api/v1/configs/{config_id}/audits"
    headers = get_headers()
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to get audit history: {str(e)}")


def get_audit_summary(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    vendor: Optional[str] = None,
    environment: Optional[str] = None,
) -> Dict[str, Any]:
    """Get audit summary/analytics with optional filters."""
    url = f"{API_BASE_URL}/api/v1/audits/summary"
    headers = get_headers()
    params = {}
    
    if start_date:
        params["start_date"] = start_date
    if end_date:
        params["end_date"] = end_date
    if vendor:
        params["vendor"] = vendor
    if environment:
        params["environment"] = environment
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        handle_api_error(e)
        return {}


def get_audit_history(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    vendor: Optional[str] = None,
    environment: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    """Get filtered audit history."""
    url = f"{API_BASE_URL}/api/v1/audits/history"
    headers = get_headers()
    params = {"limit": limit, "offset": offset}
    if start_date:
        params["start_date"] = start_date
    if end_date:
        params["end_date"] = end_date
    if vendor:
        params["vendor"] = vendor
    if environment:
        params["environment"] = environment
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        handle_api_error(e)
        return {"items": [], "total": 0}


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
    
    # Display API base URL (read-only, set via API_BASE_URL env var)
    st.text_input(
        "Backend URL",
        value=API_BASE_URL,
        disabled=True,
        help="Set via API_BASE_URL environment variable"
    )
    
    api_key = st.text_input(
        "API Key (Optional)",
        type="password",
        help="API key for authentication (leave empty if not required)",
        value=st.session_state.get("api_key", ""),
        key="api_key_input"
    )
    # Store in session state
    if api_key:
        st.session_state.api_key = api_key.strip()
    else:
        st.session_state.api_key = None
    
    # Check admin status if API key is provided
    if st.session_state.api_key:
        try:
            with st.spinner("Checking permissions..."):
                st.session_state.is_admin = check_admin_status()
        except Exception:
            st.session_state.is_admin = False
    else:
        st.session_state.is_admin = False
    
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
tab_names = ["📊 Overview", "📋 Findings", "📜 History", "🔧 Rules", "📝 Audit Trail"]
if st.session_state.is_admin:
    tab_names.append("🔐 Admin: API Keys")
tabs = st.tabs(tab_names)
tab1, tab2, tab3, tab_rules, tab_audit = tabs[0], tabs[1], tabs[2], tabs[3], tabs[4]
tab_admin = tabs[5] if st.session_state.is_admin else None

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
            # AI toggle for re-run
            ai_enabled_rerun = False
            try:
                import os
                if os.getenv("OPENAI_API_KEY"):
                    ai_enabled_rerun = st.checkbox(
                        "🤖 AI-assisted",
                        value=False,
                        key="ai_enabled_rerun",
                        help="Enable AI analysis"
                    )
            except:
                pass
            
            if st.button("🔒 Re-run Audit", use_container_width=True):
                try:
                    with st.spinner("Running audit..."):
                        audit_result = run_audit(st.session_state.config_id, ai_enabled=ai_enabled_rerun)
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
        
        # AI status
        if audit_result.get("ai_enabled"):
            ai_count = audit_result.get("ai_findings_count", 0)
            if ai_count > 0:
                st.success(f"🤖 AI-assisted analysis enabled: {ai_count} AI recommendation(s) shown.")
            else:
                st.info("🤖 AI-assisted analysis enabled: No additional AI findings.")
    
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
            
            # Create DataFrame with Source column
            findings_data = []
            for finding in filtered_findings:
                code = finding.get("code", "N/A")
                source = "🤖 AI" if code.startswith("AI_") else "📋 Rule"
                findings_data.append({
                    "Source": source,
                    "Severity": format_severity_badge(finding.get("severity", "unknown")),
                    "Code": code,
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
    # Section 4: Enhanced History with Filters and Analytics
    st.header("📜 Audit History & Analytics")
    
    # Initialize filter state
    if "history_filters_applied" not in st.session_state:
        st.session_state.history_filters_applied = False
    if "history_summary_data" not in st.session_state:
        st.session_state.history_summary_data = None
    if "history_data" not in st.session_state:
        st.session_state.history_data = None
    
    # Filters section
    st.subheader("🔍 Filters")
    filter_col1, filter_col2 = st.columns(2)
    
    with filter_col1:
        filter_row1_col1, filter_row1_col2 = st.columns(2)
        with filter_row1_col1:
            start_date = st.date_input("Start Date", value=None, key="history_start_date")
        with filter_row1_col2:
            end_date = st.date_input("End Date", value=None, key="history_end_date")
    
    with filter_col2:
        filter_row2_col1, filter_row2_col2, filter_row2_col3 = st.columns([2, 2, 1])
        with filter_row2_col1:
            vendor_options = ["All"] + ["cisco_asa", "cisco_ios", "fortinet", "palo_alto"]
            selected_vendor = st.selectbox("Vendor", options=vendor_options, index=0, key="history_vendor")
        with filter_row2_col2:
            environment_options = ["All", "Prod", "Dev", "Test", "DMZ", "Other"]
            selected_environment = st.selectbox("Environment", options=environment_options, index=0, key="history_environment")
        with filter_row2_col3:
            st.write("")  # Spacer
            st.write("")  # Spacer
            apply_filters = st.button("🔍 Apply Filters", use_container_width=True, type="primary")
    
    # Build filter params
    filter_params = {}
    if start_date:
        filter_params["start_date"] = start_date.isoformat()
    if end_date:
        filter_params["end_date"] = end_date.isoformat()
    if selected_vendor != "All":
        filter_params["vendor"] = selected_vendor
    if selected_environment != "All":
        filter_params["environment"] = selected_environment
    
    # Load data when filters are applied or on initial load
    if apply_filters or not st.session_state.history_filters_applied:
        st.session_state.history_filters_applied = True
        
        # Load summary with spinner
        with st.spinner("Loading audit summary..."):
            try:
                summary_data = get_audit_summary(**filter_params)
                st.session_state.history_summary_data = summary_data
            except Exception as e:
                st.error(f"Could not load audit summary: {str(e)}")
                st.session_state.history_summary_data = None
        
        # Load history with spinner
        with st.spinner("Loading audit history..."):
            try:
                history_params = filter_params.copy()
                history_result = get_audit_history(**history_params, limit=200)
                st.session_state.history_data = history_result
            except Exception as e:
                st.error(f"Could not load audit history: {str(e)}")
                st.session_state.history_data = None
    
    # Use cached data
    summary_data = st.session_state.history_summary_data
    history_result = st.session_state.history_data
    
    # Summary cards
    if summary_data and summary_data.get("total_configs_audited", 0) > 0:
        st.subheader("📊 Summary Metrics")
        
        # Calculate additional metrics from history if available
        max_risk = 0
        min_risk = 100
        total_audits = 0
        
        if history_result and "items" in history_result and history_result["items"]:
            risk_scores = [a.get("risk_score", 0) for a in history_result["items"]]
            if risk_scores:
                max_risk = max(risk_scores)
                min_risk = min(risk_scores)
            total_audits = len(history_result["items"])
        
        findings_by_severity = summary_data.get("findings_by_severity", {})
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Audits", total_audits or summary_data.get("total_configs_audited", 0))
        with col2:
            avg_risk = summary_data.get("average_risk_score", 0.0)
            st.metric("Avg Risk Score", f"{avg_risk:.1f}/100")
        with col3:
            st.metric("Max Risk Score", f"{max_risk}/100" if max_risk > 0 else "N/A")
        with col4:
            critical_count = findings_by_severity.get("critical", 0)
            st.metric("Critical Findings", critical_count)
        
        # Additional severity metrics
        st.markdown("---")
        severity_col1, severity_col2, severity_col3, severity_col4 = st.columns(4)
        with severity_col1:
            st.metric("🔴 Critical", findings_by_severity.get("critical", 0))
        with severity_col2:
            st.metric("🟠 High", findings_by_severity.get("high", 0))
        with severity_col3:
            st.metric("🟡 Medium", findings_by_severity.get("medium", 0))
        with severity_col4:
            st.metric("🔵 Low", findings_by_severity.get("low", 0))
    elif summary_data:
        st.info("No audit data found for the selected filters.")
    else:
        st.warning("Could not load audit summary. Check backend URL and API key.")
    
    # Charts section
    if history_result and "items" in history_result and history_result["items"]:
        audits = history_result["items"]
        
        if len(audits) > 0:
            st.markdown("---")
            st.subheader("📈 Charts")
            
            # Risk score over time chart
            chart_col1, chart_col2 = st.columns(2)
            
            with chart_col1:
                st.markdown("**Risk Score Over Time**")
                # Prepare data for risk score chart
                risk_data = []
                for audit in audits:
                    uploaded_at = audit.get("uploaded_at")
                    if uploaded_at:
                        try:
                            # Parse ISO format datetime
                            if isinstance(uploaded_at, str):
                                dt = datetime.fromisoformat(uploaded_at.replace('Z', '+00:00'))
                            else:
                                dt = uploaded_at
                            risk_data.append({
                                "Date": dt,
                                "Risk Score": audit.get("risk_score", 0),
                                "Vendor": audit.get("vendor", "unknown")
                            })
                        except Exception:
                            continue
                
                if risk_data:
                    risk_df = pd.DataFrame(risk_data)
                    risk_df = risk_df.sort_values("Date")
                    risk_df = risk_df.set_index("Date")
                    st.line_chart(risk_df[["Risk Score"]], height=300)
                else:
                    st.info("No date data available for charting.")
            
            with chart_col2:
                st.markdown("**Findings by Severity**")
                if summary_data and findings_by_severity:
                    severity_df = pd.DataFrame({
                        "Severity": ["Critical", "High", "Medium", "Low"],
                        "Count": [
                            findings_by_severity.get("critical", 0),
                            findings_by_severity.get("high", 0),
                            findings_by_severity.get("medium", 0),
                            findings_by_severity.get("low", 0),
                        ]
                    })
                    severity_df = severity_df.set_index("Severity")
                    st.bar_chart(severity_df, height=300)
                else:
                    st.info("No severity data available.")
    
    # History table
    if history_result and "items" in history_result and history_result["items"]:
        audits = history_result["items"]
        
        st.markdown("---")
        st.subheader(f"📋 Audit History ({history_result.get('total', len(audits))} total)")
        
        # Create DataFrame with sortable columns
        history_data = []
        for audit in audits:
            uploaded_at = audit.get("uploaded_at", "")
            # Format datetime for display
            if uploaded_at:
                try:
                    if isinstance(uploaded_at, str):
                        dt = datetime.fromisoformat(uploaded_at.replace('Z', '+00:00'))
                    else:
                        dt = uploaded_at
                    formatted_date = dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    formatted_date = str(uploaded_at)[:19] if len(str(uploaded_at)) > 19 else str(uploaded_at)
            else:
                formatted_date = "N/A"
            
            # Get sort date for sorting
            sort_date = datetime.min
            if uploaded_at:
                try:
                    if isinstance(uploaded_at, str):
                        sort_date = datetime.fromisoformat(uploaded_at.replace('Z', '+00:00'))
                    else:
                        sort_date = uploaded_at
                except Exception:
                    pass
            
            history_data.append({
                "Audit ID": audit.get("config_id", "N/A"),  # Using config_id as audit identifier
                "Config ID": audit.get("config_id", "N/A"),
                "Filename": audit.get("filename", "N/A"),
                "Vendor": audit.get("vendor", "N/A").upper() if audit.get("vendor") else "N/A",
                "Environment": audit.get("environment", "N/A"),
                "Risk Score": audit.get("risk_score", 0),
                "Total Findings": audit.get("total_findings", 0),
                "Completed At": formatted_date,
                "_sort_date": sort_date,  # Hidden column for sorting
            })
        
        df_history = pd.DataFrame(history_data)
        
        # Sort by risk score (descending) by default, or allow user to sort
        if not df_history.empty:
            df_history = df_history.sort_values("Risk Score", ascending=False)
            # Remove hidden sort column before display
            df_display = df_history.drop(columns=["_sort_date"])
            
            # Display table
            st.dataframe(
                df_display,
                use_container_width=True,
                hide_index=True,
                height=400
            )
            
            # CSV export
            csv = df_display.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Download CSV",
                data=csv,
                file_name=f"netsec_audit_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
            
            st.markdown("---")
            
            # Compare Audits section
            st.subheader("🔍 Compare Audits")
            
            if len(audits) >= 2:
                col1, col2 = st.columns(2)
                
                with col1:
                    baseline_options = {f"{a.get('config_id')} - {a.get('filename', 'N/A')} ({a.get('uploaded_at', '')[:10]})": a for a in audits}
                    baseline_label = st.selectbox(
                        "Baseline Audit",
                        options=[""] + list(baseline_options.keys()),
                        index=0,
                        help="Select the baseline audit to compare against"
                    )
                
                with col2:
                    comparison_options = {f"{a.get('config_id')} - {a.get('filename', 'N/A')} ({a.get('uploaded_at', '')[:10]})": a for a in audits}
                    comparison_label = st.selectbox(
                        "Comparison Audit",
                        options=[""] + list(comparison_options.keys()),
                        index=0,
                        help="Select the audit to compare with the baseline"
                    )
                
                if baseline_label and comparison_label and baseline_label != comparison_label:
                    baseline_audit = baseline_options[baseline_label]
                    comparison_audit = comparison_options[comparison_label]
                    
                    # Get full audit details for both
                    try:
                        baseline_detail = get_config_detail(baseline_audit.get("config_id"))
                        comparison_detail = get_config_detail(comparison_audit.get("config_id"))
                        
                        baseline_audit_result = baseline_detail.get("audit_result")
                        comparison_audit_result = comparison_detail.get("audit_result")
                        
                        if baseline_audit_result and comparison_audit_result:
                            st.markdown("### Comparison Results")
                            
                            # Risk score comparison
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric(
                                    "Baseline Risk Score",
                                    f"{baseline_audit_result.get('risk_score', 0)}/100",
                                    delta=None
                                )
                            with col2:
                                risk_diff = comparison_audit_result.get('risk_score', 0) - baseline_audit_result.get('risk_score', 0)
                                st.metric(
                                    "Comparison Risk Score",
                                    f"{comparison_audit_result.get('risk_score', 0)}/100",
                                    delta=f"{risk_diff:+d}" if risk_diff != 0 else None
                                )
                            with col3:
                                st.metric(
                                    "Difference",
                                    f"{abs(risk_diff)}",
                                    delta="Improved" if risk_diff < 0 else "Worsened" if risk_diff > 0 else "No change"
                                )
                            
                            # Breakdown comparison
                            baseline_breakdown = baseline_audit_result.get("breakdown", {})
                            comparison_breakdown = comparison_audit_result.get("breakdown", {})
                            
                            st.markdown("#### Findings Breakdown Comparison")
                            breakdown_data = {
                                "Severity": ["Critical", "High", "Medium", "Low"],
                                "Baseline": [
                                    baseline_breakdown.get("critical", 0),
                                    baseline_breakdown.get("high", 0),
                                    baseline_breakdown.get("medium", 0),
                                    baseline_breakdown.get("low", 0),
                                ],
                                "Comparison": [
                                    comparison_breakdown.get("critical", 0),
                                    comparison_breakdown.get("high", 0),
                                    comparison_breakdown.get("medium", 0),
                                    comparison_breakdown.get("low", 0),
                                ],
                            }
                            breakdown_df = pd.DataFrame(breakdown_data)
                            st.dataframe(breakdown_df, use_container_width=True, hide_index=True)
                            
                            # Finding codes comparison
                            baseline_codes = set(f.get("code", "") for f in baseline_audit_result.get("findings", []))
                            comparison_codes = set(f.get("code", "") for f in comparison_audit_result.get("findings", []))
                            
                            new_findings = comparison_codes - baseline_codes
                            resolved_findings = baseline_codes - comparison_codes
                            common_findings = baseline_codes & comparison_codes
                            
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.markdown("**New Findings**")
                                if new_findings:
                                    for code in sorted(new_findings)[:10]:
                                        st.write(f"• {code}")
                                    if len(new_findings) > 10:
                                        st.caption(f"... and {len(new_findings) - 10} more")
                                else:
                                    st.success("None")
                            
                            with col2:
                                st.markdown("**Resolved Findings**")
                                if resolved_findings:
                                    for code in sorted(resolved_findings)[:10]:
                                        st.write(f"• {code}")
                                    if len(resolved_findings) > 10:
                                        st.caption(f"... and {len(resolved_findings) - 10} more")
                                else:
                                    st.info("None")
                            
                            with col3:
                                st.markdown("**Common Findings**")
                                st.metric("Count", len(common_findings))
                                if common_findings:
                                    st.caption(f"Examples: {', '.join(sorted(common_findings)[:5])}")
                        else:
                            st.warning("One or both audits do not have audit results. Please run audits first.")
                    except Exception as e:
                        st.error(f"Failed to load audit details: {str(e)}")
                elif baseline_label and comparison_label and baseline_label == comparison_label:
                    st.warning("Please select two different audits to compare.")
            else:
                st.info("Need at least 2 audits to compare. Upload and analyze more configurations.")
            
            st.markdown("---")
            
            # Config selector
            config_options = {f"{a.get('config_id')} - {a.get('filename', 'N/A')}": a.get("config_id") for a in audits}
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
                                    st.info(f"Config {selected_config_id} loaded. Click 'Re-run Audit' to see results.")
                            except Exception:
                                st.info(f"Config {selected_config_id} loaded. Run audit to see results.")
                            
                            st.rerun()
                    except Exception as e:
                        st.error(f"Failed to load config: {str(e)}")
    elif history_result and "items" in history_result and len(history_result["items"]) == 0:
        st.info("No audits found for the selected filters.")
    elif not history_result:
        st.warning("Could not load audit history. Check backend URL and API key.")

# ============= Rules Tab =============
with tab_rules:
    st.header("🔧 Security Rules Management")
    st.markdown("Define and manage custom security rules for configuration auditing.")
    
    # Helper functions
    def list_rules(vendor: Optional[str] = None, enabled: Optional[bool] = None) -> Dict[str, Any]:
        """List all rules."""
        url = f"{API_BASE_URL}/api/v1/rules/"
        headers = get_headers()
        params = {}
        if vendor:
            params["vendor"] = vendor
        if enabled is not None:
            params["enabled"] = enabled
        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            handle_api_error(e)
            return {"items": [], "total": 0}
    
    def get_rule(rule_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific rule."""
        url = f"{API_BASE_URL}/api/v1/rules/{rule_id}"
        headers = get_headers()
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            handle_api_error(e)
            return None
    
    def create_rule(rule_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create a new rule."""
        url = f"{API_BASE_URL}/api/v1/rules/"
        headers = get_headers()
        try:
            response = requests.post(url, headers=headers, json=rule_data, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            handle_api_error(e)
            return None
    
    def update_rule(rule_id: int, rule_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update a rule."""
        url = f"{API_BASE_URL}/api/v1/rules/{rule_id}"
        headers = get_headers()
        try:
            response = requests.put(url, headers=headers, json=rule_data, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            handle_api_error(e)
            return None
    
    def delete_rule(rule_id: int) -> bool:
        """Disable a rule."""
        url = f"{API_BASE_URL}/api/v1/rules/{rule_id}"
        headers = get_headers()
        try:
            response = requests.delete(url, headers=headers, timeout=10)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            handle_api_error(e)
            return False
    
    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        filter_vendor = st.selectbox(
            "Filter by Vendor",
            options=["All", "cisco_asa", "cisco_ios", "fortinet", "palo_alto"],
            index=0
        )
    with col2:
        filter_enabled = st.selectbox(
            "Filter by Status",
            options=["All", "Enabled", "Disabled"],
            index=0
        )
    with col3:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()
    
    # List rules
    rules_data = list_rules(
        vendor=filter_vendor if filter_vendor != "All" else None,
        enabled=True if filter_enabled == "Enabled" else (False if filter_enabled == "Disabled" else None)
    )
    
    if rules_data.get("items"):
        rules_df_data = []
        for rule in rules_data["items"]:
            rules_df_data.append({
                "ID": rule.get("id"),
                "Name": rule.get("name", "N/A"),
                "Vendor": rule.get("vendor", "All"),
                "Category": rule.get("category", "N/A"),
                "Severity": rule.get("severity", "N/A"),
                "Status": "✅ Enabled" if rule.get("enabled") else "❌ Disabled",
                "Created": rule.get("created_at", "N/A")[:19] if rule.get("created_at") else "N/A",
            })
        
        rules_df = pd.DataFrame(rules_df_data)
        st.dataframe(rules_df, use_container_width=True, hide_index=True)
        
        # Rule details and actions
        st.subheader("📄 Rule Details & Actions")
        rule_ids = [r.get("id") for r in rules_data["items"]]
        selected_rule_id = st.selectbox(
            "Select rule to view/edit:",
            options=rule_ids,
            format_func=lambda x: f"ID {x} - {next((r.get('name', 'N/A') for r in rules_data['items'] if r.get('id') == x), 'N/A')}"
        )
        
        if selected_rule_id:
            rule_detail = get_rule(selected_rule_id)
            if rule_detail:
                col_view, col_edit, col_delete = st.columns(3)
                
                with col_view:
                    if st.button("👁️ View Details", use_container_width=True, key=f"view_{selected_rule_id}"):
                        st.json(rule_detail)
                
                with col_edit:
                    if st.button("✏️ Edit Rule", use_container_width=True, key=f"edit_{selected_rule_id}"):
                        st.session_state[f"editing_rule_{selected_rule_id}"] = True
                        st.rerun()
                
                with col_delete:
                    if st.button("🗑️ Disable Rule", use_container_width=True, key=f"delete_{selected_rule_id}"):
                        if delete_rule(selected_rule_id):
                            st.success(f"✅ Rule {selected_rule_id} disabled")
                            st.rerun()
                
                # Edit form
                if st.session_state.get(f"editing_rule_{selected_rule_id}", False):
                    st.markdown("---")
                    st.subheader(f"✏️ Edit Rule: {rule_detail.get('name')}")
                    
                    with st.form(f"edit_rule_form_{selected_rule_id}"):
                        edit_name = st.text_input("Name", value=rule_detail.get("name", ""))
                        edit_description = st.text_area("Description", value=rule_detail.get("description", ""))
                        edit_vendor = st.selectbox(
                            "Vendor",
                            options=["", "cisco_asa", "cisco_ios", "fortinet", "palo_alto"],
                            index=(["", "cisco_asa", "cisco_ios", "fortinet", "palo_alto"].index(rule_detail.get("vendor", "")) if rule_detail.get("vendor") in ["", "cisco_asa", "cisco_ios", "fortinet", "palo_alto"] else 0)
                        )
                        edit_severity = st.selectbox(
                            "Severity",
                            options=["critical", "high", "medium", "low"],
                            index=["critical", "high", "medium", "low"].index(rule_detail.get("severity", "medium"))
                        )
                        edit_enabled = st.checkbox("Enabled", value=rule_detail.get("enabled", True))
                        
                        # Match criteria (simplified - show as JSON)
                        st.markdown("**Match Criteria (JSON):**")
                        import json
                        match_criteria_str = st.text_area(
                            "Match Criteria",
                            value=json.dumps(rule_detail.get("match_criteria", {}), indent=2),
                            height=150
                        )
                        
                        submitted = st.form_submit_button("💾 Save Changes", use_container_width=True)
                        
                        if submitted:
                            try:
                                match_criteria = json.loads(match_criteria_str)
                                update_data = {
                                    "name": edit_name,
                                    "description": edit_description,
                                    "vendor": edit_vendor if edit_vendor else None,
                                    "severity": edit_severity,
                                    "enabled": edit_enabled,
                                    "match_criteria": match_criteria,
                                }
                                
                                result = update_rule(selected_rule_id, update_data)
                                if result:
                                    st.success("✅ Rule updated successfully")
                                    st.session_state[f"editing_rule_{selected_rule_id}"] = False
                                    st.rerun()
                            except json.JSONDecodeError:
                                st.error("❌ Invalid JSON in match criteria")
                            except Exception as e:
                                st.error(f"❌ Error updating rule: {str(e)}")
    else:
        st.info("No rules found matching the filters.")
    
    st.markdown("---")
    
    # Create new rule
    st.subheader("➕ Create New Rule")
    
    # Rule templates
    template_options = {
        "Custom": None,
        "Permit Any Any": {
            "name": "Permit Any Any Traffic",
            "description": "Detects ACL rules that permit any-to-any traffic",
            "vendor": "cisco_asa",
            "category": "acl",
            "severity": "critical",
            "match_criteria": {
                "pattern": "permit ip any any",
                "pattern_type": "contains"
            }
        },
        "SSH from Internet": {
            "name": "SSH Access from Internet",
            "description": "Detects SSH access rules from external sources",
            "vendor": None,
            "category": "acl",
            "severity": "high",
            "match_criteria": {
                "pattern": "permit tcp.*eq 22",
                "pattern_type": "regex"
            }
        },
        "RFC1918 from Outside": {
            "name": "RFC1918 Access from Outside",
            "description": "Detects inbound rules allowing access to private networks from outside",
            "vendor": None,
            "category": "acl",
            "severity": "high",
            "match_criteria": {
                "pattern": "permit.*10\\.0\\.0\\.0|permit.*172\\.16\\.|permit.*192\\.168\\.",
                "pattern_type": "regex"
            }
        },
    }
    
    selected_template = st.selectbox("Use Template", options=list(template_options.keys()))
    
    with st.form("create_rule_form"):
        template = template_options[selected_template] if selected_template != "Custom" else None
        
        new_rule_name = st.text_input("Rule Name", value=template.get("name", "") if template else "")
        new_rule_description = st.text_area("Description", value=template.get("description", "") if template else "")
        new_rule_vendor = st.selectbox(
            "Vendor",
            options=["", "cisco_asa", "cisco_ios", "fortinet", "palo_alto"],
            index=(["", "cisco_asa", "cisco_ios", "fortinet", "palo_alto"].index(template.get("vendor", "")) if template and template.get("vendor") in ["", "cisco_asa", "cisco_ios", "fortinet", "palo_alto"] else 0)
        )
        new_rule_category = st.selectbox(
            "Category",
            options=["general", "acl", "nat", "vpn", "routing", "interface", "crypto", "authentication"],
            index=["general", "acl", "nat", "vpn", "routing", "interface", "crypto", "authentication"].index(template.get("category", "general")) if template and template.get("category") in ["general", "acl", "nat", "vpn", "routing", "interface", "crypto", "authentication"] else 0
        )
        new_rule_severity = st.selectbox(
            "Severity",
            options=["critical", "high", "medium", "low"],
            index=["critical", "high", "medium", "low"].index(template.get("severity", "medium")) if template and template.get("severity") in ["critical", "high", "medium", "low"] else 2
        )
        new_rule_enabled = st.checkbox("Enabled", value=True)
        
        st.markdown("**Match Criteria (JSON):**")
        import json
        default_match_criteria = template.get("match_criteria", {}) if template else {}
        new_rule_match_criteria = st.text_area(
            "Match Criteria",
            value=json.dumps(default_match_criteria, indent=2),
            height=150,
            help="JSON object with pattern matching criteria. Example: {\"pattern\": \"permit ip any any\", \"pattern_type\": \"contains\"}"
        )
        
        submitted = st.form_submit_button("🔧 Create Rule", use_container_width=True)
        
        if submitted:
            if not new_rule_name or not new_rule_name.strip():
                st.error("⚠️ Please provide a rule name")
            else:
                try:
                    match_criteria = json.loads(new_rule_match_criteria)
                    rule_data = {
                        "name": new_rule_name.strip(),
                        "description": new_rule_description.strip() if new_rule_description else None,
                        "vendor": new_rule_vendor if new_rule_vendor else None,
                        "category": new_rule_category,
                        "severity": new_rule_severity,
                        "enabled": new_rule_enabled,
                        "match_criteria": match_criteria,
                    }
                    
                    with st.spinner("Creating rule..."):
                        result = create_rule(rule_data)
                        if result:
                            st.success("✅ Rule created successfully!")
                            st.rerun()
                except json.JSONDecodeError:
                    st.error("❌ Invalid JSON in match criteria")
                except Exception as e:
                    st.error(f"❌ Error creating rule: {str(e)}")

# Admin tab
if tab_admin:
    with tab_admin:
        st.header("🔐 API Key Management")
        st.markdown("Manage API keys for authentication and access control.")
        
        # Helper functions for API key management
        def list_api_keys() -> Dict[str, Any]:
            """List all API keys."""
            url = f"{API_BASE_URL}/api/v1/api-keys/"
            headers = get_headers()
            try:
                response = requests.get(url, headers=headers, timeout=10)
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                handle_api_error(e)
                return {"items": [], "total": 0}
        
        def create_api_key(name: str, role: str) -> Dict[str, Any]:
            """Create a new API key."""
            url = f"{API_BASE_URL}/api/v1/api-keys/"
            headers = get_headers()
            try:
                response = requests.post(
                    url,
                    headers=headers,
                    json={"name": name, "role": role},
                    timeout=10
                )
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                handle_api_error(e)
                return {}
        
        def deactivate_api_key(key_id: int) -> bool:
            """Deactivate an API key."""
            url = f"{API_BASE_URL}/api/v1/api-keys/{key_id}/deactivate"
            headers = get_headers()
            try:
                response = requests.patch(url, headers=headers, timeout=10)
                response.raise_for_status()
                return True
            except requests.exceptions.RequestException as e:
                handle_api_error(e)
                return False
        
        # Section 1: List existing keys
        st.subheader("📋 Existing API Keys")
        
        if st.button("🔄 Refresh List", use_container_width=False):
            st.rerun()
        
        keys_data = list_api_keys()
        
        if keys_data.get("items"):
            keys_df_data = []
            for key in keys_data["items"]:
                keys_df_data.append({
                    "ID": key.get("id"),
                    "Name": key.get("name", "N/A"),
                    "Role": key.get("role", "N/A"),
                    "Status": "✅ Active" if key.get("is_active") else "❌ Inactive",
                    "Created": key.get("created_at", "N/A")[:19] if key.get("created_at") else "N/A",
                    "Key (Masked)": key.get("key_masked", "N/A")
                })
            
            keys_df = pd.DataFrame(keys_df_data)
            st.dataframe(keys_df, use_container_width=True, hide_index=True)
            
            # Deactivate key section
            st.subheader("🗑️ Deactivate Key")
            key_ids = [k.get("id") for k in keys_data["items"] if k.get("is_active")]
            if key_ids:
                selected_key_id = st.selectbox(
                    "Select key to deactivate:",
                    options=key_ids,
                    format_func=lambda x: f"ID {x} - {next((k.get('name', 'N/A') for k in keys_data['items'] if k.get('id') == x), 'N/A')}"
                )
                
                if st.button("⚠️ Deactivate Selected Key", type="secondary"):
                    if deactivate_api_key(selected_key_id):
                        st.success(f"✅ Key {selected_key_id} deactivated successfully")
                        st.rerun()
            else:
                st.info("No active keys to deactivate")
        else:
            st.info("No API keys found")
        
        st.markdown("---")
        
        # Section 2: Create new key
        st.subheader("➕ Create New API Key")
        
        with st.form("create_api_key_form"):
            new_key_name = st.text_input("Key Name/Label", help="A descriptive name for this API key")
            new_key_role = st.selectbox(
                "Role",
                options=["viewer", "operator", "security_analyst", "auditor", "admin"],
                help="viewer: Read-only. operator: Upload/audit. security_analyst: Manage rules. auditor: Export reports. admin: Full access."
            )
            
            submitted = st.form_submit_button("🔑 Create API Key", use_container_width=True)
            
            if submitted:
                if not new_key_name or not new_key_name.strip():
                    st.error("⚠️ Please provide a key name")
                else:
                    with st.spinner("Creating API key..."):
                        result = create_api_key(new_key_name.strip(), new_key_role)
                        if result and "key" in result:
                            st.success("✅ API key created successfully!")
                            st.markdown("### 🔑 **Your New API Key**")
                            st.code(result["key"], language=None)
                            st.warning("⚠️ **Important:** Copy this key now. It will not be shown again!")
                            
                            # Copy button using session state
                            if st.button("📋 Copy to Clipboard", use_container_width=True):
                                st.info("Key copied! (Use Ctrl+C if button doesn't work)")
                            
                            st.markdown("---")
                            st.json({
                                "id": result.get("id"),
                                "name": result.get("name"),
                                "role": result.get("role"),
                                "is_active": result.get("is_active"),
                                "created_at": result.get("created_at")
                            })
                        else:
                            st.error("❌ Failed to create API key")

# ============= Audit Trail Tab =============
with tab_audit:
    st.header("📝 Activity Log / Audit Trail")
    st.markdown("View all system activities and user actions for compliance and security auditing.")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        filter_action = st.selectbox(
            "Filter by Action",
            options=["All"] + [
                "config_upload", "config_parse", "audit_run", "audit_export",
                "api_key_create", "api_key_update", "api_key_deactivate"
            ],
            index=0
        )
    
    with col2:
        filter_resource = st.selectbox(
            "Filter by Resource Type",
            options=["All", "config_file", "audit", "api_key"],
            index=0
        )
    
    with col3:
        items_per_page = st.selectbox(
            "Items per Page",
            options=[25, 50, 100, 200],
            index=1
        )
    
    # Date range filter
    col_date1, col_date2 = st.columns(2)
    with col_date1:
        start_date = st.date_input("Start Date", value=None)
    with col_date2:
        end_date = st.date_input("End Date", value=None)
    
    # Pagination
    if "audit_trail_page" not in st.session_state:
        st.session_state.audit_trail_page = 0
    
    col_prev, col_info, col_next = st.columns([1, 2, 1])
    with col_prev:
        if st.button("⬅️ Previous", disabled=st.session_state.audit_trail_page == 0):
            st.session_state.audit_trail_page = max(0, st.session_state.audit_trail_page - 1)
            st.rerun()
    
    with col_next:
        if st.button("Next ➡️"):
            st.session_state.audit_trail_page += 1
            st.rerun()
    
    # Fetch logs
    offset = st.session_state.audit_trail_page * items_per_page
    
    logs_data = get_activity_logs(
        limit=items_per_page,
        offset=offset,
        start_date=datetime.combine(start_date, datetime.min.time()) if start_date else None,
        end_date=datetime.combine(end_date, datetime.max.time()) if end_date else None,
        action=filter_action if filter_action != "All" else None,
        resource_type=filter_resource if filter_resource != "All" else None,
    )
    
    if logs_data and logs_data.get("items"):
        total = logs_data.get("total", 0)
        with col_info:
            st.info(f"Showing {offset + 1}-{min(offset + items_per_page, total)} of {total} logs")
        
        # Display logs in a table
        logs_df_data = []
        for log in logs_data["items"]:
            details_str = ""
            if log.get("details"):
                details_str = str(log["details"])[:100] + "..." if len(str(log["details"])) > 100 else str(log["details"])
            
            logs_df_data.append({
                "Timestamp": log.get("timestamp", "N/A")[:19] if log.get("timestamp") else "N/A",
                "Actor": f"{log.get('actor_role', 'N/A')} ({log.get('actor_source', 'N/A')})",
                "Action": log.get("action", "N/A"),
                "Resource": f"{log.get('resource_type', 'N/A')} #{log.get('resource_id', 'N/A')}" if log.get("resource_id") else log.get("resource_type", "N/A"),
                "IP": log.get("ip_address", "N/A"),
                "Details": details_str,
            })
        
        logs_df = pd.DataFrame(logs_df_data)
        st.dataframe(logs_df, use_container_width=True, hide_index=True)
        
        # Show full details in expander for selected log
        st.subheader("📄 Log Details")
        selected_idx = st.selectbox(
            "Select log to view full details:",
            options=range(len(logs_data["items"])),
            format_func=lambda x: f"{logs_data['items'][x].get('timestamp', 'N/A')[:19]} - {logs_data['items'][x].get('action', 'N/A')}"
        )
        
        if selected_idx is not None:
            selected_log = logs_data["items"][selected_idx]
            st.json(selected_log)
    elif logs_data and logs_data.get("total") == 0:
        st.info("No activity logs found matching the filters.")
    else:
        st.warning("Unable to load activity logs. Please check your API key and connection.")

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #666;'>"
    "🛡️ NetSec Auditor — Network Security Configuration Analyzer"
    "</div>",
    unsafe_allow_html=True
)
