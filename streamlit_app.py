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


def check_admin_status() -> bool:
    """Check if current user is admin by calling /auth/me endpoint."""
    try:
        url = f"{get_base_url()}/api/v1/auth/me"
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
        if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code in [401, 403]:
            handle_api_error(e)
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


def run_audit(config_id: int, ai_enabled: bool = False) -> Dict[str, Any]:
    """Run security audit on parsed configuration."""
    url = f"{get_base_url()}/api/v1/audit/{config_id}"
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


def get_audit_summary() -> Dict[str, Any]:
    """Get audit summary/analytics."""
    url = f"{get_base_url()}/api/v1/audits/summary"
    headers = get_headers()
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
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
    url = f"{get_base_url()}/api/v1/audits/history"
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
tab_names = ["📊 Overview", "📋 Findings", "📜 History"]
if st.session_state.is_admin:
    tab_names.append("🔐 Admin: API Keys")
tabs = st.tabs(tab_names)
tab1, tab2, tab3 = tabs[0], tabs[1], tabs[2]
tab_admin = tabs[3] if st.session_state.is_admin else None

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
    
    # Filters section
    with st.expander("🔍 Filters", expanded=True):
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            start_date = st.date_input("Start Date", value=None)
        with col2:
            end_date = st.date_input("End Date", value=None)
        with col3:
            vendor_options = ["All"] + ["cisco_asa", "cisco_ios", "fortinet", "palo_alto"]
            selected_vendor = st.selectbox("Vendor", options=vendor_options, index=0)
        with col4:
            environment_options = ["All", "Prod", "Dev", "Test", "DMZ", "Other"]
            selected_environment = st.selectbox("Environment", options=environment_options, index=0)
    
    # Get audit summary for charts
    try:
        summary_data = get_audit_summary()
        
        if summary_data:
            # Charts section
            st.subheader("📊 Analytics Overview")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Configs Audited", summary_data.get("total_configs_audited", 0))
            with col2:
                st.metric("Average Risk Score", f"{summary_data.get('average_risk_score', 0):.1f}")
            with col3:
                total_findings = sum(summary_data.get("findings_by_severity", {}).values())
                st.metric("Total Findings", total_findings)
            
            # Risk score over time chart
            if summary_data.get("findings_over_time"):
                st.subheader("📈 Findings Over Time")
                time_data = summary_data["findings_over_time"]
                if time_data:
                    chart_df = pd.DataFrame(time_data)
                    chart_df["date"] = pd.to_datetime(chart_df["date"])
                    chart_df = chart_df.set_index("date")
                    st.line_chart(chart_df[["critical", "high", "medium", "low"]])
            
            # Findings by severity bar chart
            st.subheader("📊 Findings by Severity (All Time)")
            severity_data = summary_data.get("findings_by_severity", {})
            if severity_data:
                severity_df = pd.DataFrame({
                    "Severity": list(severity_data.keys()),
                    "Count": list(severity_data.values())
                })
                st.bar_chart(severity_df.set_index("Severity"))
        
        st.markdown("---")
        
        # Get filtered audit history
        history_params = {}
        if start_date:
            history_params["start_date"] = start_date.isoformat()
        if end_date:
            history_params["end_date"] = end_date.isoformat()
        if selected_vendor != "All":
            history_params["vendor"] = selected_vendor
        if selected_environment != "All":
            history_params["environment"] = selected_environment
        
        history_result = get_audit_history(**history_params, limit=100)
        
        if history_result and "items" in history_result and history_result["items"]:
            audits = history_result["items"]
            
            st.subheader(f"📋 Audit History ({history_result.get('total', 0)} total)")
            
            # Create DataFrame
            history_data = []
            for audit in audits:
                history_data.append({
                    "Config ID": audit.get("config_id"),
                    "Filename": audit.get("filename", "N/A"),
                    "Vendor": audit.get("vendor", "N/A").upper(),
                    "Device Name": audit.get("device_name", "N/A"),
                    "Environment": audit.get("environment", "N/A"),
                    "Uploaded": audit.get("uploaded_at", "N/A")[:19] if audit.get("uploaded_at") else "N/A",
                    "Risk Score": audit.get("risk_score", 0),
                    "Total Findings": audit.get("total_findings", 0)
                })
            
            df_history = pd.DataFrame(history_data)
            
            # Display table
            st.dataframe(
                df_history,
                use_container_width=True,
                hide_index=True,
                height=400
            )
            
            # CSV export
            csv = df_history.to_csv(index=False)
            st.download_button(
                "📥 Download CSV",
                data=csv,
                file_name=f"audit_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
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
        else:
            st.info("No audit history found with the selected filters")
            
    except Exception as e:
        st.error(f"Failed to load history: {str(e)}")

# Admin tab
if tab_admin:
    with tab_admin:
        st.header("🔐 API Key Management")
        st.markdown("Manage API keys for authentication and access control.")
        
        # Helper functions for API key management
        def list_api_keys() -> Dict[str, Any]:
            """List all API keys."""
            url = f"{get_base_url()}/api/v1/api-keys/"
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
            url = f"{get_base_url()}/api/v1/api-keys/"
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
            url = f"{get_base_url()}/api/v1/api-keys/{key_id}/deactivate"
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
                options=["read_only", "admin"],
                help="read_only: Can read/list resources. admin: Full access including key management."
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

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #666;'>"
    "🛡️ NetSec Auditor — Network Security Configuration Analyzer"
    "</div>",
    unsafe_allow_html=True
)
