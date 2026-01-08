# NetSec Auditor - Development Roadmap

> **FireMon/Tufin-Class Network Security Policy Platform**

This document outlines the long-term roadmap for evolving NetSec Auditor from its current state into an enterprise-grade network security policy management platform.

---

## Current State

NetSec Auditor is a FastAPI + Streamlit application that:

- Parses multi-vendor network configurations (Cisco ASA/IOS, Fortinet, Palo Alto)
- Performs security audits with rule-based and AI-enhanced findings
- Provides API key-based RBAC (basic roles: `read_only`, `admin`)
- Generates PDF audit reports
- Deploys to Railway with PostgreSQL
- Includes Streamlit UI for visualization and management

---

## Vision: Enterprise Platform Features

The goal is to evolve into a **FireMon/Tufin-class platform** with:

- ✅ Rich RBAC with granular permissions
- ✅ Interactive rule engine with UI editor
- ✅ Device inventory & CMDB-style views
- ✅ Policy hygiene scoring & analytics
- ✅ Enterprise rule packs (pre-built security policies)
- ✅ AI explainability & rule suggestion
- ✅ Executive dashboards & scheduled reporting
- ✅ Multi-tenant SaaS architecture
- ✅ Production-grade security & API polish

---

## Development Epics (In Order)

### EPIC A — RBAC++ and Audit Logging

**Status:** 🟡 Planned

Expand from basic API key roles to enterprise RBAC with comprehensive audit trails.

**Tasks:**
- [ ] Extend role model: `viewer`, `operator`, `security_analyst`, `auditor`, `admin`
- [ ] Define permission matrix per role
- [ ] Implement role-based endpoint guards
- [ ] Add `ActivityLog` model for audit trail
- [ ] Log all critical actions (upload, audit, rule changes, key management)
- [ ] Build Streamlit "Audit Trail" tab with filters

**Key Files:**
- `app/core/auth.py` - Permission checks
- `app/models/activity_log.py` - New model
- `app/api/v1/endpoints/activity.py` - Audit log API
- `streamlit_app.py` - Audit trail UI

---

### EPIC B — Rule Engine Editor UI + Rule Management

**Status:** 🟡 Planned

Enable security analysts to create, edit, and manage custom security rules.

**Tasks:**
- [ ] Add `Rule` model (name, pattern, severity, vendor, enabled)
- [ ] Create `/api/v1/rules` CRUD endpoints
- [ ] Integrate custom rules into audit engine
- [ ] Build Streamlit rule editor with templates
- [ ] Add rule versioning support

**Key Files:**
- `app/models/rule.py` - New model
- `app/api/v1/endpoints/rules.py` - New endpoints
- `app/services/audit_service.py` - Rule evaluation
- `streamlit_app.py` - Rule editor tab

---

### EPIC C — Device Inventory / CMDB-Style View

**Status:** 🟡 Planned

Centralized device registry with configuration tracking.

**Tasks:**
- [ ] Add `Device` model (hostname, IP, vendor, site, environment)
- [ ] Create `/api/v1/devices` endpoints
- [ ] Link configs/audits to devices
- [ ] Build Streamlit "Devices" tab with risk-based sorting
- [ ] Device detail views with audit history

**Key Files:**
- `app/models/device.py` - New model
- `app/api/v1/endpoints/devices.py` - New endpoints
- `streamlit_app.py` - Devices tab

---

### EPIC D — Policy Hygiene Score & Cleanup Analytics

**Status:** 🟡 Planned

Automated policy quality scoring and optimization recommendations.

**Tasks:**
- [ ] Detect redundant, shadowed, and unused rules
- [ ] Implement hygiene scoring algorithm (0-100)
- [ ] Store scores on audits and devices
- [ ] Add hygiene metrics to UI dashboards
- [ ] Create cleanup recommendations

**Key Files:**
- `app/services/hygiene_analyzer.py` - New service
- `app/models/audit_record.py` - Add hygiene_score field
- `app/models/device.py` - Add last_policy_hygiene_score
- `streamlit_app.py` - Hygiene views

---

### EPIC E — Deep Enterprise Rule Packs

**Status:** 🟡 Planned

Pre-built, battle-tested security policy packs for common use cases.

**Tasks:**
- [ ] Define rule pack structure (`RuleSet`/`PolicyPack` model)
- [ ] Seed built-in packs:
  - Internet Exposure
  - Compliance Baseline
  - Crypto & VPN
  - Policy Hygiene
- [ ] Enable pack selection per device/workspace
- [ ] UI to show which pack triggered each finding

**Key Files:**
- `app/models/rule_set.py` - New model
- `app/core/seeds.py` - Pack definitions
- `app/services/audit_service.py` - Pack evaluation
- `streamlit_app.py` - Pack management UI

---

### EPIC F — AI Explainability V2 & AI Rule Helper

**Status:** 🟡 Planned

Enhanced AI integration for explanations and rule generation assistance.

**Tasks:**
- [ ] Extend findings with AI fields:
  - `ai_explanation`
  - `business_impact`
  - `attack_path`
  - `remediation_steps`
- [ ] Add `POST /api/v1/rules/ai-suggest` endpoint
- [ ] Build "Generate with AI" button in rule editor
- [ ] Add AI explanation expanders in findings view
- [ ] Ensure graceful degradation when AI fails

**Key Files:**
- `app/schemas/findings.py` - Extended schema
- `app/api/v1/endpoints/rules.py` - AI suggest endpoint
- `app/services/ai_service.py` - AI integration
- `streamlit_app.py` - AI UI components

---

### EPIC G — Executive Reports & Scheduled Reporting

**Status:** 🟡 Planned

CISO-level dashboards and automated report generation.

**Tasks:**
- [ ] Build executive summary API (risk trends, top devices, hygiene trends)
- [ ] Generate PDF executive reports with charts
- [ ] Add CSV exports for findings and devices
- [ ] Implement report subscriptions (DB-stored schedules)
- [ ] Build "Reports" tab in Streamlit UI

**Key Files:**
- `app/api/v1/endpoints/reports.py` - New endpoints
- `app/services/report_service.py` - Report generation
- `app/models/report_subscription.py` - New model
- `app/utils/pdf_generator.py` - Enhanced PDF exports
- `streamlit_app.py` - Reports tab

---

### EPIC H — Multi-Tenant Workspaces (SaaS-Ready)

**Status:** 🟡 Planned

Full multi-tenancy support for SaaS deployment.

**Tasks:**
- [ ] Add `Workspace` model
- [ ] Associate all resources (devices, audits, rules, keys) with workspaces
- [ ] Implement workspace scoping in all queries
- [ ] Add `X-Workspace-ID` header support
- [ ] Build workspace switcher in UI
- [ ] Add isolation tests (prevent cross-tenant data leaks)

**Key Files:**
- `app/models/workspace.py` - New model
- `app/core/auth.py` - Workspace context
- All models - Add workspace_id foreign keys
- `streamlit_app.py` - Workspace switcher

---

### EPIC I — Platform Hardening & Public API Polish

**Status:** 🟡 Planned

Production-ready security, rate limiting, and API documentation.

**Tasks:**
- [ ] Add security headers middleware (CSP, X-Frame-Options, etc.)
- [ ] Implement rate limiting (sliding window per API key)
- [ ] Enhance API documentation with examples
- [ ] Generate clean OpenAPI schema
- [ ] Create SDK examples (Python, PowerShell)

**Key Files:**
- `app/main.py` - Security middleware
- `app/core/rate_limit.py` - Rate limiting
- All endpoints - Enhanced OpenAPI docs
- `docs/` - SDK examples

---

## Development Workflow

For every change:

1. **Pick a small task** from the current epic
2. **Inspect relevant files** in the repo
3. **Implement changes** with tests
4. **Run tests**: `pytest -v`
5. **Fix any failures** before proceeding
6. **Commit & push** when green:
   ```bash
   git status
   git add -A
   git commit -m "feat(epic): description"
   git push
   ```

**Always:**
- Keep tests passing
- Maintain backwards compatibility
- Follow existing code style
- Write tests for new features
- Update documentation

---

## Technology Stack

- **Backend:** FastAPI, SQLAlchemy 2.x, Pydantic v2
- **Database:** PostgreSQL (production), SQLite (local dev)
- **UI:** Streamlit
- **Deployment:** Docker, Railway
- **AI:** OpenAI GPT-4 (optional)
- **Testing:** pytest
- **Reports:** ReportLab (PDF), Pandas (CSV)

---

## Notes

- Work through epics **one at a time**, in order
- Each epic should be **complete and tested** before moving to the next
- Maintain **incremental progress** - small, tested commits
- **Never break existing functionality** without migration
- Keep the codebase **production-ready** at all times

---

*Last Updated: $(date)*

