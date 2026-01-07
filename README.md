# NetSec Auditor

**AI-Assisted Network Security Configuration Auditor**

NetSec Auditor is a production-ready FastAPI application that analyzes firewall and router configuration files to identify security vulnerabilities and provide actionable recommendations. The system combines rule-based security analysis with optional AI-enhanced insights to deliver comprehensive security audits for multi-vendor network devices.

The application parses configuration files from major network vendors, extracts critical security elements (ACLs, NAT rules, VPNs, interfaces, routing tables), and performs automated security assessments. It stores parsed data in PostgreSQL and provides a RESTful API with interactive Swagger documentation.

## Overview

NetSec Auditor addresses a critical need in network security management: automated analysis of complex firewall and router configurations. Security teams often struggle to manually review hundreds or thousands of firewall rules across multiple devices. This tool automates the detection of common security misconfigurations such as overly permissive access control lists, insecure NAT rules, and problematic routing configurations.

The system uses a dual-approach analysis:
- **Rule-based engine**: Implements domain-specific security checks (e.g., detecting any-to-any ACL rules, private network exposure, default routes to untrusted interfaces)
- **AI-enhanced analysis**: Optional OpenAI integration provides contextual security insights and recommendations

## Features

- **Multi-Vendor Configuration Parsing**: Supports Cisco ASA, Cisco IOS, Fortinet FortiGate, and Palo Alto Networks PAN-OS
- **Structured Data Extraction**: Parses and extracts ACLs, NAT rules, VPN configurations, network interfaces, and routing tables
- **Automated Security Analysis**: Rule-based security engine detects common misconfigurations with severity classification
- **AI-Enhanced Auditing**: Optional OpenAI GPT integration for advanced security insights and recommendations
- **RESTful API**: FastAPI-based API with automatic OpenAPI/Swagger documentation
- **PostgreSQL Storage**: Persistent storage of configurations and parsed data with proper relational modeling
- **Dockerized Deployment**: Complete Docker Compose setup with PostgreSQL database
- **Production-Ready Logging**: Comprehensive logging with configurable levels and file rotation
- **Type-Safe Codebase**: Full type hints with Pydantic validation

## Architecture

NetSec Auditor follows a clean, layered architecture:

- **API Layer** (`app/api/`): FastAPI routers and endpoints for upload, parsing, auditing, and configuration retrieval
- **Service Layer** (`app/services/`): Business logic for configuration parsing and security auditing
- **Models Layer** (`app/models/`): SQLAlchemy ORM models for database persistence
- **Parser Layer** (`app/utils/parsers/`): Vendor-specific configuration parsers with structured output models
- **Database**: PostgreSQL for persistent storage with proper indexes and relationships
- **Configuration**: Centralized settings management with Pydantic BaseSettings and environment variable support

The application is containerized with Docker and uses docker-compose for orchestration. The database schema is automatically created on startup using SQLAlchemy's declarative base.

## Getting Started

### Prerequisites

- **For Docker/Production**: Docker and Docker Compose (uses PostgreSQL)
- **For Local Development (Windows)**: Python 3.13+ (uses SQLite, no build tools required)

### Quick Start with Docker

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd netsec-auditor
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and set:
   - `DATABASE_URL`: PostgreSQL connection string (default provided)
   - `OPENAI_API_KEY`: (Optional) Your OpenAI API key for AI-enhanced analysis

3. **Start the services:**
   ```bash
   docker-compose up --build
   ```

4. **Access the API:**
   - API: http://localhost:8000
   - Interactive API Docs (Swagger): http://localhost:8000/docs
   - Alternative Docs (ReDoc): http://localhost:8000/redoc

---

## 🚀 Cloud Deploy (Railway)

NetSec Auditor can be deployed to Railway using the provided `railway.json` configuration file.

### Quick Deploy Steps

1. **Connect GitHub repository to Railway:**
   - Go to [Railway](https://railway.app) and create a new project
   - Connect your GitHub repository containing this codebase

2. **Railway auto-detects configuration:**
   - Railway automatically detects `railway.json` in the root
   - A PostgreSQL plugin is created and wired as `DATABASE_URL`
   - Service `netsec-auditor-api` is deployed from `Dockerfile`

3. **Environment variables:**
   - `DATABASE_URL`: Automatically set by Railway from PostgreSQL plugin
   - `API_KEY`: Set to your secure API key (default: `changeme_static_demo_key` - **change this!**)
   - `OPENAI_API_KEY`: (Optional) Your OpenAI API key for AI-enhanced audit mode

4. **Access your deployed API:**
   - Railway provides a public URL (e.g., `https://netsec-auditor-api.up.railway.app`)
   - API Docs: `https://your-railway-url/docs`
   - Health Check: `https://your-railway-url/health`

The `railway.json` config handles database connection automatically. The API binds to `0.0.0.0` and respects Railway's `$PORT` environment variable.

---

## LOCAL DEV (Windows / Python 3.13)

**No build tools required!** All dependencies use pre-built wheels for Python 3.13 on Windows.

### Prerequisites

- Python 3.13+
- **No PostgreSQL required** - Uses SQLite by default
- **No Rust/Cargo/Visual Studio Build Tools needed** - All packages have pre-built wheels

### Setup Steps

1. **Create virtual environment:**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   
   ✅ All packages install from pre-built wheels (no compilation needed)
   ✅ `psycopg2-binary` is automatically skipped on Windows (only needed for PostgreSQL in Docker)

3. **Configure environment variables (optional):**
   ```bash
   copy .env.example .env
   ```
   
   Edit `.env` if needed:
   - `DATABASE_URL`: **Leave unset** to use SQLite (default: `sqlite:///./netsec_auditor.db`)
   - `OPENAI_API_KEY`: (Optional) Your OpenAI API key for AI-enhanced analysis
   - `API_KEY`: (Optional) API key for authentication

4. **Run the application:**
   ```bash
   python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

   The `--reload` flag enables auto-reload on code changes (development only).
   
   The database file `netsec_auditor.db` will be created automatically in the project root.

### Access the API

- Swagger UI (Interactive API Docs): http://localhost:8000/docs
- API Root: http://localhost:8000
- Health Check: http://localhost:8000/health

### Health Check

Test that the API is running:

```bash
curl http://localhost:8000/health
```

Expected response: `{"status": "ok"}`

---

## DOCKER / PRODUCTION (PostgreSQL)

For production deployment or when you need PostgreSQL features:

### Prerequisites

- Docker and Docker Compose

### Setup

1. **Configure environment variables:**
   ```bash
   copy .env.example .env
   ```
   
   Edit `.env` and set:
   - `DATABASE_URL`: PostgreSQL connection string (default provided in docker-compose.yml)
   - `OPENAI_API_KEY`: (Optional) Your OpenAI API key for AI-enhanced analysis

2. **Start the services:**
   ```bash
   docker-compose up --build
   ```

This will:
- Build the API container (includes `psycopg2-binary` for PostgreSQL on Linux)
- Start PostgreSQL database
- Start the FastAPI backend on port 8000
- Use PostgreSQL via `DATABASE_URL` environment variable

**Access the API:**
- Swagger UI (Interactive API Docs): http://localhost:8000/docs
- API Root: http://localhost:8000
- Health Check: http://localhost:8000/health

**Check logs:**
```bash
docker-compose logs -f api
```

**Stop services:**
```bash
docker-compose down
```

**Stop and remove volumes (clean slate):**
```bash
docker-compose down -v
```

---

## 🚀 Cloud Deployment (Railway / Render)

NetSec Auditor is designed for easy deployment to cloud platforms like Railway and Render. The application consists of three components:

- **Backend (FastAPI)**: REST API service running on port 8000
- **Database (PostgreSQL)**: Managed PostgreSQL service (provided by platform)
- **UI (Streamlit)**: Web interface running on port 8501

### Prerequisites

- Docker installed (for local testing)
- Railway or Render account
- GitHub repository (for automatic deployments)

### Environment Variables

#### For API Service

**Required:**
- `DATABASE_URL`: PostgreSQL connection string
  - Format: `postgresql://user:password@host:5432/dbname`
  - Railway/Render provide this automatically when you add a PostgreSQL service
  - Example: `postgresql://postgres:password@postgres.railway.internal:5432/railway`

**Optional (but recommended):**
- `OPENAI_API_KEY`: OpenAI API key for AI-enhanced analysis (if you want AI features)
- `API_KEY` or `STATIC_API_KEY`: Static API key for initial admin access
- `ALLOWED_ORIGINS`: Comma-separated list of allowed CORS origins (e.g., `https://your-ui-domain.com,https://your-api-domain.com`)
- `DEBUG`: Set to `false` in production
- `LOG_LEVEL`: `INFO` or `WARNING` for production
- `MAX_UPLOAD_SIZE`: Maximum file upload size in bytes (default: 10485760 = 10MB)

#### For UI Service

**Required:**
- `BACKEND_URL`: Backend API URL (e.g., `https://your-api-service.railway.app` or `https://your-api-service.onrender.com`)

**Note:** The UI service reads `BACKEND_URL` from environment variables. It will default to `http://localhost:8000` if not set (for local development).

### Deploy API on Railway

1. **Create a new Railway project:**
   - Go to [Railway](https://railway.app) and create a new project
   - Connect your GitHub repository

2. **Add PostgreSQL database:**
   - Click "New" → "Database" → "PostgreSQL"
   - Railway automatically creates the database and provides `DATABASE_URL`
   - Note: Railway sets `DATABASE_URL` automatically as a service variable

3. **Add API service:**
   - Click "New" → "GitHub Repo" → Select your repository
   - Railway will auto-detect `Dockerfile` in the root
   - The service will use the Dockerfile to build and deploy

4. **Configure environment variables:**
   - Go to the API service → "Variables" tab
   - `DATABASE_URL`: Already set automatically from PostgreSQL service
   - Add `OPENAI_API_KEY` (optional): Your OpenAI API key
   - Add `API_KEY` (optional): A secure static API key for initial access
   - Add `ALLOWED_ORIGINS`: Comma-separated list like `https://your-api.railway.app,https://your-ui.railway.app`

5. **Deploy:**
   - Railway will automatically build and deploy when you push to your repository
   - Wait for the build to complete

6. **Get your API URL:**
   - Railway provides a public URL like `https://netsec-auditor-api.up.railway.app`
   - Copy this URL - you'll need it for the UI service

### Deploy UI on Railway

1. **Create a new service in the same Railway project:**
   - In your Railway project, click "New" → "GitHub Repo" → Select the same repository

2. **Configure the service:**
   - Go to the service settings
   - Set **Root Directory**: (leave as root)
   - Set **Dockerfile Path**: `Dockerfile.streamlit`
   - Railway will use this Dockerfile to build the UI service

3. **Set environment variables:**
   - Go to "Variables" tab
   - Add `BACKEND_URL`: Set to your API service URL (e.g., `https://netsec-auditor-api.up.railway.app`)
   - **Important:** Use the full HTTPS URL of your API service

4. **Deploy:**
   - Railway will build and deploy the UI service
   - Railway provides a public URL like `https://netsec-auditor-ui.up.railway.app`

5. **Access the application:**
   - Streamlit UI: `https://your-ui-service.up.railway.app`
   - API Docs: `https://your-api-service.up.railway.app/docs`

### Deploy on Render (Alternative)

#### Backend (API Service)

1. **Create a new Web Service:**
   - Go to [Render](https://render.com) and create a new Web Service
   - Connect your GitHub repository

2. **Configure the service:**
   - **Name**: `netsec-auditor-api` (or your choice)
   - **Environment**: Docker
   - **Region**: Choose closest to your users
   - **Branch**: `main` (or your default branch)
   - **Root Directory**: (leave blank for root)
   - **Dockerfile Path**: `Dockerfile` (or leave blank if in root)
   - **Start Command**: (leave blank - Dockerfile CMD handles it)

3. **Add PostgreSQL database:**
   - In Render dashboard, click "New" → "PostgreSQL"
   - Choose a plan (Free tier available)
   - Render automatically provides `DATABASE_URL`
   - Link the database to your API service

4. **Set environment variables:**
   - Go to "Environment" tab in your API service
   - `DATABASE_URL`: Automatically set by Render from PostgreSQL service
   - Add `OPENAI_API_KEY` (optional): Your OpenAI API key
   - Add `API_KEY` (optional): Static API key for initial access
   - Add `ALLOWED_ORIGINS`: Comma-separated list like `https://your-api.onrender.com,https://your-ui.onrender.com`
   - Add `DEBUG`: `false`
   - Add `LOG_LEVEL`: `INFO`

5. **Create and deploy:**
   - Click "Create Web Service"
   - Render will build and deploy your API
   - Render provides a URL like `https://netsec-auditor-api.onrender.com`

#### Frontend (Streamlit UI Service)

1. **Create a new Web Service:**
   - Click "New" → "Web Service"
   - Connect the same GitHub repository

2. **Configure the service:**
   - **Name**: `netsec-auditor-ui`
   - **Environment**: Docker
   - **Region**: Same as API service
   - **Branch**: `main`
   - **Root Directory**: (leave blank)
   - **Dockerfile Path**: `Dockerfile.streamlit`
   - **Start Command**: (leave blank - Dockerfile CMD handles it)

3. **Set environment variables:**
   - Go to "Environment" tab
   - Add `BACKEND_URL`: Set to your API service URL (e.g., `https://netsec-auditor-api.onrender.com`)

4. **Create and deploy:**
   - Click "Create Web Service"
   - Render will build and deploy your UI
   - Render provides a URL like `https://netsec-auditor-ui.onrender.com`

5. **Access the application:**
   - Streamlit UI: `https://your-ui-service.onrender.com`
   - API Docs: `https://your-api-service.onrender.com/docs`

**Note:** Render provides a `render.yaml` configuration file in this repository that can be used to automate service creation. You can import it when creating services, or create services manually as described above.

### How to Point Streamlit → API

The Streamlit UI reads the backend URL from the `BACKEND_URL` environment variable:

1. **In cloud deployment:**
   - Set `BACKEND_URL` environment variable in your UI service
   - Example: `BACKEND_URL=https://netsec-auditor-api.railway.app`

2. **In local development:**
   - If `BACKEND_URL` is not set, it defaults to `http://localhost:8000`
   - You can also change it in the Streamlit UI sidebar under "Backend URL"

3. **Verification:**
   - Open the Streamlit UI
   - Check the sidebar - it should show the correct backend URL
   - Try uploading a config file - if it works, the connection is correct

### Smoke Test

After deployment, verify everything works:

1. **Test API:**
   ```bash
   # Health check
   curl https://your-api-service.railway.app/health
   # Expected: {"status": "ok"}
   
   # API root
   curl https://your-api-service.railway.app/
   # Expected: JSON with message, version, docs
   ```

2. **Test UI:**
   - Open `https://your-ui-service.railway.app` in your browser
   - The UI should load
   - Check the sidebar - it should show your API URL in "Backend URL" field

3. **Test full workflow:**
   - Upload a sample configuration file
   - Run parse and audit
   - Verify results appear
   - Check that API docs are accessible at `https://your-api-service.railway.app/docs`

### Getting Your Initial Admin API Key

After deployment, you'll need an API key to access protected endpoints:

1. **Option 1: Use Static API Key (if set)**
   - If you set `API_KEY` environment variable during deployment, use that key
   - Enter it in the Streamlit UI sidebar under "API Key (Optional)"

2. **Option 2: Create Database-Backed Key (Recommended)**
   - Access the Streamlit UI
   - Enter your static `API_KEY` in the sidebar (if you set one)
   - Go to the "Admin: API Keys" tab (visible only to admin users)
   - Click "Create New API Key"
   - Choose role: `admin` for full access
   - Copy the key immediately - it's only shown once!
   - Use this key for all future access

3. **Option 3: Direct API Call (if you have static key)**
   ```bash
   curl -X POST https://your-api-service.railway.app/api/v1/api-keys/ \
     -H "X-API-Key: your-static-api-key" \
     -H "Content-Type: application/json" \
     -d '{"name": "Admin Key", "role": "admin"}'
   ```

### Local Docker Compose (Testing)

Test the full stack locally before deploying to cloud:

```bash
# Build and start all services (PostgreSQL, API, Streamlit UI)
docker-compose up --build

# Access services:
# - FastAPI API: http://localhost:8000
# - API Docs: http://localhost:8000/docs
# - Streamlit UI: http://localhost:8501
```

The `docker-compose.yml` includes:
- **db**: PostgreSQL 16 database
- **api**: FastAPI backend (port 8000)
- **ui**: Streamlit frontend (port 8501)

All services use environment variables from `.env` or docker-compose defaults.

### Getting Your Initial Admin API Key

After deployment, you need an API key to access the application:

1. **Option 1: Use Static API Key (if set)**
   - If you set `API_KEY` environment variable, use that key
   - Enter it in the Streamlit UI sidebar under "API Key (Optional)"

2. **Option 2: Create Database-Backed Key (Recommended)**
   - First, you need to access the API with the static key (if set) or temporarily disable auth
   - Use the Admin UI in Streamlit to create database-backed API keys
   - Go to "Admin: API Keys" tab (visible only to admin users)
   - Create a new API key with "admin" role
   - Copy the key immediately (it's only shown once)
   - Use this key for all future access

3. **Option 3: Direct API Call (if you have static key)**
   ```bash
   curl -X POST https://your-api-service.com/api/v1/api-keys/ \
     -H "X-API-Key: your-static-api-key" \
     -H "Content-Type: application/json" \
     -d '{"label": "Admin Key", "role": "admin"}'
   ```

### Docker Compose for Self-Hosted Production

For self-hosted deployments on your own server:

```bash
# Create .env file with production settings
cat > .env << EOF
POSTGRES_USER=netsec_user
POSTGRES_PASSWORD=secure_password_here
POSTGRES_DB=netsec_auditor
API_KEY=your-secure-static-api-key
OPENAI_API_KEY=your-openai-key-optional
CORS_ORIGINS=["https://yourdomain.com","https://ui.yourdomain.com"]
DEBUG=false
LOG_LEVEL=INFO
EOF

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Production Notes

- **Database**: Use managed PostgreSQL (Railway, Render, AWS RDS, etc.) for production
- **File Storage**: Uploads are stored in the container's filesystem. For production, consider using object storage (S3, etc.)
- **API Keys**: Use the Admin UI to create database-backed API keys instead of static `API_KEY` for better security and key rotation
- **HTTPS**: Ensure both API and UI services use HTTPS in production
- **CORS**: Set `CORS_ORIGINS` to your actual domain(s) in production
- **Ports**: Railway/Render set `$PORT` automatically, but our Dockerfiles use fixed ports (8000 for API, 8501 for UI). Most platforms handle this automatically.

## Running Backend Locally (Linux/Mac)

For Linux/Mac local development:

1. **Create virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   
   Note: `psycopg2-binary` will be installed on Linux/Mac (for optional PostgreSQL use).

3. **Configure environment variables (optional):**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` if needed:
   - `DATABASE_URL`: Leave unset to use SQLite (default: `sqlite:///./netsec_auditor.db`)
   - Or set `DATABASE_URL` to use PostgreSQL locally (e.g., `postgresql://user:password@localhost:5432/netsec_auditor`)

4. **Run the application:**
   ```bash
   python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

## Usage Flow

### 1. Upload Configuration File

Upload a firewall/router configuration file (.txt format):

```bash
curl -X POST "http://localhost:8000/api/v1/upload/" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@router_config.txt"
```

**Response:**
```json
{
  "id": 1,
  "filename": "cisco_asa_config_1.txt",
  "vendor": "cisco_asa",
  "original_filename": "router_config.txt",
  "file_size": 45678,
  "uploaded_at": "2024-01-15T10:30:00Z",
  "parsed_at": null
}
```

### 2. Parse Configuration

Extract network elements from the uploaded configuration:

```bash
curl -X POST "http://localhost:8000/api/v1/upload/1/parse" \
  -H "accept: application/json"
```

**Response:**
```json
{
  "config_file_id": 1,
  "parsed": true,
  "parsed_at": "2024-01-15T10:31:00Z",
  "elements_parsed": {
    "acls": 45,
    "nat_rules": 12,
    "vpns": 3,
    "interfaces": 8,
    "routes": 15
  }
}
```

### 3. Run Security Audit

Perform security analysis on the parsed configuration:

```bash
curl -X POST "http://localhost:8000/api/v1/audit/1" \
  -H "accept: application/json"
```

**Response:**
```json
{
  "config_file_id": 1,
  "vendor": "cisco_asa",
  "filename": "cisco_asa_config_1.txt",
  "risk_score": 35,
  "summary": "Found 4 security finding(s) (2 high, 2 medium severity). Risk score: 35/100.",
  "findings": [
    {
      "severity": "critical",
      "code": "ACL_ANY_ANY_INBOUND",
      "description": "ACL 'OUTSIDE-IN' permits any-to-any traffic",
      "affected_objects": ["ACL:OUTSIDE-IN", "Rule ID:12"],
      "recommendation": "Replace 'any' with specific source and destination networks..."
    }
  ]
}
```

### 4. Browse Configurations

List all uploaded configurations:

```bash
curl -X GET "http://localhost:8000/api/v1/configs/?limit=20&offset=0" \
  -H "accept: application/json"
```

Get detailed information about a specific configuration:

```bash
curl -X GET "http://localhost:8000/api/v1/configs/1" \
  -H "accept: application/json"
```

## Project Structure

```
netsec-auditor/
├── app/
│   ├── api/
│   │   └── v1/
│   │       ├── endpoints/
│   │       │   ├── upload.py      # File upload endpoints
│   │       │   ├── audit.py       # Security audit endpoints
│   │       │   └── configs.py     # Configuration list/detail endpoints
│   │       └── router.py          # API router configuration
│   ├── core/
│   │   ├── config.py              # Application settings
│   │   ├── database.py            # Database connection
│   │   └── logging_config.py      # Logging setup
│   ├── models/                    # SQLAlchemy ORM models
│   │   ├── config_file.py
│   │   ├── acl.py
│   │   ├── nat_rule.py
│   │   ├── vpn.py
│   │   ├── interface.py
│   │   └── routing.py
│   ├── schemas/                   # Pydantic schemas
│   │   ├── config.py
│   │   ├── audit.py
│   │   └── findings.py
│   ├── services/                  # Business logic
│   │   ├── config_service.py      # Configuration parsing
│   │   └── audit_service.py       # Security auditing
│   ├── utils/
│   │   ├── vendor_detector.py     # Vendor detection
│   │   └── parsers/               # Configuration parsers
│   │       ├── base_parser.py
│   │       ├── acl_models.py      # Structured ACL models
│   │       ├── cisco_asa_parser.py
│   │       ├── cisco_ios_parser.py
│   │       ├── fortinet_parser.py
│   │       └── palo_alto_parser.py
│   └── main.py                    # FastAPI application
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

## Running Tests

The project includes automated tests using pytest and FastAPI's TestClient.

### Prerequisites

Install test dependencies (included in requirements.txt):
```bash
pip install -r requirements.txt
```

### Run Tests

```bash
pytest
```

Run with verbose output:
```bash
pytest -v
```

Run with coverage:
```bash
pytest --cov=app --cov-report=html
```

### Test Configuration

Tests use:
- **In-memory SQLite database** - No PostgreSQL required for testing
- **Disabled authentication** - API key auth is bypassed in tests
- **Disabled AI** - Tests rely only on rule-based audit logic (no OpenAI calls)

### Test Coverage

The test suite (`tests/test_upload_parse_audit.py`) covers:
- ✅ Configuration file upload
- ✅ Configuration parsing and data extraction (ACLs, interfaces, routes, NAT rules)
- ✅ Security audit execution with risk scoring
- ✅ Complete end-to-end workflow
- ✅ Audit response structure validation (risk_score, breakdown, findings)

### Test Structure

Tests are organized in `tests/` directory:
- `conftest.py` - Pytest fixtures (database, test client)
- `test_upload_parse_audit.py` - Core workflow tests

## Running the Frontend (Streamlit)

This project includes an optional Streamlit web dashboard for interacting with the API.

**Prerequisites:** The FastAPI backend must be running at `http://localhost:8000` before starting the Streamlit dashboard.

### Install dependencies

```bash
pip install streamlit requests
```

### Run the dashboard

From the project root directory:

```bash
python -m streamlit run streamlit_app.py
```

The dashboard will be available at: **http://localhost:8501**

### Features

- Upload router/firewall configs
- Add metadata (device, environment, location)
- Run parsing and security audit
- View risk score and findings
- Download professional PDF audit report
- API key authentication support

**Note:** Make sure the FastAPI backend is running first (see "Running the Backend (Docker)" section above). The dashboard connects to `http://localhost:8000` by default, which can be changed in the sidebar settings.

## For Hiring Managers

This project demonstrates several key competencies:

**Network Security Domain Knowledge**: The application showcases deep understanding of network security concepts, including firewall rule analysis, NAT configuration, VPN setup, and routing security. The rule-based security engine implements real-world security checks that security professionals use daily.

**Backend Engineering Excellence**: Built with FastAPI, the application demonstrates modern Python web development practices including:
- Type-safe code with Pydantic validation
- Clean architecture with separation of concerns (API, services, models)
- Proper database modeling with SQLAlchemy ORM
- RESTful API design with comprehensive documentation
- Production-ready error handling and logging

**AI Integration**: The optional OpenAI integration demonstrates practical application of AI/LLM technology to solve real business problems. The system gracefully degrades to rule-based analysis when AI is unavailable.

**DevOps & Deployment**: Docker and docker-compose configuration show understanding of containerization and modern deployment practices.

**Code Quality**: The codebase follows Python best practices with type hints, comprehensive error handling, structured logging, and clean code principles.

This project is suitable for roles in backend engineering, security engineering, DevOps, or full-stack development with a security focus.

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
