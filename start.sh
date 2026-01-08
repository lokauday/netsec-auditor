#!/bin/bash
set -e

echo "=========================================="
echo "NetSec Auditor API - Starting up..."
echo "=========================================="

# Note: Migrations are now handled in app/main.py lifespan function
# This prevents double-migration runs and ensures idempotent behavior

echo ""
echo "Starting FastAPI server..."
echo "Host: 0.0.0.0"
echo "Port: ${PORT:-8000}"
echo "=========================================="

# Start the FastAPI application
exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}

