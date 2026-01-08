#!/bin/bash
set -euo pipefail

echo "=========================================="
echo "NetSec Auditor API - Starting up..."
echo "=========================================="

# Note: Migrations are now handled in app/main.py lifespan function
# This prevents double-migration runs and ensures idempotent behavior

# Get port from environment variable (Railway sets $PORT)
PORT=${PORT:-8000}

echo ""
echo "Starting FastAPI server..."
echo "Host: 0.0.0.0"
echo "Port: ${PORT}"
echo "=========================================="

# Start the FastAPI application
# Use exec to ensure signals are properly handled
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT}"

