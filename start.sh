#!/bin/bash
set -e

echo "=========================================="
echo "NetSec Auditor API - Starting up..."
echo "=========================================="

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo "WARNING: DATABASE_URL not set. Skipping migrations."
    echo "Using SQLite or fallback database configuration."
else
    echo "DATABASE_URL detected, running migrations..."
    echo "Running: alembic upgrade head"
    alembic upgrade head
    echo "Migrations completed successfully."
fi

echo ""
echo "Starting FastAPI server..."
echo "Host: 0.0.0.0"
echo "Port: ${PORT:-8000}"
echo "=========================================="

# Start the FastAPI application
exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}

