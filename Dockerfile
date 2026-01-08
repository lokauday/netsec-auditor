FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Copy startup script
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Create directories for uploads and logs
RUN mkdir -p uploads logs && \
    chmod -R 755 uploads logs

# Expose port (default 8080, but Railway will use $PORT)
EXPOSE 8080

# Run the application using startup script
# Railway sets $PORT env var - script will use it or default to 8080
CMD ["/app/start.sh"]

