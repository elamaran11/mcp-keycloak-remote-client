FROM python:3.12-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir mcp

# Copy application code
COPY . .

# Create non-root user and set permissions
RUN useradd -m -r mcpclient && \
    chown -R mcpclient:mcpclient /app && \
    # Create directory for any writable files
    mkdir -p /app/data && \
    chown -R mcpclient:mcpclient /app/data && \
    chmod -R 770 /app/data

USER mcpclient

# Expose the port the app runs on
EXPOSE 4001

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:4001/health || exit 1

# Command to run the application
CMD ["python3", "api.py", "--host", "0.0.0.0", "--port", "4001"]