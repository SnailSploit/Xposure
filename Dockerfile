# X-POSURE v4.0 - Enterprise Credential Scanner
# "The shit your DevOps forgot."
#
# Build:  docker build -t xposure .
# Run:    docker run -it xposure example.com
# API:    docker run -p 8080:8080 xposure --api

FROM python:3.11-slim

LABEL maintainer="SnailSploit"
LABEL version="4.0.0"
LABEL description="Autonomous credential harvesting system"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user for security
RUN groupadd -r xposure && useradd -r -g xposure xposure

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the package
RUN pip install --no-cache-dir -e .

# Create data directory for persistence
RUN mkdir -p /data && chown -R xposure:xposure /data
VOLUME /data

# Set database path to persistent volume
ENV XPOSURE_DB_PATH=/data/xposure.db

# Switch to non-root user
USER xposure

# Default port for API server
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import xposure; print('OK')" || exit 1

# Default entrypoint
ENTRYPOINT ["python", "-m", "xposure"]

# Default command (show help)
CMD ["--help"]
