FROM python:3.11-slim

LABEL maintainer="Threat Intelligence Pipeline"
LABEL description="Automated threat intelligence collection, enrichment, and scoring pipeline"

# Prevent Python from writing .pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies required by python-whois and psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    whois \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN groupadd -r tipuser && useradd -r -g tipuser tipuser && \
    mkdir -p /app/data/raw /app/data/staging /app/data/reports /app/logs && \
    chown -R tipuser:tipuser /app

USER tipuser

# Health check — verify the app module can import
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "from src.config import DATABASE_URL; print('OK')" || exit 1

# Default: run the manual pipeline (override in docker-compose for celery)
CMD ["python", "-m", "src.tasks.manual_run"]
