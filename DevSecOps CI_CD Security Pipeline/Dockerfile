FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    ca-certificates \
    libffi-dev \
    libssl-dev \
    # WeasyPrint GTK dependencies
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libjpeg-dev \
    libopenjp2-7-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN addgroup --system pipelinegroup && adduser --system pipelineuser --ingroup pipelinegroup

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy pipeline code
COPY pipeline_stages/ ./pipeline_stages/
COPY findings/ ./findings/
COPY notifications/ ./notifications/
COPY report/ ./report/
COPY scripts/ ./scripts/
COPY gate_config.json .

# Ensure permissions
RUN chown -R pipelineuser:pipelinegroup /app

# Switch to non-root user
USER pipelineuser

# Set entrypoint to the orchestrator
ENTRYPOINT ["python", "scripts/orchestrator.py"]
CMD ["--help"]
