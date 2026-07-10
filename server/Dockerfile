# Multi-stage build for production-ready FastAPI server

FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install system dependencies required for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and constraints
COPY requirements.txt .
COPY constraints.txt .

ENV PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=3 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip==24.0 setuptools wheel && \
    pip install --no-cache-dir --constraint constraints.txt -r requirements.txt

# ML Classification dependencies
COPY requirements-ml.txt .
RUN pip install --no-cache-dir -r requirements-ml.txt && \
    python -m spacy download en_core_web_sm

# Verify critical packages are installed correctly
RUN python -c "import numpy; print(f'NumPy version: {numpy.__version__}')" && \
    python -c "import pandas; print(f'Pandas version: {pandas.__version__}')" && \
    python -c "import fastapi; print(f'FastAPI version: {fastapi.__version__}')"

# Production stage
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Create necessary directories and make entrypoint executable
# /app/reports must be created here (before chown) so the named Docker volume
# inherits dlpuser ownership on first mount — otherwise Docker creates it as root
# and the Celery worker cannot write PDF/CSV files into it.
RUN mkdir -p /app/logs /app/quarantine /app/ml/models /app/reports && \
    chmod +x /app/entrypoint.sh

# Create non-root user
RUN useradd -m -u 1000 dlpuser && \
    chown -R dlpuser:dlpuser /app

# Switch to non-root user
USER dlpuser

# Expose port (default 55000, can be overridden)
EXPOSE 55000

# Set default number of workers
ENV UVICORN_WORKERS=${UVICORN_WORKERS:-4}
ENV PORT=55000

# Single health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Run migrations then start the application
ENTRYPOINT ["/app/entrypoint.sh"]
