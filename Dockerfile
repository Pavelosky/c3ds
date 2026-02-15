# Multi-stage build for optimized image size
# Stage 1: Builder - Install dependencies
FROM python:3.12-slim as builder

WORKDIR /app

# Install system dependencies for PostgreSQL and cryptography
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Production - Minimal runtime image
FROM python:3.12-slim

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Create staticfiles directory
RUN mkdir -p staticfiles

# Make startup script executable
RUN chmod +x start.sh

# Create non-root user for security
RUN useradd -m -u 1000 django && chown -R django:django /app
USER django

# Expose port (Railway will override with PORT env var)
EXPOSE 8000

# Use startup script for better logging and diagnostics
CMD ["./start.sh"]
