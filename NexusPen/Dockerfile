# NexusPen - Penetration Testing Framework
# Multi-stage Docker build for security and size optimization

# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM python:3.11-slim-bookworm AS builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM python:3.11-slim-bookworm AS runtime

# Labels
LABEL maintainer="NexusPen Development Team" \
      version="1.0.0" \
      description="NexusPen Penetration Testing Framework" \
      org.opencontainers.image.source="https://github.com/nexuspen/nexuspen"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    NEXUSPEN_HOME="/nexuspen" \
    NEXUSPEN_OUTPUT="/output"

# Install runtime dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network tools
    nmap \
    netcat-openbsd \
    iputils-ping \
    dnsutils \
    whois \
    curl \
    wget \
    # Web tools
    nikto \
    dirb \
    # Misc
    git \
    vim-tiny \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create non-root user for security
RUN groupadd -r nexuspen && \
    useradd -r -g nexuspen -d /home/nexuspen -s /bin/bash nexuspen && \
    mkdir -p /home/nexuspen /nexuspen /output && \
    chown -R nexuspen:nexuspen /home/nexuspen /nexuspen /output

# Set working directory
WORKDIR /nexuspen

# Copy application code
COPY --chown=nexuspen:nexuspen . .

# Create output directory for reports
RUN mkdir -p /output/reports /output/logs /output/data && \
    chown -R nexuspen:nexuspen /output

# Volume for persistent data
VOLUME ["/output"]

# Switch to non-root user
USER nexuspen

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import modules; print('OK')" || exit 1

# Default command
ENTRYPOINT ["python", "nexuspen.py"]
CMD ["--help"]

# ============================================================================
# Usage Instructions
# ============================================================================
#
# Build the image:
#   docker build -t nexuspen:latest .
#
# Run interactive shell:
#   docker run -it --rm nexuspen:latest shell
#
# Run with output volume:
#   docker run -it --rm -v $(pwd)/output:/output nexuspen:latest scan -t target.com
#
# Run network scan (needs host network):
#   docker run -it --rm --net=host nexuspen:latest scan -t 192.168.1.0/24
#
# Run with custom config:
#   docker run -it --rm -v $(pwd)/config:/nexuspen/config nexuspen:latest
#
# ============================================================================
