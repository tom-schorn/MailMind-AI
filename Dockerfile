# Multi-stage build for smaller image
FROM python:3.12-slim as builder

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


FROM python:3.12-slim

# Create non-root user
RUN useradd -m -u 1000 mailmind

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder /root/.local /home/mailmind/.local

# Copy application files
COPY --chown=mailmind:mailmind . .

# Environment variables
ENV PATH=/home/mailmind/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    FLASK_HOST=0.0.0.0 \
    FLASK_PORT=5000

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/service/status')" || exit 1

# Labels
ARG VERSION=dev
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.title="MailMind AI" \
      org.opencontainers.image.description="Email automation and rule processing" \
      org.opencontainers.image.vendor="TS Entwicklung" \
      maintainer="TS Entwicklung"

# Switch to non-root user
USER mailmind

# Run application
CMD ["python", "__main__.py"]
