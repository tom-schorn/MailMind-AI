# Build stage
FROM python:3.12-slim AS builder

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Runtime stage
FROM python:3.12-slim

LABEL org.opencontainers.image.title="MailMind-AI"
LABEL org.opencontainers.image.description="E-Mail spam detection agent"
LABEL org.opencontainers.image.version="0.1.0"

# Create non-root user
RUN useradd --create-home --shell /bin/bash mailmind

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder /root/.local /home/mailmind/.local

# Copy application code
COPY --chown=mailmind:mailmind src/ ./src/

# Switch to non-root user
USER mailmind

# Add local bin to PATH
ENV PATH=/home/mailmind/.local/bin:$PATH
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import mailmind; print('ok')" || exit 1

# Run the application
CMD ["python", "-m", "mailmind"]
