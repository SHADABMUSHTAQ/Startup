# 🐳 WarSOC Master Build Dockerfile
# Optimized for production, multi-purpose usage (API + Workers)
# Complies with PTA CTDISR-2025 data security standards.

FROM python:3.10-slim

# 1. Environment Configuration
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC

# 2. System Dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 3. Directory Structure
WORKDIR /app

# 4. Dependency Installation
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir cryptography==43.0.0 && \
    pip install --no-cache-dir -r requirements.txt

# 5. Application Ingestion
# Copy the core app and workers into the container
COPY ./app ./app
COPY .env .env

# 6. Security Hardening
# Create a non-root user for process isolation
RUN adduser --disabled-password --gecos '' warsoc-user && \
    chown -R warsoc-user:warsoc-user /app

USER warsoc-user

# 7. Operational Port
EXPOSE 8000

# 8. Entrypoint Configuration
# Default command (overridden in docker-compose.yml for workers)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
