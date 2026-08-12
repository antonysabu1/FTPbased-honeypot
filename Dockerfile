FROM python:3.11-slim

# Prevent Python from writing .pyc files & enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies if required
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy honeypot codebase
COPY . .

# Ensure storage directories exist
RUN mkdir -p /app/data /app/quarantine

# NIST SP 800-190 hardening: run under an unprivileged UID (matches compose)
RUN useradd --uid 10001 --create-home honeypot \
    && chown -R 10001:10001 /app/data /app/quarantine
USER 10001

# Expose ports: FTP (21), Flask Dashboard (5000), PASV range (50000-50010)
EXPOSE 21 5000 50000-50010

# Command to run honeypot
CMD ["python", "run_honeypot.py"]
