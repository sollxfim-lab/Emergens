FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app

# Install system dependencies required to build Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    git \
    libssl-dev \
    libffi-dev \
    python3-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create runtime directories and a non‑root user
RUN useradd -m -u 1000 appuser && \
    mkdir -p userdata listschool static/data files/proxies wordlist porttxt data logs data/uploads && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

CMD ["python", "app.py"]
