FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pre-create quarantine tmpfs mount point
RUN mkdir -p /tmp/quarantine && chmod 700 /tmp/quarantine

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt || true

COPY . .

# Run worker in standby
CMD ["python", "-c", "import time; print('Supply Chain Analyzer container running with tmpfs'); time.sleep(86400)"]
