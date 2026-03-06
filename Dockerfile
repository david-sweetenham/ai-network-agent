FROM python:3.12-slim

# System tools required for network scanning.
# arp-scan: LAN device discovery
# vnstat: bandwidth stats (CLI only; daemon runs on the host)
# iproute2: provides the ss command for connection counting
RUN apt-get update && apt-get install -y --no-install-recommends \
    arp-scan \
    vnstat \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies before copying source so this layer is cached
# and only rebuilds when requirements.txt changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source. Shell scripts and docs are excluded via .dockerignore.
COPY alerts.py network_summary.py dashboard.py ./

EXPOSE 5000

CMD ["python", "dashboard.py"]
