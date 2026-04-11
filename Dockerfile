FROM node:22-slim

LABEL org.opencontainers.image.source="https://github.com/pegasi-ai/clawreins"
LABEL org.opencontainers.image.description="OpenClaw with ClawReins intervention layer"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Python for ToolShield
RUN apt-get update && apt-get install -y \
    python3 python3-pip git \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install OpenClaw globally
RUN npm install -g openclaw@latest

# Install ClawReins deps + build
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build && npm install -g .

# Install bundled ToolShield
RUN pip3 install --no-cache-dir ./src/core/toolshield --break-system-packages

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Persist OpenClaw config and agent workspace across runs
VOLUME ["/root/.openclaw", "/workspace"]
WORKDIR /workspace

# CLAWREINS_POLICY: permissive | balanced | strict (default: balanced)
ENV CLAWREINS_POLICY=balanced

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--help"]
