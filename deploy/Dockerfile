# Firmosaurus production/integration image (Group 4 — production profile).
#
# ONE image runs every process — the router (any SERVICES value), the gateway
# (services.integration.app), and the notifier — selected purely by the compose
# `command:` + `SERVICES` env. This is what proves the codebase is byte-identical
# between the SERVICES=all fat container and the split-container prod profile:
# same image digest, only compose + env differ.
#
# The PR-gated dev router image (services/router/Dockerfile) is intentionally left
# untouched; this is a separate, Group-4-owned production image whose only extra
# job is to carry the full dependency union (deploy/requirements.txt).
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System extraction backends binwalk shells out to (unpack.py). Pinned by the
# frozen Debian bookworm snapshot the base tag pins; --no-install-recommends keeps
# the image lean for the WSL2 memory/disk budget.
RUN apt-get update && apt-get install -y --no-install-recommends \
        squashfs-tools \
        p7zip-full \
        unzip \
        xz-utils \
        lzop \
        cpio \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first for layer caching. The full union so any process can run.
COPY deploy/requirements.txt ./deploy/requirements.txt
RUN pip install --no-cache-dir -r deploy/requirements.txt

# Application code: the frozen contracts + every service.
COPY shared/ ./shared/
COPY services/ ./services/

# In-container hosts differ from the host-native defaults. SERVICES chooses the
# router topology; the gateway/notifier override `command:` in compose.
ENV SERVICES=all \
    REDPANDA_BROKERS=redpanda:9092 \
    REDIS_URL=redis://redis:6379/0

# Default process is the router; the gateway/notifier services override this.
CMD ["python", "-m", "services.router.runner"]
