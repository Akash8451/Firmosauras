# Router base image (SHARED, PR-gated).
# Group 1 seeds this: Python 3.11 + confluent-kafka + redis + shared contracts.
# Group 2 extends it with binwalk + pinned extraction backends (for unpack.py)
# via a flagged, fast-review PR — never a silent edit.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# --- Group 2: system extraction backends for binwalk (unpack.py) ------------
# Version-pinned by the frozen Debian bookworm snapshot the base image tag pins.
# --no-install-recommends keeps the image lean (WSL2 memory budget). These are
# the CLI tools binwalk shells out to; the Python backends are installed below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        squashfs-tools \
        p7zip-full \
        unzip \
        xz-utils \
        lzop \
        cpio \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first for layer caching. The confluent-kafka manylinux wheel
# bundles librdkafka, so no apt build step is needed at this stage.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# --- Group 2: Python extraction backends (binwalk + jefferson + ubi_reader) -
COPY services/ingestion/requirements.txt ./ingestion-requirements.txt
RUN pip install --no-cache-dir -r ingestion-requirements.txt

# Application code: the frozen contracts + the router package.
COPY shared/ ./shared/
COPY services/ ./services/

# Topology is chosen at runtime; default to the local fat-container mode.
# In-container the broker/redis hosts differ from the host-native defaults.
ENV SERVICES=all \
    REDPANDA_BROKERS=redpanda:9092 \
    REDIS_URL=redis://redis:6379/0

CMD ["python", "-m", "services.router.runner"]
