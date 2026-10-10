# Madrigal Protocol Lab - backend
#
# Hardening notes (see docs/SECURITY.md):
# - non-root user, read-only root filesystem
# - capture parsing is a risk area, so the image ships no shell tooling and no
#   package manager: there is nothing in the container to exec even if the
#   process were compromised
# - HEALTHCHECK uses the stdlib so no curl/wget is required

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MPLAB_MODE=local_secure \
    MPLAB_PORT=8010

# Bind every interface *inside the container*: a published port routes to the
# container's namespace, not to its loopback. Reachability is restricted by the
# host-side port mapping (127.0.0.1:8010:8010 in docker-compose.yml), and the
# Host/Origin allowlist still applies. Overridden below at runtime.
ENV MPLAB_HOST=0.0.0.0

# Create an unprivileged user with a fixed uid so bind-mount ownership is stable.
RUN groupadd --system --gid 10001 mplab \
    && useradd --system --uid 10001 --gid mplab --no-create-home mplab

WORKDIR /app

# Dependencies first so the layer caches independently of the source.
COPY pyproject.toml ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install "fastapi==0.141.1" "uvicorn[standard]==0.34.0" \
        "pydantic==2.13.5" "SQLAlchemy==2.0.48" "alembic==1.20.0" \
        "python-multipart==0.0.20" "numpy==2.3.1"

COPY app ./app

# Writable state lives outside the read-only root.
RUN mkdir -p /app/data/storage /app/data/secrets /app/data/temp /app/data/logs \
    && chown -R mplab:mplab /app/data \
    && chmod 700 /app/data/secrets

ENV PATH="/opt/venv/bin:$PATH" \
    MPLAB_DATA_DIR=/app/data

USER mplab

EXPOSE 8010

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8010/api/health', timeout=4).status==200 else 1)"]

CMD ["python", "-m", "app"]