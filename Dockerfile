FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ZTRUST_DB=/data/ztrust.db

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install ".[server]" \
 && useradd --create-home --uid 10001 ztrust \
 && mkdir -p /data && chown ztrust:ztrust /data

USER ztrust
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"

CMD ["ztrust", "serve", "--host", "0.0.0.0", "--port", "8080"]
