FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && pip install -r requirements.txt \
    && useradd --uid 10001 --no-create-home lw \
    && mkdir /data && chown lw /data

COPY leakwatch ./leakwatch
USER lw

ENV LW_HOST=0.0.0.0 \
    LW_PORT=8765 \
    LW_DATA_DIR=/data \
    LW_TOR_PROXY=socks5h://tor:9050 \
    LW_SEARXNG_URL=http://searxng:8080

EXPOSE 8765
CMD ["python", "-m", "leakwatch"]
