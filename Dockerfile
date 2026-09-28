FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CERBERUS_API_HOST=0.0.0.0 \
    CERBERUS_API_PORT=8099 \
    CERBERUS_DB_PATH=/data/cerberus.db

WORKDIR /app

RUN addgroup --system cerberus \
    && adduser --system --ingroup cerberus --home /app cerberus \
    && mkdir -p /data \
    && chown cerberus:cerberus /data

COPY requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt

COPY cerberus ./cerberus
COPY console ./console

USER cerberus
EXPOSE 8099
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8099/health', timeout=3).read()"]

CMD ["python", "-m", "cerberus.api"]
