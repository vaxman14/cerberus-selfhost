FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS subscription-clis

ARG CERBERUS_CODEX_VERSION=0.152.0
RUN npm install -g --ignore-scripts "@openai/codex@${CERBERUS_CODEX_VERSION}" \
    && codex --version

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

ARG CERBERUS_VERSION=0.2.0
ARG CERBERUS_REVISION=unknown
ARG CERBERUS_CREATED=unknown

LABEL org.opencontainers.image.title="Cerberus" \
      org.opencontainers.image.description="Self-hosted website security and quality scanner" \
      org.opencontainers.image.source="https://github.com/vaxman14/cerberus-selfhost" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${CERBERUS_VERSION}" \
      org.opencontainers.image.revision="${CERBERUS_REVISION}" \
      org.opencontainers.image.created="${CERBERUS_CREATED}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CERBERUS_API_HOST=0.0.0.0 \
    CERBERUS_API_PORT=8099 \
    CERBERUS_DB_PATH=/data/cerberus.db

WORKDIR /app

COPY --from=subscription-clis /usr/local/bin/node /usr/local/bin/node
COPY --from=subscription-clis /usr/local/lib/node_modules/@openai/codex /usr/local/lib/node_modules/@openai/codex

RUN ln -s /usr/local/lib/node_modules/@openai/codex/bin/codex.js /usr/local/bin/codex \
    && addgroup --system --gid 10000 cerberus \
    && adduser --system --uid 10000 --ingroup cerberus --home /app cerberus \
    && mkdir -p /data/codex \
    && chmod 0700 /data/codex \
    && chown -R cerberus:cerberus /data

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
