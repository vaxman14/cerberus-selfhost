FROM node:22-bookworm-slim AS subscription-clis

ARG CERBERUS_CODEX_VERSION=0.152.0
ARG CERBERUS_CLAUDE_VERSION=2.1.258
RUN npm install -g --ignore-scripts \
      "@openai/codex@${CERBERUS_CODEX_VERSION}" \
      "@anthropic-ai/claude-code@${CERBERUS_CLAUDE_VERSION}" \
    && node "$(npm root -g)/@anthropic-ai/claude-code/install.cjs" \
    && codex --version \
    && claude --version

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CERBERUS_API_HOST=0.0.0.0 \
    CERBERUS_API_PORT=8099 \
    CERBERUS_DB_PATH=/data/cerberus.db

WORKDIR /app

COPY --from=subscription-clis /usr/local/bin/ /usr/local/bin/
COPY --from=subscription-clis /usr/local/lib/node_modules/ /usr/local/lib/node_modules/

RUN addgroup --system cerberus \
    && adduser --system --ingroup cerberus --home /app cerberus \
    && mkdir -p /data/codex /data/claude \
    && chmod 0700 /data/codex /data/claude \
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
