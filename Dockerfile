FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY llm-fingerprint-detector ./llm-fingerprint-detector

RUN pip install --no-cache-dir . \
    && cd llm-fingerprint-detector \
    && npm ci \
    && npm run build

RUN useradd --create-home --uid 10001 auditor \
    && mkdir -p /app/data \
    && chown -R auditor:auditor /app

USER auditor

EXPOSE 8000

CMD ["uvicorn", "relay_auditor.main:app", "--host", "0.0.0.0", "--port", "8000"]
