FROM semgrep/semgrep:1.89.0 AS semgrep-binary

FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy pre-compiled osemgrep binary — self-contained ELF, no Python/opentelemetry deps
COPY --from=semgrep-binary /usr/local/bin/osemgrep /usr/local/bin/semgrep

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
