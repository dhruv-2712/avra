FROM node:20-slim AS frontend-builder
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM semgrep/semgrep:1.89.0 AS semgrep-binary

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl \
    && rm -rf /var/lib/apt/lists/*

# Install gitleaks (secrets detection)
RUN curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
    | tar xz -C /usr/local/bin gitleaks

# Install osv-scanner (dependency vulnerability scanning)
RUN curl -sSL -o /usr/local/bin/osv-scanner \
    https://github.com/google/osv-scanner/releases/download/v1.7.4/osv-scanner_linux_amd64 \
    && chmod +x /usr/local/bin/osv-scanner

WORKDIR /app

RUN useradd -m -u 1000 avra

COPY --from=semgrep-binary /usr/local/bin/osemgrep /usr/local/bin/semgrep

# Pre-cache semgrep rule packs so scans never download rules at runtime
RUN mkdir -p /tmp/warm && \
    echo 'console.log(eval(x))' > /tmp/warm/a.js && \
    echo 'import os; os.system(x)' > /tmp/warm/a.py && \
    echo 'public class A { }' > /tmp/warm/a.java && \
    semgrep --config=p/javascript --config=p/nodejs \
            --config=p/python --config=p/typescript \
            --config=p/java --config=p/golang \
            --config=p/ruby --config=p/php \
            --json --timeout=30 /tmp/warm || true; \
    rm -rf /tmp/warm

COPY --from=frontend-builder /frontend/dist /app/static
RUN ls /app/static/index.html

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

RUN chown -R avra:avra /app
USER avra

EXPOSE 8000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
