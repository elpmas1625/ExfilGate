FROM python:3.12-slim

WORKDIR /app

ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && case "$TARGETARCH" in \
        amd64) GITLEAKS_ARCH=linux_x64 ;; \
        arm64) GITLEAKS_ARCH=linux_arm64 ;; \
        *) echo "unsupported architecture: $TARGETARCH" && exit 1 ;; \
    esac \
    && GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GITLEAKS_ARCH}.tar.gz" \
    && curl -fsSL "$GITLEAKS_URL" -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && gitleaks version \
    && apt-get purge -y --auto-remove curl \
    && rm -f /tmp/gitleaks.tar.gz \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY app ./app
COPY examples ./examples
COPY main.py ./

RUN pip install --no-cache-dir .

ENV AICF_CONFIG=/app/examples/config.yaml
ENV AICF_AUDIT_PATH=/data/audit.jsonl

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
