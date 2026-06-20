FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY app ./app
COPY examples ./examples
COPY main.py ./

RUN pip install --no-cache-dir .

ENV AICF_CONFIG=/app/examples/config.yaml
ENV AICF_AUDIT_PATH=/data/audit.jsonl

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
