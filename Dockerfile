FROM python:3.12-slim

# openssl is not optional: timestamp_file() shells out to `openssl ts -query` and
# swallows OSError, so a missing binary means evidence saved with no RFC-3161
# timestamp and only a one-line warning. That is the whole point of step 1.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirement.txt .
RUN pip install --no-cache-dir -r requirement.txt
COPY . .

ENV PYTHONUNBUFFERED=1
EXPOSE 8000
# Shell form so Render's $PORT expands.
CMD uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}
