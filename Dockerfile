FROM python:3.12-slim
RUN apt-get update && apt-get install --no-install-recommends -y iproute2 && rm -rf /var/lib/apt/lists/*
ARG BUILD_REVISION=unknown
ENV BUILD_REVISION=${BUILD_REVISION}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY maxbot_v2 ./maxbot_v2
COPY scripts ./scripts
COPY static ./static
RUN useradd --system --uid 10001 --home-dir /nonexistent maxbot && mkdir -p /data && chown -R 10001:10001 /data
USER 10001:10001
CMD ["uvicorn", "maxbot_v2.app:create_app", "--factory", "--host", "127.0.0.1", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1", "--no-access-log"]
