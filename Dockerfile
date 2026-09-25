FROM python:3.12-slim
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
EXPOSE 8000
CMD ["uvicorn", "maxbot_v2.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--no-access-log"]
