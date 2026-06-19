# auth-service image. Full build with the assembled app is deferred to phase8.ckpt3.
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies first for layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source ONLY. The RS256 signing keys are NEVER baked into the
# image — they are mounted read-only at runtime (compose: ./keys:/app/keys:ro),
# so the image carries no secrets. JWT_*_KEY_PATH still points at /app/keys.
COPY app/ ./app/

EXPOSE 8003

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8003"]
