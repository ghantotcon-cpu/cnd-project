FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/ghantotcon-cpu/cnd-project"
LABEL org.opencontainers.image.description="CND Project Demo Microservice"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

RUN groupadd -r appuser && useradd -r -g appuser appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

ARG BUILD_COMMIT=unknown
ARG APP_VERSION=1.0.0
ENV BUILD_COMMIT=${BUILD_COMMIT}
ENV APP_VERSION=${APP_VERSION}
ENV SLSA_LEVEL=3

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "main:app"]
