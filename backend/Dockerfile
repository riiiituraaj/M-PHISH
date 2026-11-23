FROM python:3.12-slim AS build
WORKDIR /build
COPY backend/requirements.lock .
RUN python -m pip install --no-cache-dir --prefix=/install -r requirements.lock
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/* && useradd --create-home --uid 10001 appuser
WORKDIR /app
COPY --from=build /install /usr/local
COPY backend ./backend
COPY data/samples ./data/samples
USER 10001
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=2)"
CMD ["uvicorn","backend.app.main:app","--host","0.0.0.0","--port","8000","--no-access-log","--limit-concurrency","64","--timeout-keep-alive","5"]
