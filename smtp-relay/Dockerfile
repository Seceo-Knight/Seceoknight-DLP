# Small, self-contained relay image. Deliberately does NOT reuse the manager
# image (which carries the multi-GB ML stack) — the relay only needs SMTP,
# document parsers, and an HTTP client to call the DLP server.
FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Unprivileged: the relay listens on 10025, not a privileged port.
RUN useradd -m -u 1000 relayuser
USER relayuser

EXPOSE 10025
CMD ["python", "-m", "app.main"]
