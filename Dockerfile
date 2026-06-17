FROM python:3.12-slim

LABEL org.opencontainers.image.title="Automation Hardening"
LABEL org.opencontainers.image.description="Cross-platform security baseline auditing and controlled remediation"
LABEL org.opencontainers.image.source="https://github.com/wahidhendrawan/Automation-Hardening"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY . /app

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir '.[aws,azure,gcp]'

ENTRYPOINT ["automation-hardening"]
CMD ["--help"]
