FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS build

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY cloud ./cloud

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir '.[aws,azure,gcp]'

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

LABEL org.opencontainers.image.title="PagerWesi"
LABEL org.opencontainers.image.description="Cross-platform security baseline auditing and controlled remediation"
LABEL org.opencontainers.image.source="https://github.com/wahidhendrawan/PagerWesi"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH=/opt/venv/bin:$PATH

COPY --from=build /opt/venv /opt/venv
RUN useradd --create-home --uid 10001 pagerwesi
USER pagerwesi
WORKDIR /home/pagerwesi

# CLI only, no HTTP endpoint, so no HEALTHCHECK.
ENTRYPOINT ["pagerwesi"]
CMD ["--help"]
