# AuthzLedger 1.5.0
# Copyright (c) 2026 Nasser Aldin Farag (0xFarag). All rights reserved.
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="AuthzLedger" \
      org.opencontainers.image.version="1.5.0" \
      org.opencontainers.image.revision="03aea857e35358ddeb13d2a861b633e60c1ca873" \
      org.opencontainers.image.source="https://github.com/0xFarag/0xFarag" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary" \
      org.opencontainers.image.authors="Nasser Aldin Farag" \
      org.opencontainers.image.description="Scoped assessment CLI. Studio binds 127.0.0.1 inside the container."

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SOURCE_DATE_EPOCH=1767225600

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/authzledger
COPY pyproject.toml README.md LICENSE NOTICE.txt MANIFEST.in ./
COPY authzledger ./authzledger

RUN python -m pip install --no-cache-dir '.[reports]' \
    && python -I -c 'import authzledger; raise SystemExit(0 if authzledger.__version__ == "1.5.0" else 1)'

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin authzledger \
    && mkdir -p /home/authzledger/.authzledger /work \
    && chown -R authzledger:authzledger /home/authzledger /work

USER authzledger
WORKDIR /work

ENTRYPOINT ["python", "-I", "-m", "authzledger"]
CMD ["--help"]
