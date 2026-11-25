# © Nasser Aldin Farag (0xFarag). All rights reserved.
ARG PYTHON_BASE=python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
FROM ${PYTHON_BASE} AS dependencies
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
COPY team/requirements.txt /build/requirements.txt
RUN python -m venv --without-pip /opt/authzledger-venv \
    && python -m pip --python /opt/authzledger-venv/bin/python install \
        --no-cache-dir --no-compile --only-binary=:all: -r /build/requirements.txt
COPY packaging/team/collect_notices.py /build/collect_notices.py
RUN /opt/authzledger-venv/bin/python /build/collect_notices.py /build/notices

FROM ${PYTHON_BASE} AS runtime
LABEL org.opencontainers.image.title="AuthzLedger Team" \
    org.opencontainers.image.url="https://authzledger.com" \
    org.opencontainers.image.source="https://github.com/0xFarag/0xFarag" \
    org.opencontainers.image.version="1.5.0.5" \
    org.opencontainers.image.authors="Nasser Aldin Farag (0xFarag)" \
    org.opencontainers.image.licenses="LicenseRef-AuthzLedger" \
    org.authzledger.copyright="© Nasser Aldin Farag (0xFarag). All rights reserved."
ENV PATH="/opt/authzledger-venv/bin:${PATH}" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/data
WORKDIR /opt/authzledger
COPY --from=dependencies /opt/authzledger-venv /opt/authzledger-venv
COPY --from=dependencies /build/notices /usr/share/doc/authzledger-team/third-party
COPY LICENSE NOTICE.txt packaging/team/README.md packaging/team/THIRD-PARTY.md docs/Team-Login-RBAC.md docs/Key-Rotation.md docs/ZAP-API-Scan-Import.md docs/Proof-Studio-Betrieb.md docs/ZAP-Ergebnisimport.md /usr/share/doc/authzledger-team/
COPY integrations/burp/README.md /usr/share/doc/authzledger-team/Burp-Export.md
COPY integrations/burp-handoff/README.md /usr/share/doc/authzledger-team/Burp-Handoff.md
COPY team/static/fonts/*-OFL.txt /usr/share/doc/authzledger-team/
COPY team/ team/
RUN mkdir -p /data && chown 10001:10001 /data && chmod 0700 /data
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8765
ENTRYPOINT ["python", "-m", "team.server", "--data-dir", "/data"]
CMD ["--host", "127.0.0.1", "--port", "8765"]
