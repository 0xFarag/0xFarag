# © Nasser Aldin Farag (0xFarag). All rights reserved.
FROM python:3.13-slim-trixie AS source-check
WORKDIR /src
COPY authzledger_recipient_verifier.py LICENSE NOTICE.txt ./
RUN echo 'afe47e30606d61f09025fa8b2703d7446b08cc0a3093e4b82eace355bfba5303  authzledger_recipient_verifier.py' | sha256sum --check - \
 && python -I -B authzledger_recipient_verifier.py --help >/dev/null

FROM python:3.13-slim-trixie AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/authzledger
COPY --from=source-check /src/ ./
USER 65534:65534
ENTRYPOINT ["python", "-I", "-B", "/opt/authzledger/authzledger_recipient_verifier.py"]
CMD ["--help"]
