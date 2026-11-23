FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/data
WORKDIR /opt/authzledger
COPY team/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --only-binary=:all: -r /tmp/requirements.txt && rm /tmp/requirements.txt && mkdir -p /data && chown 10001:10001 /data && chmod 0700 /data
COPY team/ team/
COPY LICENSE NOTICE.txt ./
COPY packaging/team/THIRD-PARTY.md /usr/share/doc/authzledger-team/THIRD-PARTY.md
COPY packaging/team/collect_notices.py /tmp/collect_team_notices.py
RUN cp LICENSE NOTICE.txt /usr/share/doc/authzledger-team/ && python /tmp/collect_team_notices.py /usr/share/doc/authzledger-team/third-party && rm /tmp/collect_team_notices.py
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8765
ENTRYPOINT ["python", "-m", "team.server", "--data-dir", "/data"]
CMD ["--host", "127.0.0.1", "--port", "8765"]
