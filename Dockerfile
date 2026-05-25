FROM python:3.11-slim AS base

ARG SOPS_VERSION=3.12.1
ARG AGE_VERSION=1.2.1
ARG SOPS_SHA256=cf3136d20a6004405c986a48e179c3c7a731f777fbf105a37bd5dac5c9047100
ARG AGE_SHA256=7df45a6cc87d4da11cc03a539a7470c15b1041ab2b396af088fe9990f7c79d50

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates \
 && curl -fsSL -o /tmp/sops \
      "https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.linux.amd64" \
 && echo "${SOPS_SHA256}  /tmp/sops" | sha256sum -c - \
 && install -m 0755 /tmp/sops /usr/local/bin/sops \
 && rm /tmp/sops \
 && curl -fsSL -o /tmp/age.tgz \
      "https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/age-v${AGE_VERSION}-linux-amd64.tar.gz" \
 && echo "${AGE_SHA256}  /tmp/age.tgz" | sha256sum -c - \
 && tar -xzf /tmp/age.tgz -C /usr/local/bin --strip-components=1 age/age age/age-keygen \
 && chmod 0755 /usr/local/bin/age /usr/local/bin/age-keygen \
 && rm /tmp/age.tgz \
 && apt-get purge -y curl ca-certificates \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask==3.1.* pyyaml==6.0.*

ENV APP_HOME=/app
ENV HOME=${APP_HOME}

RUN useradd -M -u 10001 -d ${APP_HOME} -s /usr/sbin/nologin pxs \
 && mkdir -p ${APP_HOME}/.px-secrets ${APP_HOME}/.config/sops/age \
 && chown -R pxs:pxs ${APP_HOME}

USER pxs
WORKDIR ${APP_HOME}

COPY --chown=pxs:pxs px_secrets.py ${APP_HOME}/px_secrets.py

ENV PX_SECRETS_HOST=0.0.0.0 \
    PX_SECRETS_READ_ONLY=1 \
    PYTHONUNBUFFERED=1

EXPOSE 9999

CMD ["python3", "px_secrets.py", "--headless", "--port", "9999"]
