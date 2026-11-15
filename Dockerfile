FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

LABEL maintainer="CGFixIT"
LABEL description="Veeam Health Check Simplifier — processes VBR exports into remediation artifacts"
LABEL org.opencontainers.image.source="https://github.com/cgfixit/Veeam-HealthCheck-Simplifier"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Pull Debian security fixes newer than the base digest (apt CVE-2026-109518, libsqlite3, etc.).
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml constraints.txt README.md LICENSE.md vhc_simplifier.py /tmp/src/

# Install the package itself with the same pins as CI and the release (constraints.txt).
# pip<26.2 is CVE-2026-13346 (path traversal from a malicious index).
# Behind TLS inspection, pass the proxy CA without baking it into a layer:
#   docker build --secret id=pip_ca,src=corp-ca.pem .
RUN --mount=type=secret,id=pip_ca,required=false \
    if [ -s /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi \
    && python -m pip install --no-cache-dir --upgrade "pip>=26.2.0" \
    && python -m pip install --no-cache-dir \
        --constraint /tmp/src/constraints.txt --build-constraint /tmp/src/constraints.txt \
        "/tmp/src[container]" \
    && python -m pip uninstall --yes pip \
    && rm -rf /tmp/src

COPY docker_entrypoint.py ./

RUN python -m py_compile docker_entrypoint.py \
    && useradd --create-home --shell /bin/bash vhc \
    && install -d -o vhc -g vhc /app/output

# infocmp contains CVE-2025-69720; the application needs neither it nor set-ID tools.
RUN rm -f /usr/bin/infocmp \
    && find / -xdev -type f -perm /6000 -exec chmod a-s {} +
USER vhc

ENTRYPOINT ["python", "/app/docker_entrypoint.py"]
CMD ["--demo", "--quiet", "--output-dir", "/app/output"]
