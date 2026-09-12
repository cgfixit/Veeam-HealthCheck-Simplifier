FROM python:3.12-slim

LABEL maintainer="CGFixIT"
LABEL description="Veeam Health Check Simplifier — processes VBR exports into remediation artifacts"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends busybox-static \
    && rm -rf /var/lib/apt/lists/*

# pip<26.2 is CVE-2026-13346 (path traversal from a malicious index).
RUN python -m pip install --no-cache-dir --upgrade "pip>=26.2.0" \
    && pip install --no-cache-dir "pandas>=2.0.0"

COPY vhc_simplifier.py .
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN python -m py_compile vhc_simplifier.py
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

RUN useradd --create-home --shell /bin/bash vhc \
    && mkdir -p /home/vhc/crontabs \
    && chown -R vhc:vhc /home/vhc/crontabs /app
USER vhc

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["--demo", "--quiet"]
