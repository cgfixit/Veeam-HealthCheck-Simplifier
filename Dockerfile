FROM python:3.15-slim@sha256:94d3426f1def7db4a106a232ac121bfd975393e5dfd40a619b955fae45fe7913

LABEL maintainer="CGFixIT"
LABEL description="Veeam Health Check Simplifier — processes VBR exports into remediation artifacts"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# pip<26.2 is CVE-2026-13346 (path traversal from a malicious index).
RUN python -m pip install --no-cache-dir --upgrade "pip>=26.2.0" \
    && pip install --no-cache-dir "pandas>=2.0.0" "cronsim==2.7" \
    && python -m pip uninstall --yes pip

COPY vhc_simplifier.py docker_entrypoint.py ./

RUN python -m py_compile vhc_simplifier.py docker_entrypoint.py

RUN useradd --create-home --shell /bin/bash vhc \
    && chown -R vhc:vhc /app

# infocmp contains CVE-2025-69720; the application needs neither it nor set-ID tools.
RUN rm -f /usr/bin/infocmp \
    && find / -xdev -type f -perm /6000 -exec chmod a-s {} +
USER vhc

ENTRYPOINT ["python", "/app/docker_entrypoint.py"]
CMD ["--demo", "--quiet"]
