FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

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
USER vhc

ENTRYPOINT ["python", "/app/docker_entrypoint.py"]
CMD ["--demo", "--quiet"]
