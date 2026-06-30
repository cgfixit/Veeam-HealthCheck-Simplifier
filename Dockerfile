FROM python:3.13-slim

LABEL maintainer="CGFixIT"
LABEL description="Veeam Health Check Simplifier — processes VBR exports into remediation artifacts"

WORKDIR /app

RUN pip install --no-cache-dir "pandas>=2.0.0"

COPY vhc_simplifier.py .

RUN python -m py_compile vhc_simplifier.py

RUN useradd --create-home --shell /bin/bash vhc
USER vhc

ENTRYPOINT ["python", "vhc_simplifier.py"]
CMD ["--demo", "--quiet"]
