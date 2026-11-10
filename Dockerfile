FROM aquasec/trivy:0.76.0 AS trivy
FROM ghcr.io/gitleaks/gitleaks:v8.30.1 AS gitleaks
FROM python:3.12-slim-bookworm

# PDF reports: Liberation Serif/Sans stand in for Times New Roman/Arial (same metrics), DejaVu Sans Mono
# is the code font, and Loma adds Thai.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates fonts-liberation fonts-dejavu-core fonts-tlwg-loma-ttf \
    && rm -rf /var/lib/apt/lists/*
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
WORKDIR /opt/app
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip install --no-cache-dir . semgrep==1.183.0 \
    && useradd --create-home --uid 10001 scanner \
    && install -d -o scanner -g scanner /home/scanner/.cache /home/scanner/.cache/trivy /home/scanner/.appsec-triage
ENV APPSEC_CONTAINER=1 TRIVY_CACHE_DIR=/home/scanner/.cache/trivy
USER scanner
RUN trivy --version && semgrep --version && gitleaks version && appsec-triage --help
ENTRYPOINT ["appsec-triage"]
CMD ["ui"]
