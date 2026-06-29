FROM python:3.12-slim

WORKDIR /app

RUN groupadd -r enrichment && useradd -r -g enrichment enrichment

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install cosign for SBOM/signature fetching
RUN curl -sSfL https://github.com/sigstore/cosign/releases/download/v2.2.4/cosign-linux-amd64 \
    -o /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign

# Install kubectl
RUN curl -sSL "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    -o /usr/local/bin/kubectl && chmod +x /usr/local/bin/kubectl

COPY main.py .

RUN chown -R enrichment:enrichment /app
USER enrichment

EXPOSE 8090

CMD ["python3", "main.py"]
