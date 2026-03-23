FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        iptables \
        libssl3 \
        libtss2-esys-3.0.2-0 \
        libtss2-tctildr0 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app /opt/lunal-services

COPY build/ratls-mesh /app/ratls-mesh
COPY build/attest-sev-snp /opt/lunal-services/attest-sev-snp
RUN chmod +x /app/ratls-mesh /opt/lunal-services/attest-sev-snp

ENTRYPOINT ["/app/ratls-mesh"]
