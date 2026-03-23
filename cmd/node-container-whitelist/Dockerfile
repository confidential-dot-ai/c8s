FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        libtss2-esys-3.0.2-0 \
        libtss2-tctildr0 \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY build/node-container-whitelist /usr/local/bin/node-container-whitelist
COPY build/attest-sev-snp /usr/local/bin/attest-sev-snp
RUN chmod +x /usr/local/bin/node-container-whitelist /usr/local/bin/attest-sev-snp

ENTRYPOINT ["/usr/local/bin/node-container-whitelist"]
