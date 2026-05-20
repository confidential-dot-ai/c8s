FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        ipset \
        iptables \
        libssl3 \
        libtss2-esys-3.0.2-0 \
        libtss2-tctildr0 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app

COPY build/c8s /app/c8s
RUN chmod +x /app/c8s

ENTRYPOINT ["/app/c8s", "ratls-mesh"]
