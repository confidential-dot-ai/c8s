# Bump: crane digest debian:bookworm-slim
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

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
