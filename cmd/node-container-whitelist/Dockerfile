FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY build/node-container-whitelist /usr/local/bin/node-container-whitelist
RUN chmod +x /usr/local/bin/node-container-whitelist

ENTRYPOINT ["/usr/local/bin/node-container-whitelist"]
