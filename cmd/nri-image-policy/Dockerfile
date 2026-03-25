FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/nri/conf.d /var/log/nri-image-policy /var/run/nri

COPY build/nri-image-policy /usr/local/bin/nri-image-policy
COPY cmd/nri-image-policy/enable-nri.sh /usr/local/bin/enable-nri.sh
RUN chmod +x /usr/local/bin/nri-image-policy /usr/local/bin/enable-nri.sh

ENTRYPOINT ["/usr/local/bin/nri-image-policy"]
CMD ["--config", "/etc/nri/conf.d/image-policy.yaml"]
