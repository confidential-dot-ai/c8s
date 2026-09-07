# Bump: crane digest debian:bookworm-slim
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/nri/conf.d /var/log/nri-image-policy /var/run/nri

COPY build/c8s /usr/local/bin/c8s
COPY cmd/nri-image-policy/enable-nri.sh /usr/local/bin/enable-nri.sh
# The c8s chart, so node-guest-image/c8s/mkosi.sync can stage it into the
# node image's HelmChart AddOn without a separate chart-fetch step: this
# image is already extracted at build time for the plugin binary (see
# mkosi.sync "3. nri-image-policy plugin binary"), so the chart rides the
# same C8S_REF-pinned artifact.
COPY internal/helmchart/c8s /usr/share/c8s/chart
RUN chmod +x /usr/local/bin/c8s /usr/local/bin/enable-nri.sh \
    && ln -s /usr/local/bin/c8s /usr/local/bin/nri-image-policy

ENTRYPOINT ["/usr/local/bin/c8s", "nri-image-policy"]
CMD ["--config", "/etc/nri/conf.d/image-policy.yaml"]
