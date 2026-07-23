# luks-open runs `c8s luks-open`, which shells out to cryptsetup + mkfs.<fs> +
# mount — none of which the distroless operator image carries. This image exists
# solely to provide them, keeping the operator (and the injected get-cert
# containers, which share the operator image) on distroless. It is injected only
# into pods requesting confidential.ai/luks-<name> volumes — see
# internal/webhook/luks.go.
FROM debian:bookworm-slim

# cryptsetup: LUKS format/open. util-linux: mount(8), blkid, losetup.
# e2fsprogs / xfsprogs: mkfs.ext4 / mkfs.xfs for the format-if-empty path.
# ca-certificates: TLS from any c8s subcommand.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       cryptsetup \
       util-linux \
       e2fsprogs \
       xfsprogs \
       ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# luks-open runs privileged as root (raw block device + cryptsetup ioctls; see
# internal/webhook/luks.go), so no nonroot user is baked in. The bare `/c8s`
# entrypoint mirrors the operator image: the webhook passes `luks-open` as the
# first arg, the same contract get-cert injection uses.
COPY build/c8s /c8s

ENTRYPOINT ["/c8s"]
