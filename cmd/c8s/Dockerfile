# Bump: crane digest gcr.io/distroless/static:nonroot
FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

# The `/c8s` binary path is hardcoded in the c8s-cert-wait gate command
# (internal/helmchart/lib/templates/_helpers.tpl "c8s-lib.getCertContainers"
# and internal/webhook/pod_mutator.go "certWaitContainer") because command
# bypasses the ENTRYPOINT. If you move the COPY target or change the
# ENTRYPOINT, update that command too.
COPY build/c8s /c8s

ENTRYPOINT ["/c8s"]
