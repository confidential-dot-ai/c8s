# Bump: crane digest gcr.io/distroless/static:nonroot
FROM gcr.io/distroless/static:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

# The `/c8s` binary path is hardcoded in the c8s-cert-wait gate command
# (internal/helmchart/c8s/templates/_helpers.tpl "c8s.getCertContainers" and
# internal/webhook/pod_mutator.go "certWaitContainer") because command bypasses
# the ENTRYPOINT. If you move the COPY target or change the ENTRYPOINT, update
# that command too.
COPY build/c8s /c8s

ENTRYPOINT ["/c8s"]
