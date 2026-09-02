# Bump: crane digest gcr.io/distroless/static:nonroot
FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

# The `/c8s` binary path is hardcoded in the c8s-cert-wait gate command
# (internal/helmchart/c8s/templates/_helpers.tpl "c8s.getCertContainers" and
# internal/webhook/pod_mutator.go "certWaitContainer") because command bypasses
# the ENTRYPOINT. If you move the COPY target or change the ENTRYPOINT, update
# that command too.
COPY build/c8s /c8s

# Run the named-workload proxy through this alias. Do not run it as
# `/c8s workload-proxy`: CDS excludes only the exact helper commands that the
# webhook injects. It keeps `/c8s workload-proxy` in workload matching, and the
# proxy also rejects that entrypoint. The distinct argv[0] keeps the proxy mode,
# peer name, addresses, and limits inside the exact named-workload policy.
COPY build/c8s /workload-proxy

ENTRYPOINT ["/c8s"]
