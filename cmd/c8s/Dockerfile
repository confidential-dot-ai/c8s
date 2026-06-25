FROM gcr.io/distroless/static:nonroot

# The `/c8s` binary path is hardcoded in the chart's c8s-cert startupProbe
# (internal/helmchart/c8s/templates/_helpers.tpl, "c8s.getCertContainers")
# because exec probes bypass the ENTRYPOINT. If you move the COPY target or
# change the ENTRYPOINT, update that probe command too.
COPY build/c8s /c8s

ENTRYPOINT ["/c8s"]
