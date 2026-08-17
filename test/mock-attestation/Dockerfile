FROM golang:1.26 AS builder

WORKDIR /src
# Repo-root build context (the module replaces c8s => ../..); #13's .dockerignore must keep these paths.
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY test/mock-attestation/ ./test/mock-attestation/
RUN CGO_ENABLED=0 go build -C test/mock-attestation -ldflags="-s -w" -o /mock-attestation .

FROM gcr.io/distroless/static-debian12
COPY --from=builder /mock-attestation /mock-attestation
ENTRYPOINT ["/mock-attestation"]
