# Bump: crane digest golang:1.26
FROM golang:1.27@sha256:512690a5660563b57d37ecc31129e7f136e831db2aed24a1dbeb8ad7380dc0fa AS builder

WORKDIR /src
# Repo-root build context (the module replaces c8s => ../..); #13's .dockerignore must keep these paths.
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY test/mock-attestation/ ./test/mock-attestation/
RUN CGO_ENABLED=0 go build -C test/mock-attestation -ldflags="-s -w" -o /mock-attestation .

# Bump: crane digest gcr.io/distroless/static-debian12:latest
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=builder /mock-attestation /mock-attestation
ENTRYPOINT ["/mock-attestation"]
