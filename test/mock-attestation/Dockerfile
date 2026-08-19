# Bump: crane digest golang:1.26
FROM golang:1.26@sha256:45a5f7a810238aabcbad211d70b9ae082022d96f7c7259e94041ad1b933575ac AS builder

WORKDIR /src
# Repo-root build context (the module replaces c8s => ../..); #13's .dockerignore must keep these paths.
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY test/mock-attestation/ ./test/mock-attestation/
RUN CGO_ENABLED=0 go build -C test/mock-attestation -ldflags="-s -w" -o /mock-attestation .

# Bump: crane digest gcr.io/distroless/static-debian12:latest
FROM gcr.io/distroless/static-debian12:latest@sha256:6447365a6337c3732f412d1b74357b30a633831955b2bc45552b0086be907687
COPY --from=builder /mock-attestation /mock-attestation
ENTRYPOINT ["/mock-attestation"]
