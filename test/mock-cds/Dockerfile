FROM golang:1.26 AS builder

WORKDIR /src
# Repo-root build context (the module replaces c8s => ../..); #13's .dockerignore must keep these paths.
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY test/mock-cds/ ./test/mock-cds/
RUN CGO_ENABLED=0 go build -C test/mock-cds -ldflags="-s -w" -o /mock-cds .

FROM gcr.io/distroless/static-debian12
COPY --from=builder /mock-cds /mock-cds
ENTRYPOINT ["/mock-cds"]
