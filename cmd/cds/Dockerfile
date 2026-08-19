# Bump: crane digest gcr.io/distroless/static-debian12:latest
FROM gcr.io/distroless/static-debian12:latest@sha256:6447365a6337c3732f412d1b74357b30a633831955b2bc45552b0086be907687

COPY build/c8s /c8s

ENTRYPOINT ["/c8s", "cds"]
