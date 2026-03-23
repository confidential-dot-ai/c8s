FROM gcr.io/distroless/static:nonroot

COPY build/cert-rotator /cert-rotator
COPY build/attest-sev-snp /attest-sev-snp
COPY build/attest-tdx /attest-tdx

ENTRYPOINT ["/cert-rotator"]
