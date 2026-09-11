module github.com/confidential-dot-ai/c8s/test/mock-cds

go 1.26.3

require (
	github.com/confidential-dot-ai/attestation-go v0.7.0
	github.com/confidential-dot-ai/c8s v0.0.0
)

require (
	github.com/google/go-sev-guest v0.15.0 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d // indirect
	github.com/google/logger v1.1.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/confidential-dot-ai/c8s => ../..
