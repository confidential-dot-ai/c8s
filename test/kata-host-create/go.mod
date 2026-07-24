module github.com/confidential-dot-ai/c8s/test/kata-host-create

go 1.25.11

// The kata runtime bindings are not published as a Go module. Point this at
// a local kata-containers checkout before building:
//
//	go mod edit -replace github.com/kata-containers/kata-containers/src/runtime=/path/to/kata-containers/src/runtime
//
// (the replace is intentionally not committed: it is machine-local)
require (
	github.com/containerd/ttrpc v1.2.9
	github.com/kata-containers/kata-containers/src/runtime v0.0.0-00010101000000-000000000000
	github.com/mdlayher/vsock v1.3.0
	github.com/opencontainers/runtime-spec v1.3.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/containerd/log v0.1.0 // indirect
	github.com/mdlayher/socket v0.6.0 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/grpc v1.81.1 // indirect
)
