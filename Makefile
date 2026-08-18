.PHONY: build install build-c8s build-c8s-node build-get-cert build-ratls-mesh \
       build-nri-image-policy build-policy-monitor build-rtmr3-measurer build-volumed \
       test test-integration test-node-guest-image-role test-node-guest-image-role-systemd test-node-guest-image-cloud-init test-e2e-cw-label-policy test-e2e-mesh-cw-enforcement test-e2e-ca-handoff mutation-check mutation-full vet fmt lint clean \
       manifests generate check-crd-chart install-controller-gen require-controller-gen \
       policy-test print-opa-version

OPA                ?= opa
OPA_VERSION        ?= v1.9.0
KATA_POLICY        ?= kata-guest-base/extra/etc/kata-opa/default-policy.rego
KATA_POLICY_TESTS  ?= kata-guest-base/tests/default-policy_test.rego

CONTROLLER_GEN         ?= controller-gen
CONTROLLER_GEN_VERSION ?= v0.20.1

# CRD YAMLs land in the helm chart's crds/ folder — the install vector.
CRD_OUT_DIR    ?= ./internal/helmchart/c8s/crds

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DIR  = ./build
MODULE     = github.com/confidential-dot-ai/c8s

LDFLAGS = -s -w -X $(MODULE)/internal/version.Version=$(VERSION)

# --- All binaries ---

build: build-c8s

# Build the c8s CLI and install it onto PATH via `go install`. The day-2 CLI
# (install, attest, ops) is meant to run on an operator's machine, so it lands
# in GOBIN (else GOPATH/bin) rather than ./build.
install:
	go install -ldflags="$(LDFLAGS)" ./cmd/c8s
	@bindir="$$(go env GOBIN)"; [ -n "$$bindir" ] || bindir="$$(go env GOPATH)/bin"; \
		echo "Installed c8s to $$bindir/c8s"

# --- c8s multi-mode binary (the canonical artifact each per-role image
# COPYs in). Per-role Dockerfiles set ENTRYPOINT ["/c8s", "<name>"].

build-c8s:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 \
		go build -ldflags="$(LDFLAGS)" \
		-o $(BUILD_DIR)/c8s ./cmd/c8s
	@echo "Built $(BUILD_DIR)/c8s"

# Slim variant for node-side images (nri-image-policy, ratls-mesh, get-cert):
# omits 'operator' and 'install' subcommands so the
# binary doesn't pull controller-runtime or the embedded helm chart.
build-c8s-node:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -tags c8s_node \
		-ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/c8s-node ./cmd/c8s
	@echo "Built $(BUILD_DIR)/c8s-node"

# --- Policy-monitor (in-kata-guest image-digest enforcer) ---
# Standalone binary baked into kata-guest-base. It watches kata-agent's
# container bundles and SIGKILLs any container whose image digest isn't
# on the allowlist baked into the dm-verity guest rootfs. Static build
# with the same flags as the other in-guest binaries so the kata-guest
# osbuilder can copy it into the rootfs.
build-policy-monitor:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/policy-monitor ./cmd/policy-monitor
	@echo "Built $(BUILD_DIR)/policy-monitor"

# --- Volumed (in-kata-guest encrypted-volume opener) ---
# Standalone binary baked into kata-guest-base, run as `volumed --guest`. The
# node-side DaemonSet runs `c8s volumed` from the multi-mode binary instead;
# the guest gets its own so only this command sits on the dm-verity root.
build-volumed:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/volumed ./cmd/volumed
	@echo "Built $(BUILD_DIR)/volumed"

# --- RTMR3-measurer (in-kata-guest per-workload RTMR[3] measurer) ---
# Standalone daemon baked into kata-guest-base. Scans kata-agent's container
# bundles and extends TDX RTMR[3] with each deployed workload's image digest,
# binding the workload into the guest's attestation quote (measurement-only;
# independent of policy-monitor's allowlist). Requires a guest kernel with the
# TDX RTMR-extend sysfs (mainline >= 6.16). Static build like the other in-guest
# binaries so osbuilder can copy it into the rootfs.
build-rtmr3-measurer:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/rtmr3-measurer ./cmd/rtmr3-measurer
	@echo "Built $(BUILD_DIR)/rtmr3-measurer"

# --- Get-Cert ---

build-get-cert:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/get-cert ./cmd/get-cert
	@echo "Built $(BUILD_DIR)/get-cert"

# --- RA-TLS Mesh ---

build-ratls-mesh:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/ratls-mesh ./cmd/ratls-mesh
	@echo "Built $(BUILD_DIR)/ratls-mesh"

# --- NRI Image Policy ---

build-nri-image-policy:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/nri-image-policy ./cmd/nri-image-policy
	@echo "Built $(BUILD_DIR)/nri-image-policy"

# --- Tests ---

# C8S_TEST_COUNT= lets CI use Go's content-addressed test cache; the local
# default keeps forced reruns.
C8S_TEST_COUNT ?= -count=1
test:
	go test -race $(C8S_TEST_COUNT) -timeout=120s ./...

test-integration:
	./test/integration/run.sh

# The byte-exact rke2-role.sh against real ISO9660 loop devices. Root (loop
# mounts, writes /run/confos) — sudo on a disposable box.
test-node-guest-image-role:
	./node-guest-image/tests/rke2-role-test.sh

# Role-gated unit wiring under real systemd in a privileged container.
# Needs only docker.
test-node-guest-image-role-systemd:
	./node-guest-image/tests/rke2-role-systemd-test.sh

# The cloud-init datasource pin against the distro's real DataSourceNoCloud:
# a host cidata disk or cmdline seed redirect must lose to the baked seed.
# Needs the distro cloud-init package; no root.
test-node-guest-image-cloud-init:
	python3 ./node-guest-image/tests/cloud-init-datasource-test.py

# Advisory mutation testing of code changed vs BASE (default origin/main).
mutation-check:
	./scripts/mutation-check.sh run "$${BASE:-origin/main}"
	./scripts/mutation-check.sh summary

# Mutation-test every covered mutant in the module (slow; linux only).
mutation-full:
	./scripts/mutation-check.sh full
	./scripts/mutation-check.sh summary

# Live-cluster check of the cw-label integrity admission policy. Needs
# kubectl pointed at a cluster with the c8s chart installed. Also runs
# post-merge in the snp-metal-e2e lane's in-guest payload.
test-e2e-cw-label-policy:
	./test/e2e/cw-label-policy.sh

# Live-cluster check that the workload path is mesh-wrapped and plaintext
# bypasses to cw pods fail closed. Needs kubectl pointed at a cluster with
# the c8s chart installed and a Running confidential workload. Not CI-wired:
# snp-metal's guest kernel lacks ratls-mesh's netfilter matches (the lane
# installs ratlsMesh.enabled=false) and tdx-metal's vendored lane runs Cilium
# kube-proxy-free, so VIP traffic never hits the FORWARD guard this asserts.
test-e2e-mesh-cw-enforcement:
	./test/e2e/mesh-cw-enforcement.sh

# Live-cluster check that attested CA handoff works end to end: an attested
# probe pulls the mesh CA over /handoff and proves it is the live trust root.
# Needs kubectl pointed at a node-as-CVM cluster with cds.handoff.enabled=true.
# Also runs post-merge in the snp-metal-e2e lane's in-guest payload.
test-e2e-ca-handoff:
	./test/e2e/ca-handoff.sh

# Parse + decision tests for the baked kata-agent policy. The guest evaluates
# it with regorus, which reads Rego v0 plus the future keywords, so the checks
# run with --v0-compatible. The fmt gate keeps the policy's layout normalised
# for the Go lockstep tests that read its text. Install with:
#   curl -fsSL -o opa https://openpolicyagent.org/downloads/$(OPA_VERSION)/opa_linux_amd64_static && chmod +x opa
# Single source of the pinned version for CI's installer step.
print-opa-version:
	@echo $(OPA_VERSION)

policy-test:
	@command -v $(OPA) >/dev/null 2>&1 || { echo "opa not found; see the policy-test comment in the Makefile"; exit 1; }
	$(OPA) fmt --v0-compatible --diff --fail $(KATA_POLICY) $(KATA_POLICY_TESTS)
	$(OPA) check --v0-compatible --strict $(KATA_POLICY)
	$(OPA) test --v0-compatible $(KATA_POLICY) $(KATA_POLICY_TESTS)

# --- Linting ---

vet:
	go vet ./...

# gofmt over tracked Go files only — scanning `.` recurses into the gitignored
# kata-guest-base/.build/ (fetched kata source + a root-owned rootfs tree) and
# fails on permission-denied.
fmt:
	@test -z "$$(git ls-files '*.go' | xargs gofmt -l)" || (echo "files need formatting:"; git ls-files '*.go' | xargs gofmt -l; exit 1)

lint: fmt vet

# --- CRD generation ---

install-controller-gen:
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

require-controller-gen:
	@command -v $(CONTROLLER_GEN) >/dev/null 2>&1 || { \
		echo "controller-gen not found. Install with:"; \
		echo "  go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)"; \
		exit 1; \
	}

manifests: require-controller-gen
	@mkdir -p $(CRD_OUT_DIR)
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:dir=$(CRD_OUT_DIR)

check-crd-chart: require-controller-gen
	@set -eu; \
	tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:dir="$$tmp"; \
	diff -ruN "$(CRD_OUT_DIR)" "$$tmp"

generate: require-controller-gen
	$(CONTROLLER_GEN) object paths=./api/...

# --- Cleanup ---

clean:
	rm -rf $(BUILD_DIR)
