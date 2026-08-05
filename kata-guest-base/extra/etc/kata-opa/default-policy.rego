# c8s kata-agent boot policy — baked into the kata-guest-base guest
# rootfs at /etc/kata-opa/default-policy.rego. This is the file
# kata-agent loads at startup (POLICY_DEFAULT_FILE in upstream
# src/agent/policy/src/policy.rs).
#
# Role in the c8s design:
#
#   The policy gates kata-agent's ttRPC RPCs. It splits the image
#   decision with the in-VM policy-monitor daemon: the rules here bind a
#   CreateContainerRequest to itself — one guest-pull storage, at the
#   container's rootfs, whose source is the digest-pinned reference the
#   annotations carry — and policy-monitor decides whether that digest is
#   allowlisted. regorus has no crypto builtins, so the allowlist half
#   cannot live here. See c8s/docs/kata-image-policy.md.
#
#   It is NOT permissive on the RPCs that let the host reach into a
#   running container (Exec/ReadStream/WriteStream) — those are denied
#   below. CopyFile stays allowed but is scoped to the sandbox seeding
#   directory (see the rule).
#
#   `SetPolicyRequest := false` stops the host replacing this policy over
#   vsock at runtime. The file lives on the dm-verity root, so changing it
#   means rebuilding the guest image and its launch measurement. The
#   init-data `policy.rego` channel would bypass both; the guest build
#   removes it (kata-guest-base/patches/0001-*.patch).
#
# How updates work:
#
#   This policy is FIXED for the lifetime of the guest image. To change
#   it the operator rebuilds the guest image and rolls kata-qemu-snp pods
#   to pick up the new kata-guest-base tag by setting
#   `kata.guestImage.tag` in a values file
#   (`c8s install --cvm-mode=pod -f values.yaml`).

package agent_policy

# regorus defaults to Rego v0, where rule bodies need these. Upstream
# genpolicy's rules.rego carries the same three for the same reason.
import future.keywords.every
import future.keywords.if
import future.keywords.in

default AddARPNeighborsRequest := true
default AddSwapRequest := true
default CloseStdinRequest := true
default DestroySandboxRequest := true
default GetDiagnosticDataRequest := true
default GetMetricsRequest := true
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := true
default ListRoutesRequest := true
default MemHotplugByProbeRequest := true
default OnlineCPUMemRequest := true
default PauseContainerRequest := true
default PullImageRequest := true
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := true
default ResumeContainerRequest := true

# Load-bearing override. See header comment.
default SetPolicyRequest := false

# Host-as-adversary RPCs. policy-monitor gates *which image* runs, but these
# ttRPCs let the host reach *into a running container* over vsock — regardless
# of the image digest — so they are denied at the policy layer too. Nothing in
# the c8s in-guest flow needs them: workloads are driven by kubelet→kata-agent
# CreateContainer, not by host-side exec/stream/copy. This intentionally breaks
# `kubectl exec` into a kata-snp pod — the host node is outside the trust
# boundary, so an in-guest shell/stream/file-copy would be a host-readable side
# channel. Flip one back to `true` only with a one-line note on why it must stay.
default ExecProcessRequest := false
default ReadStreamRequest := false
default WriteStreamRequest := false

default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := true
default StatsContainerRequest := true
default StopTracingRequest := true
default TtyWinResizeRequest := true
default UpdateContainerRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default WaitProcessRequest := true

# --- Container rootfs binding ------------------------------------------
#
# policy-monitor admits a container on the digest in the
# io.kubernetes.cri.image-name annotation; kata pulls the guest-pull
# storage's `source`. Both are host-written fields of the same request, so
# the rules below require them to be the same digest-pinned reference, and
# require that reference to be what actually becomes the rootfs. Evaluated
# before do_create_container, so a violation is PERMISSION_DENIED: no pull,
# no bundle, no init process.
#
# print() calls are how a denial is diagnosed — kata-agent gathers them
# into the PERMISSION_DENIED message the operator sees.

default CreateContainerRequest := false

CreateContainerRequest if {
	print("CreateContainerRequest: start")

	# policy-monitor and rtmr3-measurer only watch ids matching this; kata's
	# own verify_id is wider (dots, underscores, Unicode), and an id outside
	# their filter is a container neither of them ever decides on.
	regex.match("^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$", input.container_id)
	not reserved_bundle_name
	print("CreateContainerRequest: container_id ok")

	# The Go runtime never sets this; setup_shared_mounts bind-mounts a
	# sibling container's path in after the container has started.
	count(input.shared_mounts) == 0
	print("CreateContainerRequest: no shared_mounts")

	pull := sole_guest_pull_storage
	print("CreateContainerRequest: one image_guest_pull storage")

	# add_storages skips a handler whose mount point is already registered
	# sandbox-wide, and setup_bundle bind-mounts the host's spec.root.path
	# when nothing is mounted at the rootfs. Pinning the mount point to this
	# container's own rootfs is what makes the pull actually happen.
	pull.mount_point == container_rootfs
	print("CreateContainerRequest: guest pull is the rootfs")

	every s in input.storages {
		storage_outside_rootfs(s)
		not layered_rootfs_storage(s)
	}
	print("CreateContainerRequest: no storage shadows the rootfs")

	pull_source_bound(pull)
	print("CreateContainerRequest: allowed")
}

container_rootfs := concat("/", ["/run/kata-containers", input.container_id, "rootfs"])

# kata's own subdirectories of /run/kata-containers. A container taking one of
# these names collides with them, and the c8s watchers skip them by name.
reserved_bundle_name if {
	some name in ["shared", "sandbox", "image"]
	input.container_id == name
}

sole_guest_pull_storage := s if {
	pulls := [x | some x in input.storages; x.driver == "image_guest_pull"]
	count(pulls) == 1
	s := pulls[0]
}

# Anything mounted at or under the rootfs replaces part of the pulled image.
storage_outside_rootfs(s) if {
	s.driver == "image_guest_pull"
}

storage_outside_rootfs(s) if {
	s.mount_point != container_rootfs
	not startswith(s.mount_point, concat("", [container_rootfs, "/"]))
}

# The multi-layer EROFS path is dispatched on a mount option before the driver
# is looked at, and assembles a rootfs out of host block devices. c8s guests
# are guest-pull only.
layered_rootfs_storage(s) if {
	s.driver == "erofs.multi-layer"
}

layered_rootfs_storage(s) if {
	some o in s.options
	startswith(o, "X-kata.multi-layer")
}

layered_rootfs_storage(s) if {
	some o in s.options
	startswith(o, "X-kata.overlay-")
}

# kata's own switch is io.katacontainers.pkg.oci.container_type; the guest-pull
# handler's is the container-type copied into the storage's driver_options
# metadata; policy-monitor's is the CRI annotation. A container runs what all
# three agree on, or it does not run.
pull_source_bound(pull) if {
	sandbox_annotations
	sandbox_pull_metadata(pull)
	pull.source == "pause"
	print("pull_source_bound: sandbox, measured /pause_bundle")
}

pull_source_bound(pull) if {
	workload_annotations
	not sandbox_pull_metadata(pull)
	pull.source == input.OCI.Annotations["io.kubernetes.cri.image-name"]
	regex.match("^[^@]+@sha256:[0-9a-f]{64}$", pull.source)
	print("pull_source_bound: workload, digest-pinned")
}

sandbox_annotations if {
	input.OCI.Annotations["io.katacontainers.pkg.oci.container_type"] == "pod_sandbox"
	input.OCI.Annotations["io.kubernetes.cri.container-type"] == "sandbox"
}

workload_annotations if {
	input.OCI.Annotations["io.katacontainers.pkg.oci.container_type"] == "pod_container"
	input.OCI.Annotations["io.kubernetes.cri.container-type"] == "container"
}

# The runtime merges every container annotation into ImagePull.Metadata, so an
# honest sandbox carries the marker verbatim in the serialised options.
sandbox_pull_metadata(pull) if {
	some opt in pull.driver_options
	startswith(opt, "image_guest_pull=")
	contains(opt, "\"io.kubernetes.cri.container-type\":\"sandbox\"")
}

# --- Sandbox and ephemeral storages ------------------------------------
#
# Sandbox storages are refcounted by mount point across the whole sandbox, and
# a later container storage at an already-registered path is skipped rather
# than handled. One pre-registered at a container's rootfs therefore suppresses
# that container's image pull. kata's own sandbox storages live under
# /run/kata-containers/{shared,sandbox}/.

default CreateSandboxRequest := false

CreateSandboxRequest if {
	every s in input.storages {
		not container_rootfs_shaped(s.mount_point)
	}
	print("CreateSandboxRequest: allowed")
}

default UpdateEphemeralMountsRequest := false

UpdateEphemeralMountsRequest if {
	every s in input.storages {
		not container_rootfs_shaped(s.mount_point)
	}
	print("UpdateEphemeralMountsRequest: allowed")
}

container_rootfs_shaped(mount_point) if {
	regex.match("^/run/kata-containers/[^/]+/rootfs(/.*)?$", mount_point)
}

# --- CopyFile ----------------------------------------------------------
#
# With shared_fs="none" there is no virtio-fs share, so the runtime seeds the
# sandbox over CopyFile: resolv.conf, hostname, /etc/hosts, the serviceaccount
# token, and every configmap/secret/projected mount. Every destination the
# runtime writes is under kataGuestSharedDir(); the container rootfs is not, and
# writing there after the pull would replace the image that was admitted.
#
# The `..` check is on path components: projected volumes legitimately use
# `..data` and `..<timestamp>` names, and the agent's own prefix check compares
# components without resolving traversal.

default CopyFileRequest := false

CopyFileRequest if {
	startswith(input.path, "/run/kata-containers/shared/containers/")
	not regex.match(`(^|/)\.\.(/|$)`, input.path)
	print("CopyFileRequest: allowed")
}
