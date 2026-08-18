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

# Swap never leaves TEE memory.
default AddSwapRequest := false

default CloseStdinRequest := true

default DestroySandboxRequest := true

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

# The only in-stack producer is kata's VM-factory template path, which an
# image= boot cannot enable; the guest CRNG seeds from the in-TEE CPU RNG.
default ReseedRandomDevRequest := false

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

# The termination-log branch reads the guest file behind the OCI mount whose
# destination equals the terminationMessagePath annotation, and returns 4 KiB of
# it over vsock. Both fields are host-written, so this reads any guest path a
# mount may name — the injected certs and secrets tmpfs included.
default GetDiagnosticDataRequest := false

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

	# A container id is the CRI's 32 random bytes, hex-encoded.
	regex.match("^[a-f0-9]{64}$", input.container_id)
	print("CreateContainerRequest: container_id ok")

	# The Go runtime never sets this; setup_shared_mounts bind-mounts a
	# sibling container's path in after the container has started.
	count(input.shared_mounts) == 0
	print("CreateContainerRequest: no shared_mounts")

	# containerd is the only CRI in this shape and never sets the CRI-O key.
	not input.OCI.Annotations["io.kubernetes.cri-o.ContainerType"]
	print("CreateContainerRequest: no foreign container-type marker")

	no_spec_hooks
	print("CreateContainerRequest: no spec hooks")

	pull := sole_guest_pull_storage
	print("CreateContainerRequest: one image_guest_pull storage")

	not crio_pull_metadata(pull)
	print("CreateContainerRequest: no foreign marker in the pull metadata")

	# add_storages skips a handler whose mount point is already registered
	# sandbox-wide, and setup_bundle bind-mounts the host's spec.root.path
	# when nothing is mounted at the rootfs. Pinning the mount point to this
	# container's own rootfs is what makes the pull actually happen.
	pull.mount_point == container_rootfs
	print("CreateContainerRequest: guest pull is the rootfs")

	every s in input.storages {
		storage_outside_rootfs(s)
		not layered_rootfs_storage(s)
		container_storage_allowed(s)
	}
	print("CreateContainerRequest: every storage is the guest pull or guest-local scratch")

	every m in input.OCI.Mounts {
		mount_source_allowed(m)
	}
	print("CreateContainerRequest: no mount reaches outside the sandbox dirs")

	pull_source_bound(pull)
	print("CreateContainerRequest: allowed")
}

# Prestart and CreateContainer hooks execute as guest root during
# do_create_container, ahead of the admission verdict — prestart in the
# agent's own namespaces. The remaining lists run after the verdict, with
# the admitted container (CreateRuntime has no execution site in the
# agent). The runtime clears Hooks before it sends the spec, so the
# serializer emits null and that is the only shape an honest request
# carries; every other shape is host-smuggled. Same guard as upstream
# genpolicy's allow_create_container_input.
no_spec_hooks if {
	is_null(input.OCI.Hooks)
}

container_rootfs := concat("/", ["/run/kata-containers", input.container_id, "rootfs"])

sole_guest_pull_storage := s if {
	pulls := [x | some x in input.storages; x.driver == "image_guest_pull"]
	count(pulls) == 1
	s := pulls[0]
}

# Anything mounted at or under the rootfs replaces part of the pulled image.
# Unreachable while container_storage_allowed holds every mount point to the
# runtime trees and the id shape keeps `shared` and `sandbox` out of a rootfs
# path; kept so widening either cannot silently uncover the rootfs.
storage_outside_rootfs(s) if {
	s.driver == "image_guest_pull"
}

storage_outside_rootfs(s) if {
	s.mount_point != container_rootfs
	not startswith(s.mount_point, concat("", [container_rootfs, "/"]))
}

# The multi-layer EROFS path assembles a rootfs out of host block devices, and
# is_multi_layer_storage dispatches on the options before the driver is looked
# at — so the option forms below are the live guard. c8s guests are guest-pull
# only. The driver form is unreachable while container_storage_allowed pins the
# driver; kept so widening that rule cannot silently uncover this path.
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

# A container's storages are the guest pull — its rootfs, whose source
# pull_source_bound binds — and scratch the guest builds for itself.
container_storage_allowed(s) if {
	s.driver == "image_guest_pull"
	print("storage: guest pull", s.mount_point)
}

container_storage_allowed(s) if {
	guest_local_storage(s)
	storage_mount_point_allowed(s)
}

container_storage_allowed(s) if {
	encrypted_block_storage(s)
	storage_mount_point_allowed(s)
}

# The driver selects the handler and the handler decides what the storage is
# made of, so the driver is pinned: the ephemeral handler mounts the filesystem
# `fstype` names, which is pinned with it.
guest_local_storage(s) if {
	s.driver == "ephemeral"
	s.fstype == "tmpfs"
	print("storage: guest tmpfs", s.mount_point)
}

# A default-medium emptyDir under emptydir_mode="block-encrypted". The marker
# routes the device to CDH, which LUKS2-formats it under a key the guest
# generates. An absolute source is the `/dev` form block_handler resolves
# directly, and this branch formats what it resolves, so the source is held to
# the relative forms the runtime writes — a PCI path, a devno, a SCSI address.
#
# Reached only from container_storage_allowed: a sandbox storage names a
# filesystem, never a device.
encrypted_block_storage(s) if {
	some driver in ["blk", "blk-ccw", "scsi"]
	s.driver == driver
	not startswith(s.source, "/")
	some opt in s.driver_options
	opt == "encryption_key=ephemeral"
	print("storage: CDH-encrypted block device", s.mount_point)
}

storage_mount_point_allowed(s) if {
	in_runtime_tree(s.mount_point)
	print("storage: mount point in a runtime tree", s.mount_point)
}

# The trees the runtime manages: the CopyFile-seeded share, and the sandbox's
# ephemeral/local/storage dirs. A plain component has to follow the prefix — the
# prefix alone is the tree, and a leading `.` or `/` component resolves back to
# it.
in_runtime_tree(path) if {
	some prefix in ["/run/kata-containers/shared/containers/", "/run/kata-containers/sandbox/"]
	startswith(path, prefix)
	regex.match(`^[^/.]`, trim_prefix(path, prefix))
	no_traversal(path)
}

# A bind mount's source is a guest path, and the runtime rewrites every one it
# sends to a directory it manages: the CopyFile-seeded share, or the sandbox's
# ephemeral/local/storage trees. Anything else — the verity root, /run/c8s,
# another container's rootfs — is guest state the host is asking to hand a
# container. A non-bind mount names its filesystem instead of a path; the
# pseudo-filesystems below carry nothing in.
#
# This bounds where mount CONTENT comes from, not where it lands: a destination
# is a path inside the container, and which paths a workload may have shadowed
# is per-image knowledge that lives in the allowlist document, not here.
mount_source_allowed(m) if {
	some fstype in ["cgroup", "cgroup2", "devpts", "mqueue", "proc", "sysfs", "tmpfs"]
	m.type_ == fstype
	not startswith(m.source, "/")
	not bind_mount(m)
}

mount_source_allowed(m) if {
	bind_mount(m)
	in_runtime_tree(m.source)
}

no_traversal(path) if {
	not regex.match(`(^|/)\.\.(/|$)`, path)
}

# rustjail resolves a bind source against the bundle directory, and the kernel
# binds whenever MS_BIND is set — a bind/rbind option marks a bind regardless
# of the declared type.
bind_mount(m) if {
	m.type_ == "bind"
}

bind_mount(m) if {
	some o in m.options
	o == "bind"
}

bind_mount(m) if {
	some o in m.options
	o == "rbind"
}

# kata's own switch is io.katacontainers.pkg.oci.container_type; the guest-pull
# handler's is the container-type copied into the storage's driver_options
# metadata; policy-monitor's is this same sandbox_annotations pair (a Go
# lockstep test machine-compares them). A container runs what all three agree
# on, or it does not run.
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

# containerd never writes the CRI-O key, so an honest request cannot carry it
# in the serialised pull metadata either. The key is checked after decoding,
# the way the guest-pull handler reads it: a text match would miss a
# JSON-escaped key.
crio_pull_metadata(pull) if {
	some opt in pull.driver_options
	startswith(opt, "image_guest_pull=")
	metadata := json.unmarshal(trim_prefix(opt, "image_guest_pull="))
	metadata["io.kubernetes.cri-o.ContainerType"]
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
	# add_hooks arms every container with executables from this guest directory
	count(input.guest_hook_path) == 0

	# load_kernel_modules runs modprobe as guest root with host-chosen argv
	count(input.kernel_modules) == 0

	every s in input.storages {
		not container_rootfs_shaped(s.mount_point)
		not layered_rootfs_storage(s)
		sandbox_storage_source_allowed(s)
		guest_local_storage(s)
		storage_mount_point_allowed(s)
	}
	print("CreateSandboxRequest: allowed")
}

default UpdateEphemeralMountsRequest := false

UpdateEphemeralMountsRequest if {
	every s in input.storages {
		not container_rootfs_shaped(s.mount_point)
		not layered_rootfs_storage(s)
		sandbox_storage_source_allowed(s)
		guest_local_storage(s)
		storage_mount_point_allowed(s)
	}
	print("UpdateEphemeralMountsRequest: allowed")
}

container_rootfs_shaped(mount_point) if {
	regex.match("^/run/kata-containers/[^/]+/rootfs(/.*)?$", mount_point)
}

# The storages the runtime sends here mount guest-local tmpfs instances (the
# sandbox shm, emptyDir resizes); their source is a filesystem token.
sandbox_storage_source_allowed(s) if {
	some token in ["", "shm", "tmpfs"]
	s.source == token
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
	no_traversal(input.path)
	symlink_target_in_tree
	print("CopyFileRequest: allowed")
}

# Writes through the link resolve its target; relative and traversal-free
# keeps resolution inside the seeding tree.
symlink_target_in_tree if {
	input.file_type == "Symlink"
	not startswith(input.symlink_target, "/")
	no_traversal(input.symlink_target)
}

symlink_target_in_tree if {
	input.file_type != "Symlink"
}
