# Decision tests for the baked kata-agent policy.
#
# Run by `make policy-test` and the kata-guest-base workflow. This file is
# deliberately outside extra/, which build.sh rsyncs into the guest rootfs.
#
# The policy is evaluated by regorus in the guest, which reads Rego v0 plus the
# future keywords; the checks run with --v0-compatible for the same reason.

package agent_policy

import future.keywords.every
import future.keywords.if
import future.keywords.in

cid := "6d7f5f7bd6e6b1f3a2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6"

rootfs := rootfs_of(cid)

rootfs_of(id) := concat("/", ["/run/kata-containers", id, "rootfs"])

digest_ref := "ghcr.io/confidential-dot-ai/assam@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# A CreateContainerRequest the policy admits: one guest-pull storage at this
# container's rootfs, digest-pinned, workload markers agreeing everywhere. The
# rootfs tracks the id, so an id-shape test isolates the id rule instead of
# tripping the mount-point rule with a stale path.
workload_input_for(id) := {
	"container_id": id,
	"shared_mounts": [],
	"storages": [{
		"driver": "image_guest_pull",
		"mount_point": rootfs_of(id),
		"source": digest_ref,
		"options": [],
		"driver_options": ["image_guest_pull={\"io.kubernetes.cri.container-type\":\"container\"}"],
	}],
	"OCI": {
		"Annotations": {
			"io.katacontainers.pkg.oci.container_type": "pod_container",
			"io.kubernetes.cri.container-type": "container",
			"io.kubernetes.cri.image-name": digest_ref,
		},
		"Mounts": [],
	},
}

workload_input := workload_input_for(cid)

test_workload_allowed if {
	CreateContainerRequest with input as workload_input
}

# --- container id shape -------------------------------------------------

test_container_id_must_be_64_hex if {
	every bad in [
		"init",
		"ab",
		"shared",
		"sandbox",
		"image",
		"6d7f5f7bd6e6b1f3a2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a",
		"6d7f5f7bd6e6b1f3a2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a66",
		"6D7F5F7BD6E6B1F3A2C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6",
	] {
		not CreateContainerRequest with input as workload_input_for(bad)
	}
}

# Guards the test above: the fixture must admit a well-formed id, or every
# rejection below proves nothing.
test_fixture_admits_a_valid_id if {
	CreateContainerRequest with input as workload_input_for("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
}

# --- rootfs binding -----------------------------------------------------

test_tag_only_source_denied if {
	tagged := "ghcr.io/confidential-dot-ai/assam:latest"
	not CreateContainerRequest with input as object.union(workload_input, {
		"storages": [object.union(workload_input.storages[0], {"source": tagged})],
		"OCI": {"Annotations": object.union(
			workload_input.OCI.Annotations,
			{"io.kubernetes.cri.image-name": tagged},
		)},
	})
}

# The annotation policy-monitor reads and the source kata pulls are independent
# fields of the same request; admitting a mismatch decouples the decision from
# the executed bytes.
test_source_must_equal_image_name_annotation if {
	not CreateContainerRequest with input as object.union(workload_input, {"OCI": {"Annotations": object.union(
		workload_input.OCI.Annotations,
		{"io.kubernetes.cri.image-name": "ghcr.io/other/image@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	)}})
}

test_pull_must_be_the_rootfs if {
	not CreateContainerRequest with input as object.union(workload_input, {"storages": [object.union(
		workload_input.storages[0],
		{"mount_point": "/run/kata-containers/other/rootfs"},
	)]})
}

test_second_storage_over_rootfs_denied if {
	not CreateContainerRequest with input as object.union(workload_input, {"storages": array.concat(
		workload_input.storages,
		[{"driver": "local", "mount_point": concat("/", [rootfs, "etc"]), "options": []}],
	)})
}

test_two_guest_pulls_denied if {
	not CreateContainerRequest with input as object.union(workload_input, {"storages": array.concat(
		workload_input.storages,
		[object.union(workload_input.storages[0], {"mount_point": "/elsewhere"})],
	)})
}

test_layered_rootfs_denied if {
	every layered in [
		{"driver": "erofs.multi-layer", "mount_point": "/elsewhere", "options": []},
		{"driver": "local", "mount_point": "/elsewhere", "options": ["X-kata.multi-layer=1"]},
		{"driver": "local", "mount_point": "/elsewhere", "options": ["X-kata.overlay-lower=1"]},
	] {
		not CreateContainerRequest with input as object.union(
			workload_input,
			{"storages": array.concat(workload_input.storages, [layered])},
		)
	}
}

test_shared_mounts_denied if {
	not CreateContainerRequest with input as object.union(
		workload_input,
		{"shared_mounts": [{"name": "whatever"}]},
	)
}

# --- sandbox vs workload agreement --------------------------------------

sandbox_input := {
	"container_id": cid,
	"shared_mounts": [],
	"storages": [{
		"driver": "image_guest_pull",
		"mount_point": rootfs,
		"source": "pause",
		"options": [],
		"driver_options": ["image_guest_pull={\"io.kubernetes.cri.container-type\":\"sandbox\"}"],
	}],
	"OCI": {
		"Annotations": {
			"io.katacontainers.pkg.oci.container_type": "pod_sandbox",
			"io.kubernetes.cri.container-type": "sandbox",
		},
		"Mounts": [],
	},
}

test_sandbox_allowed if {
	CreateContainerRequest with input as sandbox_input
}

# kata reads the container type from three places. A container that claims to be
# a workload while its pull metadata says sandbox runs a host-chosen rootfs.
test_sandbox_metadata_on_workload_denied if {
	not CreateContainerRequest with input as object.union(workload_input, {"storages": [object.union(
		workload_input.storages[0],
		{"driver_options": ["image_guest_pull={\"io.kubernetes.cri.container-type\":\"sandbox\"}"]},
	)]})
}

test_sandbox_source_must_be_pause if {
	not CreateContainerRequest with input as object.union(
		sandbox_input,
		{"storages": [object.union(sandbox_input.storages[0], {"source": digest_ref})]},
	)
	not CreateContainerRequest with input as object.union(
		sandbox_input,
		{"storages": [object.union(sandbox_input.storages[0], {"source": "ghcr.io/confidential-dot-ai/assam:latest"})]},
	)
}

# Sandbox annotations without the sandbox marker in the pull metadata admit
# no pull: the sandbox branch runs the measured pause and the workload branch
# is keyed on workload_annotations, so neither may bind the host's image.
test_sandbox_annotations_without_sandbox_metadata_denied if {
	not CreateContainerRequest with input as object.union(sandbox_input, {
		"storages": [object.union(sandbox_input.storages[0], {
			"source": digest_ref,
			"driver_options": ["image_guest_pull={}"],
		})],
		"OCI": {"Annotations": object.union(
			sandbox_input.OCI.Annotations,
			{"io.kubernetes.cri.image-name": digest_ref},
		)},
	})
	not CreateContainerRequest with input as object.union(sandbox_input, {
		"storages": [object.union(sandbox_input.storages[0], {
			"source": digest_ref,
			"driver_options": ["image_guest_pull={\"io.kubernetes.cri.container-type\":\"container\"}"],
		})],
		"OCI": {"Annotations": object.union(
			sandbox_input.OCI.Annotations,
			{"io.kubernetes.cri.image-name": digest_ref},
		)},
	})
}

# An image-name annotation must not give a sandbox-annotated request's pull
# source a second way to bind: the sandbox branch runs the measured pause.
test_sandbox_source_stays_pause_with_image_name if {
	not CreateContainerRequest with input as object.union(sandbox_input, {
		"storages": [object.union(sandbox_input.storages[0], {"source": digest_ref})],
		"OCI": {"Annotations": object.union(
			sandbox_input.OCI.Annotations,
			{"io.kubernetes.cri.image-name": digest_ref},
		)},
	})
}

# object.union is shallow, so merge at each level to keep the rest of the
# fixture — with the base fixtures admitted, only the override can deny.
with_annotations(base, extra) := object.union(base, {"OCI": object.union(
	base.OCI,
	{"Annotations": object.union(base.OCI.Annotations, extra)},
)})

# containerd never sets the CRI-O marker; a request carrying one is denied
# rather than classified, whatever the honest markers say. The guard is on
# the key's presence, so an empty or garbage value denies too.
test_crio_container_type_marker_denied if {
	not CreateContainerRequest with input as with_annotations(workload_input, {"io.kubernetes.cri-o.ContainerType": "sandbox"})
	not CreateContainerRequest with input as with_annotations(workload_input, {"io.kubernetes.cri-o.ContainerType": "container"})
	not CreateContainerRequest with input as with_annotations(sandbox_input, {"io.kubernetes.cri-o.ContainerType": "sandbox"})
	not CreateContainerRequest with input as with_annotations(sandbox_input, {"io.kubernetes.cri-o.ContainerType": "container"})
	not CreateContainerRequest with input as with_annotations(workload_input, {"io.kubernetes.cri-o.ContainerType": ""})
	not CreateContainerRequest with input as with_annotations(workload_input, {"io.kubernetes.cri-o.ContainerType": "garbage"})
}

# The guest-pull handler reads the container type from the serialised pull
# metadata as well; the CRI-O marker is denied there too, plain or
# JSON-escaped.
test_crio_marker_in_pull_metadata_denied if {
	not CreateContainerRequest with input as object.union(workload_input, {"storages": [object.union(
		workload_input.storages[0],
		{"driver_options": ["image_guest_pull={\"io.kubernetes.cri-o.ContainerType\":\"sandbox\"}"]},
	)]})
	not CreateContainerRequest with input as object.union(workload_input, {"storages": [object.union(
		workload_input.storages[0],
		{"driver_options": ["image_guest_pull={\"io.kubernetes.cri-o.\\u0043ontainerType\":\"sandbox\"}"]},
	)]})
	not CreateContainerRequest with input as object.union(sandbox_input, {"storages": [object.union(
		sandbox_input.storages[0],
		{"driver_options": ["image_guest_pull={\"io.kubernetes.cri.container-type\":\"sandbox\",\"io.kubernetes.cri-o.ContainerType\":\"sandbox\"}"]},
	)]})
}

# The veto reads decoded metadata keys, so an annotation value that merely
# mentions the key string is not the marker.
test_crio_key_string_in_annotation_value_allowed if {
	CreateContainerRequest with input as object.union(workload_input, {
		"storages": [object.union(
			workload_input.storages[0],
			{"driver_options": ["image_guest_pull={\"io.kubernetes.cri.container-type\":\"container\",\"example.com/note\":\"mentions io.kubernetes.cri-o.ContainerType\"}"]},
		)],
		"OCI": {"Annotations": object.union(
			workload_input.OCI.Annotations,
			{"example.com/note": "mentions io.kubernetes.cri-o.ContainerType"},
		)},
	})
}

# The two type markers the policy conjoins must agree with each other.
test_conflicting_container_type_markers_denied if {
	not CreateContainerRequest with input as with_annotations(sandbox_input, {"io.kubernetes.cri.container-type": "container"})
	not CreateContainerRequest with input as with_annotations(workload_input, {"io.katacontainers.pkg.oci.container_type": "pod_sandbox"})
}

# --- sandbox and ephemeral storages -------------------------------------

test_sandbox_storage_shaped_like_a_rootfs_denied if {
	not CreateSandboxRequest with input as {"storages": [{"mount_point": rootfs}]}
	not UpdateEphemeralMountsRequest with input as {"storages": [{"mount_point": rootfs}]}
}

test_sandbox_storage_elsewhere_allowed if {
	CreateSandboxRequest with input as {"storages": [{"mount_point": "/run/kata-containers/sandbox/shm", "source": "shm"}]}
	CreateSandboxRequest with input as {"storages": [{"mount_point": "/run/kata-containers/shared/containers/x", "source": ""}]}
	UpdateEphemeralMountsRequest with input as {"storages": [{"mount_point": "/run/kata-containers/sandbox/y", "source": "tmpfs"}]}
}

# The runtime only ever sends fs tokens here; a path source is host-staged
# content the ephemeral handler would mount verbatim.
test_sandbox_storage_with_path_source_denied if {
	every source in ["/", "/run", "/run/kata-containers/other/rootfs", "../.."] {
		not CreateSandboxRequest with input as {"storages": [{"mount_point": "/run/kata-containers/sandbox/x", "source": source}]}
		not UpdateEphemeralMountsRequest with input as {"storages": [{"mount_point": "/run/kata-containers/sandbox/x", "source": source}]}
	}
}

# --- mounts -------------------------------------------------------------
#
# The runtime rewrites every bind source it sends into a directory it manages,
# so a source anywhere else is guest state the host is asking to hand a
# container. Where a mount LANDS is not gated here — see the rule comment.

honest_mounts := [
	{"destination": "/proc", "source": "proc", "type_": "proc", "options": []},
	{"destination": "/sys/fs/cgroup", "source": "cgroup", "type_": "cgroup", "options": []},
	{"destination": "/dev/shm", "source": "/run/kata-containers/sandbox/shm", "type_": "bind", "options": ["rbind"]},
	{"destination": "/etc/resolv.conf", "source": "/run/kata-containers/shared/containers/pod-resolv.conf", "type_": "bind", "options": []},
	{"destination": "/data", "source": "/run/kata-containers/sandbox/storage/aGk", "type_": "bind", "options": []},
]

with_mounts(ms) := object.union(workload_input, {"OCI": {"Mounts": ms}})

bind_from(source) := {"destination": "/x", "source": source, "type_": "bind", "options": []}

test_honest_mounts_allowed if {
	CreateContainerRequest with input as with_mounts(honest_mounts)
}

test_mount_from_outside_the_sandbox_dirs_denied if {
	every source in [
		"/",
		"/etc/c8s/bootstrap-allowlist.json",
		"/run/c8s/ratls-mesh.env",
		"/run/kata-containers/image",
		"/run/kata-containers/other/rootfs",
	] {
		not CreateContainerRequest with input as with_mounts(array.concat(
			honest_mounts,
			[bind_from(source)],
		))
	}
}

test_mount_source_traversal_denied if {
	not CreateContainerRequest with input as with_mounts(array.concat(
		honest_mounts,
		[bind_from("/run/kata-containers/sandbox/../../c8s/ratls-mesh.env")],
	))
}

# A relative bind source resolves against the bundle directory, so "../.."
# reaches /run — whether the bind is marked by type or by option.
test_relative_bind_source_denied if {
	every m in [
		{"destination": "/x", "source": "../..", "type_": "bind", "options": []},
		{"destination": "/x", "source": "../..", "type_": "tmpfs", "options": ["rbind"]},
		{"destination": "/x", "source": "../..", "type_": "", "options": ["bind"]},
	] {
		not CreateContainerRequest with input as with_mounts(array.concat(honest_mounts, [m]))
	}
}

# Filesystem mounts carry a type, not a source path.
test_fs_mount_without_source_allowed if {
	CreateContainerRequest with input as with_mounts(array.concat(
		honest_mounts,
		[{"destination": "/x", "source": "", "type_": "tmpfs", "options": []}],
	))
}

# Same names CopyFile has to keep working for.
test_mount_allows_projected_volume_names if {
	CreateContainerRequest with input as with_mounts(array.concat(
		honest_mounts,
		[bind_from("/run/kata-containers/shared/containers/pod-vol/..data")],
	))
}

# --- CopyFile -----------------------------------------------------------

test_copyfile_scoped_to_the_seeding_dir if {
	CopyFileRequest with input as {"path": "/run/kata-containers/shared/containers/pod/etc/hosts", "file_type": "Regular"}
	not CopyFileRequest with input as {"path": "/run/kata-containers/foo/rootfs/bin/sh", "file_type": "Regular"}
	not CopyFileRequest with input as {"path": "/etc/passwd", "file_type": "Regular"}
}

test_copyfile_rejects_traversal if {
	not CopyFileRequest with input as {"path": "/run/kata-containers/shared/containers/../../foo/rootfs/x", "file_type": "Regular"}
	not CopyFileRequest with input as {"path": "/run/kata-containers/shared/containers/..", "file_type": "Regular"}
}

# Projected volumes legitimately carry `..data` and `..<timestamp>` names.
test_copyfile_allows_projected_volume_names if {
	CopyFileRequest with input as {"path": "/run/kata-containers/shared/containers/pod/..data/token", "file_type": "Regular"}
	CopyFileRequest with input as {"path": "/run/kata-containers/shared/containers/pod/..2026_08_05_12_00_00/token", "file_type": "Regular"}
}

symlink_input(target) := {
	"path": "/run/kata-containers/shared/containers/pod-vol/..data",
	"file_type": "Symlink",
	"symlink_target": target,
}

test_copyfile_symlink_absolute_target_denied if {
	not CopyFileRequest with input as symlink_input("/run")
}

test_copyfile_symlink_traversal_target_denied if {
	not CopyFileRequest with input as symlink_input("../../../c8s")
	not CopyFileRequest with input as symlink_input("sub/../../c8s/ratls-mesh.env")
}

# Projected volumes seed `..data` as a link to a `..<timestamp>` name.
test_copyfile_symlink_relative_target_allowed if {
	CopyFileRequest with input as symlink_input("..2026_08_10_12_00_00.123456789")
}

# --- host-as-adversary RPCs ---------------------------------------------

test_host_reach_in_rpcs_denied if {
	not SetPolicyRequest
	not ExecProcessRequest
	not ReadStreamRequest
	not WriteStreamRequest
}

test_add_swap_denied if {
	not AddSwapRequest
}
