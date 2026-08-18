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
		"Hooks": null,
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

# is_multi_layer_storage reads the options before the driver, so the option forms
# are carried by a storage the driver and mount-point rules admit — on any other
# carrier those rules deny first and this test reads nothing.
test_layered_rootfs_denied if {
	every layered in [
		{"driver": "ephemeral", "fstype": "tmpfs", "mount_point": "/run/kata-containers/sandbox/storage/aGk", "options": ["X-kata.multi-layer=1"]},
		{"driver": "ephemeral", "fstype": "tmpfs", "mount_point": "/run/kata-containers/sandbox/storage/aGk", "options": ["X-kata.overlay-lower=/run/c8s"]},
	] {
		not CreateContainerRequest with input as object.union(
			workload_input,
			{"storages": array.concat(workload_input.storages, [layered])},
		)
	}
}

# --- container storages -------------------------------------------------
#
# Under the shipped emptydir_mode="block-encrypted", a container carries the
# guest pull plus two emptyDir shapes: a memory-backed one as a guest tmpfs, and
# a default-medium one as a LUKS2 device CDH opens under a guest-generated key.
# `local` and `hugetlbfs` storages need emptydir_mode="shared-fs", which is the
# only mode that sets the mount type handleLocalStorage and handleHugepages
# both key on, so neither is admitted.

memory_emptydir := {
	"driver": "ephemeral",
	"mount_point": "/run/kata-containers/sandbox/ephemeral/aGk",
	"source": "tmpfs",
	"fstype": "tmpfs",
	"options": [],
	"driver_options": [],
}

encrypted_emptydir := {
	"driver": "blk",
	"mount_point": "/run/kata-containers/sandbox/storage/aGk",
	"source": "0000:00:04.0",
	"fstype": "ext4",
	"options": [],
	"driver_options": ["encryption_key=ephemeral"],
}

with_storages(ss) := object.union(workload_input, {"storages": array.concat(workload_input.storages, ss)})

test_guest_local_container_storages_allowed if {
	CreateContainerRequest with input as with_storages([memory_emptydir, encrypted_emptydir])
}

# Which of the three block drivers carries the device is the shim's choice of
# BlockDeviceDriver, and each has its own source form.
test_encrypted_block_drivers_allowed if {
	every s in [
		{"driver": "blk", "source": "0000:00:04.0"},
		{"driver": "blk-ccw", "source": "0.0.0004"},
		{"driver": "scsi", "source": "0:0:0:4"},
	] {
		CreateContainerRequest with input as with_storages([object.union(encrypted_emptydir, s)])
	}
}

# The runtime merges every container annotation into the driver options, so the
# marker arrives among entries the policy does not read. Pinned, so tightening to
# an exact list would fail here rather than in a cluster.
test_encrypted_block_with_extra_driver_options_allowed if {
	CreateContainerRequest with input as with_storages([object.union(
		encrypted_emptydir,
		{"driver_options": ["fsGroup=2000", "encryption_key=ephemeral"]},
	)])
}

# cdh_secure_mount LUKS2-formats what it is handed, and the block handler takes
# any /dev path that stats as a block device — the verity backing device or a
# volumed-opened mapper node included.
test_encrypted_block_with_a_device_path_source_denied if {
	every source in ["/dev/vda", "/dev/mapper/c8s-vol-weights", "/"] {
		not CreateContainerRequest with input as with_storages([object.union(
			encrypted_emptydir,
			{"source": source},
		)])
	}
}

# The mode option is what a local storage chmods its mount point with.
test_local_driver_denied if {
	not CreateContainerRequest with input as with_storages([{
		"driver": "local",
		"mount_point": "/run/kata-containers/shared/containers/x/rootfs/local/aGk",
		"source": "local",
		"fstype": "local",
		"options": ["mode=0777"],
		"driver_options": [],
	}])
	not CreateSandboxRequest with input as sandbox_req([{"driver": "local", "mount_point": "/run/kata-containers/shared/containers/x", "source": "", "fstype": "local"}])
}

# CDS's own /data volume is a default-medium emptyDir when persistence is off,
# so the encrypted block shape is on the boot path of the cluster's own service.
test_cds_data_volume_allowed if {
	CreateContainerRequest with input as object.union(
		with_storages([encrypted_emptydir]),
		{"OCI": {"Mounts": array.concat(honest_mounts, [{
			"destination": "/data",
			"source": encrypted_emptydir.mount_point,
			"type_": "bind",
			"options": ["rbind"],
		}])}},
	)
}

# The matrix crosses driver and fstype in both directions: here a host-backed
# driver wearing the guest-local fstype, below the reverse. The source is one the
# watchable-bind copy loop would carry out to a path the container binds.
test_host_backed_driver_denied if {
	every driver in ["blk", "blk-ccw", "erofs.multi-layer", "mmioblk", "nvdimm", "overlayfs", "scsi", "virtio-fs", "watchable-bind"] {
		not CreateContainerRequest with input as with_storages([{
			"driver": driver,
			"mount_point": "/run/kata-containers/shared/containers/watchable/leak",
			"source": "/run/c8s",
			"fstype": "tmpfs",
			"options": [],
			"driver_options": [],
		}])
	}
}

# The overlay handler rewrites fstype to "overlay" on this option and assembles
# the mount from a host-named lowerdir. The option prefix is not the
# X-kata.overlay- one layered_rootfs_storage reads.
test_overlay_rw_option_denied if {
	not CreateContainerRequest with input as with_storages([{
		"driver": "overlayfs",
		"mount_point": "/run/kata-containers/sandbox/storage/aGk",
		"source": "none",
		"fstype": "tmpfs",
		"options": ["io.katacontainers.fs-opt.overlay-rw", "lowerdir=/run/c8s"],
		"driver_options": [],
	}])
}

test_unencrypted_block_storage_denied if {
	every driver_options in [[], ["encryption_key=none"], ["mentions encryption_key=ephemeral"]] {
		not CreateContainerRequest with input as with_storages([object.union(
			encrypted_emptydir,
			{"driver_options": driver_options},
		)])
	}
}

# mmioblk and nvdimm never route to the CDH branch, so the marker must not carry
# them either.
test_encryption_marker_on_a_plaintext_driver_denied if {
	every driver in ["mmioblk", "nvdimm"] {
		not CreateContainerRequest with input as with_storages([object.union(
			encrypted_emptydir,
			{"driver": driver},
		)])
	}
}

# The ephemeral handler hands fstype to mount(2), so a guest-local driver naming
# a host-attached filesystem mounts one.
test_host_backed_fstype_on_a_guest_driver_denied if {
	every fstype in ["9p", "erofs", "ext4", "hugetlbfs", "iso9660", "overlay", "vfat", "virtiofs"] {
		not CreateContainerRequest with input as with_storages([object.union(memory_emptydir, {"fstype": fstype})])
	}
}

# A storage's mount point is a guest path the host names. /run/c8s holds the
# pod's mesh leaf key and its released secrets, /etc/c8s the allowlist seed. A
# mount point that is the prefix, or resolves back to it, covers the seeded tree
# and every sibling emptyDir.
test_container_storage_on_a_guest_path_denied if {
	every mount_point in [
		"/run/c8s",
		"/run/c8s/certs",
		"/run/c8s/secrets",
		"/etc/c8s",
		"/run/kata-containers/sandbox",
		"/run/kata-containers/sandbox/",
		"/run/kata-containers/sandbox//",
		"/run/kata-containers/sandbox/.",
		"/run/kata-containers/shared/containers",
		"/run/kata-containers/shared/containers/",
		"/run/kata-containers/shared/containers/./x",
		"/run/kata-containers/sandbox/../../c8s/secrets",
		"/run/kata-containers/sandbox/ephemeral/../../../c8s/secrets",
		"//run/kata-containers/sandbox/x",
	] {
		not CreateContainerRequest with input as with_storages([object.union(memory_emptydir, {"mount_point": mount_point})])
		not CreateContainerRequest with input as with_storages([object.union(encrypted_emptydir, {"mount_point": mount_point})])
	}
}

# A host-backed storage at a path the runtime manages, which an OCI mount then
# binds over the credential directory the c8s sidecar writes into.
test_host_backed_storage_bound_over_a_credential_path_denied if {
	block := object.union(encrypted_emptydir, {"driver_options": []})
	every destination in ["/run/c8s/certs", "/run/c8s/secrets"] {
		not CreateContainerRequest with input as object.union(
			with_storages([block]),
			{"OCI": {"Mounts": array.concat(honest_mounts, [{
				"destination": destination,
				"source": block.mount_point,
				"type_": "bind",
				"options": ["rbind"],
			}])}},
		)
	}
}

# The same paths carry the injected memory-backed emptyDirs, which is how the
# sidecar and the workload share them.
test_credential_path_from_a_guest_tmpfs_allowed if {
	CreateContainerRequest with input as object.union(
		with_storages([memory_emptydir]),
		{"OCI": {"Mounts": array.concat(honest_mounts, [{
			"destination": "/run/c8s/certs",
			"source": memory_emptydir.mount_point,
			"type_": "bind",
			"options": ["rbind"],
		}])}},
	)
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
		"Hooks": null,
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
#
# The shm tmpfs, and the resize of an unbounded memory emptyDir. Both land in
# the trees a container binds from, so both carry a container storage's
# constraints.

# guest_hook_path and kernel_modules always serialize; an honest request
# carries both empty.
sandbox_req(ss) := {"guest_hook_path": "", "kernel_modules": [], "storages": ss}

# The fixture is otherwise admissible, so only the rootfs shape can deny it. A
# sandbox-tree path can be rootfs-shaped too, which is the case that isolates
# this rule from the mount-point prefix rule.
test_sandbox_storage_shaped_like_a_rootfs_denied if {
	every mount_point in [rootfs, "/run/kata-containers/sandbox/rootfs"] {
		not CreateSandboxRequest with input as sandbox_req([{"driver": "ephemeral", "mount_point": mount_point, "source": "shm", "fstype": "tmpfs"}])
		not UpdateEphemeralMountsRequest with input as {"storages": [{"driver": "ephemeral", "mount_point": mount_point, "source": "tmpfs", "fstype": "tmpfs"}]}
	}
}

test_sandbox_storage_elsewhere_allowed if {
	CreateSandboxRequest with input as sandbox_req([{"driver": "ephemeral", "mount_point": "/run/kata-containers/sandbox/shm", "source": "shm", "fstype": "tmpfs"}])
	CreateSandboxRequest with input as sandbox_req([{"driver": "ephemeral", "mount_point": "/run/kata-containers/shared/containers/x", "source": "", "fstype": "tmpfs"}])
	UpdateEphemeralMountsRequest with input as {"storages": [{"driver": "ephemeral", "mount_point": "/run/kata-containers/sandbox/y", "source": "tmpfs", "fstype": "tmpfs"}]}
}

# A source token says nothing about the filesystem the handler mounts: the
# sandbox shm and the seeding tree are what every container binds from, so a
# storage claiming a host-attached filesystem there is host bytes for the pod.
test_sandbox_storage_with_host_backed_fstype_denied if {
	every fstype in ["9p", "erofs", "ext4", "hugetlbfs", "iso9660", "overlay", "vfat", "virtiofs"] {
		not CreateSandboxRequest with input as sandbox_req([{"driver": "ephemeral", "mount_point": "/run/kata-containers/shared/containers/x", "source": "tmpfs", "fstype": fstype}])
		not UpdateEphemeralMountsRequest with input as {"storages": [{"driver": "ephemeral", "mount_point": "/run/kata-containers/sandbox/ephemeral/x", "source": "tmpfs", "fstype": fstype}]}
	}
}

# A sandbox storage names a filesystem, so the encrypted-block shape has no
# business here — and the source tokens are not what excludes it: "shm" is no
# more absolute than a PCI path. Only container_storage_allowed reaches that rule.
test_sandbox_encrypted_block_storage_denied if {
	every source in ["", "shm", "tmpfs"] {
		not CreateSandboxRequest with input as sandbox_req([{"driver": "blk", "mount_point": "/run/kata-containers/sandbox/x", "source": source, "fstype": "ext4", "driver_options": ["encryption_key=ephemeral"]}])
		not UpdateEphemeralMountsRequest with input as {"storages": [{"driver": "blk", "mount_point": "/run/kata-containers/sandbox/x", "source": source, "fstype": "ext4", "driver_options": ["encryption_key=ephemeral"]}]}
	}
}

# is_multi_layer_storage reads the options alone, so the option forms reach the
# sandbox path too — add_storages dispatches on them for a storage carrying no
# container id. An overlay assembled out of host block devices at the seeding
# tree is what every container then binds from.
test_sandbox_layered_storage_denied if {
	every options in [["X-kata.multi-layer=true"], ["X-kata.overlay-lower=/run/c8s"], ["X-kata.overlay-rw"]] {
		not CreateSandboxRequest with input as sandbox_req([{"driver": "ephemeral", "mount_point": "/run/kata-containers/shared/containers/hijack", "source": "tmpfs", "fstype": "tmpfs", "options": options}])
		not UpdateEphemeralMountsRequest with input as {"storages": [{"driver": "ephemeral", "mount_point": "/run/kata-containers/sandbox/ephemeral/hijack", "source": "tmpfs", "fstype": "tmpfs", "options": options}]}
	}
}

# The same both ways round: a host-backed driver carrying a guest-local fstype.
# The seeding tree is the sandbox-time prize — every container binds from it.
test_sandbox_storage_with_host_backed_driver_denied if {
	every driver in ["blk", "blk-ccw", "erofs.multi-layer", "mmioblk", "nvdimm", "overlayfs", "scsi", "virtio-fs", "watchable-bind"] {
		not CreateSandboxRequest with input as sandbox_req([{"driver": driver, "mount_point": "/run/kata-containers/shared/containers/x", "source": "tmpfs", "fstype": "tmpfs"}])
		not UpdateEphemeralMountsRequest with input as {"storages": [{"driver": driver, "mount_point": "/run/kata-containers/sandbox/ephemeral/x", "source": "tmpfs", "fstype": "tmpfs"}]}
	}
}

test_sandbox_storage_outside_the_runtime_dirs_denied if {
	every mount_point in [
		"/run/c8s",
		"/run/c8s/certs",
		"/etc/c8s",
		"/run/kata-containers/sandbox",
		"/run/kata-containers/sandbox/",
		"/run/kata-containers/sandbox/.",
		"/run/kata-containers/shared/containers/",
		"/run/kata-containers/sandbox/../../c8s",
		"/run/kata-containers/sandbox/ephemeral/../../../c8s",
	] {
		not CreateSandboxRequest with input as sandbox_req([{"driver": "ephemeral", "mount_point": mount_point, "source": "tmpfs", "fstype": "tmpfs"}])
		not UpdateEphemeralMountsRequest with input as {"storages": [{"driver": "ephemeral", "mount_point": mount_point, "source": "tmpfs", "fstype": "tmpfs"}]}
	}
}

# The runtime only ever sends fs tokens here; a path source is host-staged
# content the ephemeral handler would mount verbatim.
test_sandbox_storage_with_path_source_denied if {
	every source in ["/", "/run", "/run/kata-containers/other/rootfs", "../.."] {
		not CreateSandboxRequest with input as sandbox_req([{"driver": "ephemeral", "mount_point": "/run/kata-containers/sandbox/x", "source": source, "fstype": "tmpfs"}])
		not UpdateEphemeralMountsRequest with input as {"storages": [{"driver": "ephemeral", "mount_point": "/run/kata-containers/sandbox/x", "source": source, "fstype": "tmpfs"}]}
	}
}

# --- mounts -------------------------------------------------------------
#
# The runtime rewrites every bind source it sends into a directory it manages,
# so a source anywhere else is guest state the host is asking to hand a
# container. Where a mount LANDS is not gated here — see the rule comment.

honest_mounts := [
	{"destination": "/proc", "source": "proc", "type_": "proc", "options": []},
	{"destination": "/sys", "source": "sysfs", "type_": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"]},
	{"destination": "/sys/fs/cgroup", "source": "cgroup", "type_": "cgroup", "options": []},
	{"destination": "/sys/fs/cgroup", "source": "cgroup", "type_": "cgroup2", "options": ["nsdelegate"]},
	{"destination": "/dev/pts", "source": "devpts", "type_": "devpts", "options": ["newinstance", "ptmxmode=0666"]},
	{"destination": "/dev/mqueue", "source": "mqueue", "type_": "mqueue", "options": ["nosuid", "noexec", "nodev"]},
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

# A bind source is held to the same shape a storage mount point is: a tree with
# a plain component after it. The tree itself carries every seeded file and every
# sibling emptyDir.
test_bind_source_at_the_tree_denied if {
	every source in [
		"/run/kata-containers/sandbox/",
		"/run/kata-containers/sandbox//",
		"/run/kata-containers/shared/containers/",
		"/run/kata-containers/shared/containers/./x",
	] {
		not CreateContainerRequest with input as with_mounts(array.concat(honest_mounts, [bind_from(source)]))
	}
}

# A relative bind source resolves against the bundle directory: "../.." reaches
# /run, and a plain name reaches the bundle itself. The runtime builds every
# source it sends with filepath.Join, so all of these are host-composed.
test_relative_bind_source_denied if {
	every m in [
		{"destination": "/x", "source": "../..", "type_": "bind", "options": []},
		{"destination": "/x", "source": "rootfs/etc", "type_": "bind", "options": []},
		{"destination": "/x", "source": "../..", "type_": "tmpfs", "options": ["rbind"]},
		{"destination": "/x", "source": "../..", "type_": "proc", "options": ["bind"]},
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

# rustjail passes a non-bind mount's type straight to mount(2), so a filesystem
# name is the second way to reach host bytes: virtiofs and 9p mount a device the
# host attached to the VM, and a disk filesystem mounts a disk it attached. The
# destination is the host's to choose, credential paths included.
test_host_backed_fs_mount_denied if {
	every m in [
		{"destination": "/run/c8s/certs", "source": "kataShared", "type_": "virtiofs", "options": []},
		{"destination": "/run/c8s/secrets", "source": "kataShared", "type_": "9p", "options": ["trans=virtio"]},
		{"destination": "/x", "source": "vda", "type_": "ext4", "options": []},
		{"destination": "/x", "source": "none", "type_": "overlay", "options": ["lowerdir=/run/kata-containers/sandbox/x"]},
		{"destination": "/x", "source": "none", "type_": "erofs", "options": []},
		{"destination": "/x", "source": "", "type_": "", "options": []},
		# A virtiofs or 9p source is the tag the host gave the device, not a
		# path, so it may be spelled as one of the sandbox directories.
		{"destination": "/run/c8s/certs", "source": "/run/kata-containers/sandbox/x", "type_": "virtiofs", "options": []},
		{"destination": "/run/c8s/secrets", "source": "/run/kata-containers/shared/containers/x", "type_": "9p", "options": ["trans=virtio"]},
	] {
		not CreateContainerRequest with input as with_mounts(array.concat(honest_mounts, [m]))
	}
}

# Same names CopyFile has to keep working for.
test_mount_allows_projected_volume_names if {
	CreateContainerRequest with input as with_mounts(array.concat(
		honest_mounts,
		[bind_from("/run/kata-containers/shared/containers/pod-vol/..data")],
	))
}

# --- spec hooks ---------------------------------------------------------
#
# Hooks ride inside the OCI spec of an otherwise-admitted request; Prestart
# and CreateContainer execute as guest root before the admission verdict,
# the remaining lists after it (CreateRuntime never fires in the agent).
# constrainGRPCSpec clears Hooks, and the protobuf serializer emits null
# for an unset message, so null is the one shape an honest request carries.

with_hooks(base, hooks) := object.union(base, {"OCI": {"Hooks": hooks}})

spec_hook := {"Path": "/bin/bash", "Args": ["bash", "-c", "true"], "Env": [], "Timeout": 0}

test_spec_hooks_denied if {
	every list_name in ["Prestart", "CreateRuntime", "CreateContainer", "StartContainer", "Poststart", "Poststop"] {
		not CreateContainerRequest with input as with_hooks(workload_input, {list_name: [spec_hook]})
		not CreateContainerRequest with input as with_hooks(sandbox_input, {list_name: [spec_hook]})
	}
}

test_honest_hook_shape_allowed if {
	CreateContainerRequest with input as with_hooks(workload_input, null)
}

# Shapes an enumeration of the six known lists reads straight past: a hook
# list this kata pin does not have, a falsy element, an empty-but-present
# message, and a Hooks that is not an object at all.
test_non_null_hooks_denied if {
	every hooks in [
		{"NewHookList": [spec_hook]},
		{"Prestart": [false]},
		{"Prestart": []},
		{},
		"hooks",
		[spec_hook],
	] {
		not CreateContainerRequest with input as with_hooks(workload_input, hooks)
	}
}

admissible_sandbox := sandbox_req([{"driver": "ephemeral", "mount_point": "/run/kata-containers/sandbox/shm", "source": "shm", "fstype": "tmpfs"}])

# A non-empty guest_hook_path is denied even on an otherwise-admitted
# sandbox: add_hooks would arm every container from that guest directory.
test_guest_hook_path_denied if {
	CreateSandboxRequest with input as admissible_sandbox
	not CreateSandboxRequest with input as object.union(
		admissible_sandbox,
		{"guest_hook_path": "/run/kata-containers/shared/containers/x"},
	)
}

# load_kernel_module runs modprobe with the request's name and parameters
# as argv, so a module list is host-chosen code in the guest kernel.
test_kernel_modules_denied if {
	not CreateSandboxRequest with input as object.union(
		admissible_sandbox,
		{"kernel_modules": [{"name": "c8s_hostile", "parameters": []}]},
	)
}

# Both guards are count() over a key the protobuf serializer always emits.
# An absent key makes count() undefined, so the request is denied — pinned
# because a kata bump that stops emitting either key denies every sandbox.
test_sandbox_guard_keys_required if {
	every key in ["guest_hook_path", "kernel_modules"] {
		not CreateSandboxRequest with input as object.remove(admissible_sandbox, [key])
	}
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

# The mount this reads through is itself admissible, so the RPC is what denies.
test_termination_log_read_denied if {
	not GetDiagnosticDataRequest with input as {
		"container_id": cid,
		"log_type": "termination_log",
	}

	CreateContainerRequest with input as object.union(
		with_annotations(workload_input, {"io.kubernetes.container.terminationMessagePath": "/dev/termination-log"}),
		{"OCI": {"Mounts": [{
			"destination": "/dev/termination-log",
			"source": "/run/kata-containers/sandbox/ephemeral/c8s-certs/tls.key",
			"type_": "bind",
			"options": ["rbind", "ro"],
		}]}},
	)
}

test_add_swap_denied if {
	not AddSwapRequest
}

test_reseed_random_dev_denied if {
	not ReseedRandomDevRequest
}
