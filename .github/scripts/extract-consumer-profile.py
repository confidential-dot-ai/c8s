#!/usr/bin/env python3
"""Extract the one reviewed confidential-inference node profile safely."""

import argparse
import hashlib
import pathlib
import tarfile


EXPECTED_FILES = {
    "mkosi.conf",
    "mkosi.extra/etc/systemd/system/control-plane-state-disk.service",
    # This must sort after c8s no-modprobe.conf. That drop-in clears the base
    # RKE2 ExecStartPre list; an earlier consumer recovery hook is also lost.
    "mkosi.extra/etc/systemd/system/rke2-server.service.d/zz-control-plane-state.conf",
    "mkosi.extra/usr/local/libexec/confidential-inference/control-plane-state-disk.sh",
    "mkosi.extra/usr/local/libexec/confidential-inference/rke2-single-control-recovery.sh",
}
EXPECTED_MKOSI_SHA256 = "b65d550f0fd78f710aa35272c361622e2e66f9f4e4d7e557ed2d2be4528c03a3"
MAX_CONTENT_BYTES = 65_536


def extract(archive: pathlib.Path, destination: pathlib.Path) -> None:
    found: set[str] = set()
    total = 0
    with tarfile.open(archive, "r:") as source:
        for member in source.getmembers():
            name = member.name.removeprefix("./").rstrip("/")
            if not name:
                continue
            path = pathlib.PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unsafe profile path: {member.name}")
            if member.isdir():
                continue
            if not member.isfile() or name not in EXPECTED_FILES:
                raise ValueError(f"unexpected profile member: {member.name}")
            if name in found:
                raise ValueError(f"duplicate profile member: {member.name}")
            total += member.size
            if total > MAX_CONTENT_BYTES:
                raise ValueError("consumer profile content is too large")
            content = source.extractfile(member)
            if content is None:
                raise ValueError(f"cannot read profile member: {member.name}")
            output = destination.joinpath(*path.parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(content.read())
            output.chmod(0o644)
            found.add(name)

    if found != EXPECTED_FILES:
        missing = ", ".join(sorted(EXPECTED_FILES - found))
        raise ValueError(f"consumer profile is incomplete: {missing}")
    actual_mkosi_sha256 = hashlib.sha256((destination / "mkosi.conf").read_bytes()).hexdigest()
    if actual_mkosi_sha256 != EXPECTED_MKOSI_SHA256:
        raise ValueError("consumer mkosi.conf is not the reviewed packages-only profile")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=pathlib.Path)
    parser.add_argument("destination", type=pathlib.Path)
    args = parser.parse_args()
    extract(args.archive, args.destination)


if __name__ == "__main__":
    main()
