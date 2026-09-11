#!/usr/bin/python3
"""c8s writable-state contract; invoke through immutable-root-test.sh only."""

import errno
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import unittest

IMAGE = Path("/image")
ROOT = Path("/sysroot")


def run(*args, **kwargs):
    return subprocess.run(
        args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=30, **kwargs
    )


def snapshot(root):
    """Include names, contents, ownership, modes and symlinks, ignoring atime."""
    result = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        content = None
        if path.is_symlink():
            content = os.readlink(path)
        elif path.is_file():
            content = hashlib.sha256(path.read_bytes()).hexdigest()
        result[str(path.relative_to(root))] = (
            info.st_mode, info.st_uid, info.st_gid, content
        )
    return result


class ImmutableNodeRootTests(unittest.TestCase):
    def setUp(self):
        shutil.copytree("/image-template", IMAGE, symlinks=True)
        # Package-created base dirs and sync-created c8s paths. The invariant
        # gate separately checks mkosi.sync creates CNI/NRI directories; do not
        # derive these from state.d, which would hide missing build-time dirs.
        for directory in (
            "var", "home", "root", "tmp", "run", "etc",
            "etc/rancher/rke2/config.yaml.d", "etc/cni/net.d", "opt/cni/bin",
            "etc/nri/conf.d", "opt/nri/plugins",
        ):
            (IMAGE / directory).mkdir(parents=True, exist_ok=True)
        (IMAGE / "root").chmod(0o700)
        (IMAGE / "tmp").chmod(0o1777)
        shutil.copyfile("/nri-floor-template", IMAGE / "etc/nri/conf.d/image-policy.yaml")
        (IMAGE / "opt/nri/plugins/10-nri-image-policy").write_text("baked plugin fixture\n")
        # Run the actual finalizer after composing all profile extra trees. In
        # particular it must create /etc/confai without overwriting a profile.
        finalized = run(
            "/bin/bash", "/finalize-under-test",
            env={**os.environ, "BUILDROOT": str(IMAGE)},
        )
        self.assertEqual(finalized.returncode, 0, finalized.stdout)
        self.assertEqual(os.readlink(IMAGE / "etc/confai"), "../run/confai")
        Path("/switch-root-args").unlink(missing_ok=True)
        Path("/proc/sysrq-trigger").write_text("")

    def test_declared_state_writes_leave_the_image_immutable(self):
        before = snapshot(IMAGE)
        booted = run("/bin/bash", "/init-under-test")
        self.assertEqual(booted.returncode, 0, booted.stdout)
        self.assertEqual(Path("/switch-root-args").read_text(), "/sysroot\n/sbin/init\n")
        self.assertEqual(Path("/proc/sysrq-trigger").read_text(), "")

        # Representative RKE2, Cilium, NRI and runtime writes, including the
        # chart's atomic replacement of a baked NRI floor in its own directory.
        for relative in (
            "etc/rancher/rke2/config.yaml.d/95-gpu-resources.yaml",
            "etc/rancher/node/password", "etc/cni/net.d/10-cilium.conflist",
            "opt/cni/bin/cilium-cni", "etc/nri/conf.d/image-policy.yaml",
            "var/lib/rancher/rke2/server/token", "run/immutable-root-test",
        ):
            with self.subTest(writable=relative):
                path = ROOT / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                replacement = path.with_name(path.name + ".new")
                replacement.write_text("runtime state\n")
                replacement.replace(path)
                self.assertEqual(path.read_text(), "runtime state\n")
        for relative in (
            "usr/local/bin/immutable-root-test",
            "opt/nri/plugins/10-nri-image-policy", "etc/hostname", "etc/undeclared",
        ):
            with self.subTest(immutable=relative):
                with self.assertRaises(OSError) as denied:
                    (ROOT / relative).write_text("must not modify the image\n")
                self.assertEqual(denied.exception.errno, errno.EROFS)
        for directory in ("root", "tmp"):
            self.assertEqual(
                stat.S_IMODE((ROOT / directory).stat().st_mode),
                stat.S_IMODE((IMAGE / directory).stat().st_mode),
            )
        self.assertEqual(snapshot(IMAGE), before)

    def test_missing_declared_directory_prevents_switch_root(self):
        shutil.rmtree(IMAGE / "etc/cni")
        before = snapshot(IMAGE)
        booted = run("/bin/bash", "/init-under-test")
        self.assertNotEqual(booted.returncode, 0, booted.stdout)
        self.assertIn("FATAL: state.d: etc/cni listed in 60-c8s.conf", booted.stdout)
        self.assertFalse(Path("/switch-root-args").exists(), booted.stdout)
        self.assertEqual(Path("/proc/sysrq-trigger").read_text(), "b\n")
        self.assertEqual(snapshot(IMAGE), before)


if __name__ == "__main__":
    if not Path("/c8s-immutable-test-root").is_file():
        raise SystemExit("Run immutable-root-test.sh; these tests require its isolated root")
    unittest.main(verbosity=2)
