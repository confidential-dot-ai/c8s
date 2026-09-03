import io
import importlib.util
import pathlib
import sys
import tarfile
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("extract-consumer-profile.py")
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("extract_consumer_profile", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ExtractConsumerProfileTests(unittest.TestCase):
    def profile_files(self):
        mkosi = (
            b"# Consumer profile: persistent RKE2 control-plane state.\n"
            b"#\n"
            b"# Use this profile with the Confidential OS Builder c8s profile. The files in\n"
            b"# mkosi.extra become part of the measured, read-only node image.\n\n"
            b"[Content]\nPackages=\n    e2fsprogs\n    util-linux\n"
        )
        return {
            name: mkosi if name == "mkosi.conf" else f"fixture:{name}\n".encode()
            for name in MODULE.EXPECTED_FILES
        }

    def archive(self, directory, files, extra=None):
        path = pathlib.Path(directory) / "profile.tar"
        with tarfile.open(path, "w:") as output:
            for name, content in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                output.addfile(member, io.BytesIO(content))
            if extra is not None:
                output.addfile(extra)
        return path

    def test_extracts_exact_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = self.archive(temporary, self.profile_files())
            destination = pathlib.Path(temporary) / "out"
            MODULE.extract(archive, destination)
            self.assertEqual(
                (destination / "mkosi.conf").read_bytes(),
                self.profile_files()["mkosi.conf"],
            )

    def test_rejects_missing_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            files = self.profile_files()
            files.pop(next(iter(files)))
            archive = self.archive(temporary, files)
            with self.assertRaisesRegex(ValueError, "incomplete"):
                MODULE.extract(archive, pathlib.Path(temporary) / "out")

    def test_rejects_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            extra = tarfile.TarInfo("link")
            extra.type = tarfile.SYMTYPE
            extra.linkname = "/etc/shadow"
            archive = self.archive(temporary, self.profile_files(), extra)
            with self.assertRaisesRegex(ValueError, "unexpected"):
                MODULE.extract(archive, pathlib.Path(temporary) / "out")

    def test_rejects_changed_mkosi_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            files = self.profile_files()
            files["mkosi.conf"] += b"\n[Build]\nBuildScripts=steal-key\n"
            archive = self.archive(temporary, files)
            with self.assertRaisesRegex(ValueError, "packages-only"):
                MODULE.extract(archive, pathlib.Path(temporary) / "out")


if __name__ == "__main__":
    unittest.main()
