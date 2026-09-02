import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "bump-pins.py"


class BumpPinsTests(unittest.TestCase):
    OLD_CONFOS = "1" * 40
    OLD_ATTEST = "2" * 40
    OLD_MKOSI = "3" * 40
    NEW_CONFOS = "a" * 40
    NEW_ATTEST = "b" * 40
    NEW_MKOSI = "c" * 40
    UNRELATED_REF = "4" * 40

    def run_bump(self, filename, contents, *, confos=None, attest=None, mkosi=None):
        confos = self.NEW_CONFOS if confos is None else confos
        attest = self.NEW_ATTEST if attest is None else attest
        mkosi = self.NEW_MKOSI if mkosi is None else mkosi
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / filename
            path.write_text(contents)
            before = path.read_bytes()
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--confos",
                    confos,
                    "--attest",
                    attest,
                    "--mkosi-sha",
                    mkosi,
                    "--mkosi-ver",
                    "v28",
                    "--date",
                    "2026-09-02",
                    str(path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            return result, before, path.read_bytes()

    def c8s_image(self, confos=None, attest=None, mkosi=None):
        confos = confos or self.OLD_CONFOS
        attest = attest or self.OLD_ATTEST
        mkosi = mkosi or self.OLD_MKOSI
        return f"""\
env:
  CONFOS_REF: ${{{{ inputs.confos_ref || '{confos}' }}}} # old pin
  ATTESTATION_RS_REF: "{attest}" # old pin
jobs:
  build:
    steps:
      - name: Unrelated action
        uses: example/unrelated-action@v1
        with:
          ref: {self.UNRELATED_REF} # v99
      - name: Setup mkosi
        uses: ./c8s/.github/actions/setup-mkosi
        # A comment between the action and its inputs is harmless.
        with:
          # The ref remains semantically attached to setup-mkosi.
          ref: {mkosi} # v27
"""

    def test_local_setup_mkosi_ref_is_scoped_to_its_action(self):
        result, _, after = self.run_bump("c8s-image.yml", self.c8s_image())

        self.assertEqual(result.returncode, 0, result.stderr)
        rewritten = after.decode()
        self.assertIn(f"ref: {self.NEW_MKOSI} # v28", rewritten)
        self.assertIn(f"ref: {self.UNRELATED_REF} # v99", rewritten)
        self.assertIn("bumped 3 sites", result.stdout)

    def test_unrelated_versioned_ref_cannot_replace_missing_mkosi_pin(self):
        contents = self.c8s_image().replace(
            "      - name: Setup mkosi\n"
            "        uses: ./c8s/.github/actions/setup-mkosi\n"
            "        # A comment between the action and its inputs is harmless.\n"
            "        with:\n"
            "          # The ref remains semantically attached to setup-mkosi.\n"
            f"          ref: {self.OLD_MKOSI} # v27\n",
            "",
        )

        result, before, after = self.run_bump("c8s-image.yml", contents)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("recognized 2 pin sites, expected 3", result.stderr)
        self.assertEqual(after, before)

    def test_upstream_mkosi_action_is_rewritten_without_touching_other_refs(self):
        contents = f"""\
env:
  CONFOS_REF: "{self.OLD_CONFOS}" # old pin
  ATTESTATION_RS_REF: "{self.OLD_ATTEST}" # old pin
jobs:
  build:
    steps:
      - name: Unrelated action
        uses: example/unrelated-action@v1
        with:
          ref: {self.UNRELATED_REF} # v99
      - name: Setup mkosi
        uses: systemd/mkosi@{self.OLD_MKOSI} # v27
"""

        result, _, after = self.run_bump("kata-guest-base.yml", contents)

        self.assertEqual(result.returncode, 0, result.stderr)
        rewritten = after.decode()
        self.assertIn(f"uses: systemd/mkosi@{self.NEW_MKOSI} # v28", rewritten)
        self.assertIn(f"ref: {self.UNRELATED_REF} # v99", rewritten)
        self.assertIn("bumped 3 sites", result.stdout)

    def test_kernel_snapshot_rewrites_both_defaults_and_named_mkosi_step(self):
        contents = f"""\
on:
  workflow_dispatch:
    inputs:
      confos_ref:
        description: confos commit/ref
        required: false
        type: string
        default: "{self.OLD_CONFOS}" # old pin
  workflow_call:
    inputs:
      confos_ref:
        description: confos commit/ref
        required: false
        type: string
        default: "{self.OLD_CONFOS}" # old pin
jobs:
  kernel:
    steps:
      - name: Setup mkosi
        uses: systemd/mkosi@{self.OLD_MKOSI} # v27
"""

        result, _, after = self.run_bump("kernel-snapshot.yml", contents)

        self.assertEqual(result.returncode, 0, result.stderr)
        rewritten = after.decode()
        self.assertEqual(rewritten.count(f'default: "{self.NEW_CONFOS}"'), 2)
        self.assertIn(f"uses: systemd/mkosi@{self.NEW_MKOSI} # v28", rewritten)
        self.assertIn("bumped 3 sites", result.stdout)

    def test_malformed_source_sha_fails_without_partial_write(self):
        contents = self.c8s_image().replace(
            f"ref: {self.OLD_MKOSI} # v27",
            "ref: not-a-full-sha # v27",
        )

        result, before, after = self.run_bump("c8s-image.yml", contents)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("recognized 2 pin sites, expected 3", result.stderr)
        self.assertEqual(after, before)

    def test_malformed_target_sha_is_rejected_without_writing(self):
        contents = self.c8s_image()

        result, before, after = self.run_bump(
            "c8s-image.yml", contents, mkosi="not-a-full-sha"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a full 40-hex sha", result.stderr)
        self.assertEqual(after, before)

    def test_no_drift_leaves_file_byte_identical(self):
        contents = self.c8s_image(
            confos=self.NEW_CONFOS,
            attest=self.NEW_ATTEST,
            mkosi=self.NEW_MKOSI,
        )

        result, before, after = self.run_bump("c8s-image.yml", contents)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "no-drift")
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
