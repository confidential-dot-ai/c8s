#!/usr/bin/env python3
"""Rewrite the confos / attestation-rs / mkosi source pins in workflow files.

Used by confos-pin-watch.yml; runnable (and testable) locally:

    .github/scripts/bump-pins.py --confos <sha40> --attest <sha40> \
        --mkosi-sha <sha40> --mkosi-ver v27 --date 2026-09-02 \
        .github/workflows/c8s-image.yml

A pin whose SHA already matches is left byte-identical (comment included),
so "did anything change" is exactly "did a SHA change" — a scheduled run
with no upstream drift rewrites nothing and prints `no-drift`.

Every file must yield its expected number of recognized pin sites, counted
whether or not they change (the sync-c8s-pins sub_once principle): a
hand-reformatted pin line fails this script loudly instead of shipping a
PR that silently half-bumped. Update EXPECTED alongside any pin-site move.

Mkosi pins are file-specific and action-scoped: direct systemd/mkosi uses are
matched separately from the local setup-mkosi action's ref input. An unrelated
version-commented ref never satisfies the mkosi pin count.
"""

import argparse
import re
import sys

HEX = r"[0-9a-f]{40}"

# Recognized pin sites per file. bump() FATALs on any mismatch, so moving
# or adding a pin site must update this table in the same commit.
EXPECTED = {
    "c8s-image.yml": 3,        # CONFOS_REF (dispatch form), ATTESTATION_RS_REF, setup-mkosi ref
    "kata-guest-base.yml": 3,  # CONFOS_REF (quoted), ATTESTATION_RS_REF, systemd/mkosi uses
    "kernel-snapshot.yml": 3,  # confos_ref default x2 (dispatch + call), systemd/mkosi uses
}

# Keep mkosi rewrites tied to the action that consumes the pin. In particular,
# a generic `ref: <sha> # vN` may belong to any action and must never count as
# the c8s-image mkosi pin merely because it has the same textual shape.
LOCAL_MKOSI_PATTERN = (
    rf"(?P<pre>^[ \t]*uses:[ \t]+\./c8s/\.github/actions/setup-mkosi[ \t]*(?:#[^\n]*)?\n"
    rf"(?:^[ \t]*(?:#[^\n]*)?\n){{0,5}}"
    rf"^[ \t]*with:[ \t]*(?:#[^\n]*)?\n"
    rf"(?:^[ \t]*(?:#[^\n]*)?\n){{0,5}}"
    rf"^[ \t]*ref:[ \t]*)(?P<sha>{HEX})( # v[0-9.]+)$"
)
UPSTREAM_MKOSI_PATTERN = (
    rf"^(?P<pre>[ \t]*uses:[ \t]+systemd/mkosi@)(?P<sha>{HEX})( # v[0-9.]+)$"
)
MKOSI_PATTERNS = {
    "c8s-image.yml": LOCAL_MKOSI_PATTERN,
    "kata-guest-base.yml": UPSTREAM_MKOSI_PATTERN,
    "kernel-snapshot.yml": UPSTREAM_MKOSI_PATTERN,
}


def rewrite(text, pattern, new_sha, tail):
    """Substitute sites whose SHA differs; count all recognized sites."""
    found = replaced = 0

    def repl(m):
        nonlocal found, replaced
        found += 1
        if m.group("sha") == new_sha:
            return m.group(0)
        replaced += 1
        return m.group("pre") + new_sha + tail

    return re.sub(pattern, repl, text, flags=re.M), found, replaced


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--confos", required=True, help="confos main sha (full)")
    ap.add_argument("--attest", required=True, help="attestation-rs main sha (full)")
    ap.add_argument("--mkosi-sha", required=True, help="mkosi sha from that confos commit's base.yml")
    ap.add_argument("--mkosi-ver", required=True, help="mkosi version comment, e.g. v27")
    ap.add_argument("--date", required=True, help="UTC date for the pin comment")
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    for v in (a.confos, a.attest, a.mkosi_sha):
        if not re.fullmatch(HEX, v):
            sys.exit(f"error: not a full 40-hex sha: {v!r}")

    note = f"# pin: main {a.date} (pin-watch) — review the upstream log for what rolls"
    # (pattern, target sha, replacement tail appended after the sha)
    dol = "$"  # keep the literal Actions expression out of grep'able source
    common_rules = [
        (rf"^(?P<pre>\s*CONFOS_REF: \{dol}\{{\{{ inputs\.confos_ref \|\| ')(?P<sha>{HEX})(' \}}\}}) *(#.*)?$",
         a.confos, "' }} " + note),
        (rf'^(?P<pre>\s*CONFOS_REF: ")(?P<sha>{HEX})(") *(#.*)?$', a.confos, '" ' + note),
        (rf'^(?P<pre>\s*ATTESTATION_RS_REF: ")(?P<sha>{HEX})(") *(#.*)?$', a.attest, '" ' + note),
        # workflow input defaults, anchored to the confos_ref input block so a
        # future unrelated hex default can never be rewritten to confos's sha
        (rf'(?P<pre>confos_ref:(?:\n[^\n]*){{0,5}}?\n\s*default: ")(?P<sha>{HEX})("[^\n]*)',
         a.confos, '" ' + note),
    ]

    total_replaced = 0
    for path in a.files:
        text = open(path).read()
        base = path.rsplit("/", 1)[-1]
        rules = list(common_rules)
        mkosi_pattern = MKOSI_PATTERNS.get(base)
        if mkosi_pattern is not None:
            rules.append((mkosi_pattern, a.mkosi_sha, f" # {a.mkosi_ver}"))
        found_total = replaced_total = 0
        for pattern, sha, tail in rules:
            text, found, replaced = rewrite(text, pattern, sha, tail)
            found_total += found
            replaced_total += replaced
        want = EXPECTED.get(base)
        if want is not None and found_total != want:
            sys.exit(f"error: {path}: recognized {found_total} pin sites, expected {want} — "
                     "a pin line moved or was reformatted; fix the pattern or EXPECTED")
        if want is None and found_total == 0:
            sys.exit(f"error: {path}: no recognized pin sites")
        if replaced_total:
            open(path, "w").write(text)
            print(f"{path}: {replaced_total}/{found_total} pin sites bumped")
        total_replaced += replaced_total

    print("no-drift" if total_replaced == 0 else f"bumped {total_replaced} sites")


if __name__ == "__main__":
    main()
