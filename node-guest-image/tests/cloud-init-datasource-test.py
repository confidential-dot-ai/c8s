#!/usr/bin/env python3
# Semantic gate for the node image's cloud-init datasource pin
# (mkosi.extra/etc/cloud/cloud.cfg.d/99-c8s-datasource.cfg). Runs the
# distro's real DataSourceNoCloud._get_data against the SHIPPED pin and a
# hostile host: a bait cidata disk and cmdline/DMI seed redirects. Asserts the
# baked seed's user-data is the only one cloud-init will execute, and that
# the pin is load-bearing (the same host input wins without it).
#
# No root needed: device/DMI/cmdline reads are faked in-process. Uses the
# system python3 (distro cloud-init package); the asserted precedence rules
# are stable across cloud-init versions, and the metal e2e tripwire covers
# the exact shipped one. Output keeps the tests/lib.sh "FAIL:" prefix
# convention; failure is the exit code.

import os
import shutil
import sys
import tempfile

import yaml  # pyyaml, a cloud-init dependency
from cloudinit import dmi, helpers, util
from cloudinit.sources import DataSourceNoCloud as ncm

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILE = os.path.join(TESTS_DIR, "..", "c8s")
PIN_FILE = os.path.join(
    PROFILE, "mkosi.extra", "etc", "cloud", "cloud.cfg.d",
    "99-c8s-datasource.cfg",
)
BAKED_UD = os.path.join(PROFILE, "user-data")
# confos's inject_cloud_init writes this meta-data next to the baked
# user-data (src/commands/build.rs).
BAKED_MD = "instance-id: confos-sealed\nlocal-hostname: confos\n"
CANONICAL_SEED = "file:///var/lib/cloud/seed/nocloud/"

BAIT_UD = "#cloud-config\nhostname: cidata-bait\nruncmd: [touch /run/host-pwned]\n"
BAIT_MD = "instance-id: i-host\nlocal-hostname: cidata-bait\n"
EVIL_UD = "#cloud-config\nhostname: cmdline-evil\nruncmd: [touch /run/cmdline-pwned]\n"

PASS = 0
FAIL = 0
FAILURES = []
CASE = ""


def ok(desc, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append(f"{CASE}: {desc}")
        print(f"  FAIL: {CASE}: {desc}")


def summarize(title):
    print()
    print(f"==== {title} ====")
    print(f"PASS: {PASS}  FAIL: {FAIL}")
    if FAIL:
        for f in FAILURES:
            print(f"   {f}")
        sys.exit(1)


def stage(work):
    """The baked seed (real user-data + confos meta-data) and a redirect target."""
    seed = os.path.join(work, "seed")
    os.makedirs(os.path.join(seed, "nocloud"))
    shutil.copy(BAKED_UD, os.path.join(seed, "nocloud", "user-data"))
    with open(os.path.join(seed, "nocloud", "meta-data"), "w") as f:
        f.write(BAKED_MD)
    evil = os.path.join(work, "evil")
    os.makedirs(evil)
    with open(os.path.join(evil, "user-data"), "w") as f:
        f.write(EVIL_UD)
    with open(os.path.join(evil, "meta-data"), "w") as f:
        f.write("instance-id: i-evil\n")
    return seed, evil


def resolve(sys_cfg, cmdline="", dmi_serial=None):
    """Run the distro DataSourceNoCloud against a hostile host.

    A bait cidata disk is always attached. Returns (user-data str, scanned
    bool, claimed bool). Host-side reads (DMI, /proc/cmdline, device mount)
    are faked; dmi_serial is a hostile system-serial-number, if given.
    """
    work = tempfile.mkdtemp(prefix="cictl-")
    try:
        seed, evil = stage(work)
        cfg = dict(sys_cfg)
        ds_cfg = cfg.get("datasource", {}).get("NoCloud") or {}
        cfg["datasource"] = {"NoCloud": dict(ds_cfg)}
        sf = cfg["datasource"]["NoCloud"].get("seedfrom")
        if sf:
            cfg["datasource"]["NoCloud"]["seedfrom"] = sf.replace(
                CANONICAL_SEED, f"file://{seed}/nocloud/"
            )
        # Paths derives seed_dir from cloud_dir: the staged seed is on the
        # default search path, as on the node.
        ds = ncm.DataSourceNoCloud(cfg, None, helpers.Paths({"cloud_dir": work}))

        saved = (dmi.read_dmi_data, util.get_cmdline, util.mount_cb)
        scanned = []

        def fake_mount_cb(dev, cb, data):
            return {
                "meta-data": BAIT_MD,
                "user-data": BAIT_UD,
                "vendor-data": None,
                "network-config": None,
            }

        def fake_dmi(key, *a, **k):
            if key == "system-serial-number" and dmi_serial:
                return dmi_serial.replace("EVIL", evil)
            return None

        try:
            dmi.read_dmi_data = fake_dmi
            util.get_cmdline = lambda: cmdline.replace("EVIL", evil)
            util.mount_cb = fake_mount_cb
            ds._get_devices = lambda label: scanned.append(label) or [
                "/dev/fake-cidata"
            ]
            claimed = ds._get_data()
        finally:
            dmi.read_dmi_data, util.get_cmdline, util.mount_cb = saved

        ud = ds.userdata_raw or ""
        if isinstance(ud, bytes):
            ud = ud.decode("utf-8", "replace")
        return ud, bool(scanned), claimed
    finally:
        shutil.rmtree(work)


def main():
    global CASE
    CASE = "pin file present"
    ok(f"{os.path.relpath(PIN_FILE)} exists", os.path.isfile(PIN_FILE))
    if FAIL:
        summarize("cloud-init datasource pin")
    with open(PIN_FILE) as f:
        pin = yaml.safe_load(f)

    CASE = "shipped pin shape"
    ok("datasource_list is exactly [NoCloud]", pin.get("datasource_list") == ["NoCloud"])
    ds_cfg = pin.get("datasource", {}).get("NoCloud", {})
    ok("seedfrom pins the baked seed dir", ds_cfg.get("seedfrom") == CANONICAL_SEED)
    ok("fs_label is null (no device scan)", "fs_label" in ds_cfg and ds_cfg["fs_label"] is None)

    baked_marker = "c8s node cloud-init complete"

    CASE = "unpinned image, host cidata disk"
    ud, scanned, claimed = resolve({})
    ok("datasource claims the guest", claimed)
    ok("bait user-data wins without the pin (attack reproduces)", "cidata-bait" in ud)

    CASE = "pinned image, host cidata disk"
    ud, scanned, claimed = resolve(pin)
    ok("datasource claims the guest", claimed)
    ok("baked user-data wins", baked_marker in ud)
    ok("cidata device never scanned", not scanned)

    CASE = "pinned image, cmdline seed redirect"
    ud, scanned, claimed = resolve(pin, cmdline="root=/dev/dm-0 ro ds=nocloud;s=file://EVIL/ ")
    ok("datasource claims the guest", claimed)
    ok("baked user-data wins", baked_marker in ud)

    CASE = "pinned image, DMI-serial seed redirect"
    ud, scanned, claimed = resolve(pin, dmi_serial="ds=nocloud;s=file://EVIL/")
    ok("datasource claims the guest", claimed)
    ok("baked user-data wins", baked_marker in ud)

    CASE = "unpinned image, cmdline seed redirect"
    ud, scanned, claimed = resolve({}, cmdline="root=/dev/dm-0 ro ds=nocloud;s=file://EVIL/ ")
    ok("datasource claims the guest", claimed)
    ok("redirected seed wins without the pin (pin is load-bearing)", "cmdline-evil" in ud)

    summarize("cloud-init datasource pin")


if __name__ == "__main__":
    main()
