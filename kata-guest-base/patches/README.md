# kata source patches

Patches applied to the kata-containers tree at `KATA_SRC_COMMIT` before
osbuilder compiles kata-agent into the guest rootfs. `scripts/build.sh` applies
every `*.patch` here with `patch -p1 --forward --batch` right after the tarball
is extracted, and a rejected hunk fails the build: the guest is measured, so
shipping one silently un-patched would mean the launch digest no longer implies
the behaviour this repo documents.

They live in-tree rather than in a kata fork because the build already consumes
upstream as a pinned tarball (`gh api .../tarball/${KATA_SRC_COMMIT}`), and a
fork would add a second thing to bump on every kata upgrade. A patch is also
the reviewable unit: it shows up in the diff of the PR that needs it.

Each patch should be upstreamable, and carried only until the pin moves past
it. Rebasing is the cost of a kata bump — expected, and loud when it is due.
