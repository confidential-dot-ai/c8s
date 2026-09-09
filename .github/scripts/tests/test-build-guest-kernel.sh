#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
confos="$scratch/confos"
guest="$scratch/guest"
mkdir -p "$confos/target/release" "$guest/kernel"
printf 'fragment\n' > "$guest/kernel/container.config"
cat > "$confos/target/release/confos" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == kernel && "$2" == --kernel-config-fragment && -f "$3" ]]
[[ "${RESULT:-}" != failure ]] || exit 17
[[ "${RESULT:-}" != cache-hit ]] || exit 0
mkdir -p output/kernel kernel
[[ "${RESULT:-}" == no-kernel ]] || printf 'kernel\n' > output/kernel/vmlinuz
[[ "${RESULT:-}" == no-snapshot ]] || printf '%s\n' "$RESOLVED" > "$(dirname "$3")/config-x86_64-container.snapshot"
STUB
chmod +x "$confos/target/release/confos"

run_case() {
  local mode=$1 resolved=$2 check=$3 expected=$4
  if [[ "$mode" != cache-hit ]]; then
    rm -rf "$confos/output" "$guest/output"
    rm -f "$guest/kernel/config-x86_64-container.snapshot"
  fi
  # A real confos checkout retains this unrelated bare-kernel baseline.
  mkdir -p "$confos/kernel"
  printf 'bare baseline\n' > "$confos/kernel/config-x86_64.snapshot"
  printf 'committed\n' > "$guest/kernel/config-x86_64.snapshot"
  local status=0
  RESULT="$mode" RESOLVED="$resolved" CHECK_SNAPSHOT="$check" \
    bash "$root/kata-guest-base/scripts/build-kernel.sh" "$confos" "$guest" > "$scratch/log" 2>&1 || status=$?
  if [[ "$expected" == success && "$status" != 0 || "$expected" == failure && "$status" == 0 ]]; then
    cat "$scratch/log" >&2
    echo "unexpected result for $mode/$resolved/$check: $status" >&2
    exit 1
  fi
}

run_case normal committed 1 success
cmp "$confos/output/kernel/vmlinuz" "$guest/output/vmlinuz"
mode=$(stat -c %a "$guest/output/vmlinuz" 2>/dev/null || stat -f %Lp "$guest/output/vmlinuz")
[[ "$mode" == 644 ]]
[[ $(cat "$confos/kernel/config-x86_64.snapshot") == 'bare baseline' ]]
run_case cache-hit ignored 1 success
run_case normal changed 0 success
[[ $(cat "$guest/kernel/config-x86_64.snapshot") == changed ]]
run_case cache-hit ignored 1 failure
grep -q 'resolved kernel config drifted' "$scratch/log"
[[ $(cat "$guest/kernel/config-x86_64.snapshot") == changed ]]
run_case normal changed 1 failure
grep -q 'resolved kernel config drifted' "$scratch/log"
[[ $(cat "$guest/kernel/config-x86_64.snapshot") == changed ]]
run_case no-kernel committed 1 failure
grep -q 'confos did not produce' "$scratch/log"
run_case no-snapshot committed 1 failure
grep -q 'cannot capture the resolved-config snapshot' "$scratch/log"
run_case failure committed 1 failure
[[ ! -e "$guest/output/vmlinuz" ]]
[[ $(cat "$guest/kernel/config-x86_64.snapshot") == committed ]]
printf 'shared guest kernel tests passed\n'

# Exercise the composite's cache probes and ownership-preserving tar commands.
run_step() {
  awk -v name="$1" '
    /^    - name:/ { if (active) exit; active = ($0 == "    - name: " name) }
    active && /^      run: \|/ { body = 1; next }
    active && body { sub(/^        /, ""); print }
  ' "$root/.github/actions/build-guest-kernel/action.yml" > "$scratch/step"
  [[ -s "$scratch/step" ]]
  (cd "$scratch" && bash -euo pipefail "$scratch/step")
}
export GITHUB_OUTPUT="$scratch/outputs" RUNNER_TEMP="$scratch"
export TAR_CALLS="$scratch/tar-calls"
mkdir -p "$scratch/bin" "$scratch/confidential-os-builder/output/kernel"
cat > "$scratch/bin/sudo" <<'STUB'
#!/usr/bin/env bash
[[ "${FAIL_SUDO:-0}" == 0 ]] || exit 19
printf '%s\n' "$*" >> "$TAR_CALLS"
STUB
chmod +x "$scratch/bin/sudo"
export PATH="$scratch/bin:$PATH"
run_step 'Check guest kernel output'
grep -qx complete=false "$GITHUB_OUTPUT"
touch "$scratch/confidential-os-builder/output/kernel/vmlinuz"
: > "$GITHUB_OUTPUT"
run_step 'Check guest kernel output'
grep -qx complete=false "$GITHUB_OUTPUT"
touch "$scratch/confidential-os-builder/output/kernel/manifest.json"
: > "$GITHUB_OUTPUT"
run_step 'Check guest kernel output'
grep -qx complete=false "$GITHUB_OUTPUT"
mkdir -p "$scratch/c8s/kata-guest-base/kernel"
touch "$scratch/c8s/kata-guest-base/kernel/config-x86_64-container.snapshot"
: > "$GITHUB_OUTPUT"
run_step 'Check guest kernel output'
grep -qx complete=true "$GITHUB_OUTPUT"
: > "$GITHUB_OUTPUT"
run_step 'Pack kernel-builder tools tree'
grep -qx exists=false "$GITHUB_OUTPUT"
[[ ! -e "$TAR_CALLS" ]]
mkdir -p "$scratch/confidential-os-builder/mkosi/kernel-builder/mkosi.output"
touch "$scratch/confidential-os-builder/mkosi/kernel-builder/mkosi.output/.confos-tools-stamp"
: > "$GITHUB_OUTPUT"
run_step 'Pack kernel-builder tools tree'
grep -qx exists=true "$GITHUB_OUTPUT"
run_step 'Unpack kernel-builder tools tree'
[[ $(wc -l < "$TAR_CALLS") == 2 ]]
grep -q -- "--numeric-owner --xattrs --xattrs-include=\* -cpf" "$TAR_CALLS"
grep -q -- "--numeric-owner --xattrs --xattrs-include=\* -xpf" "$TAR_CALLS"
printf 'shared kernel cache tests passed\n'

: > "$GITHUB_OUTPUT"
status=0
FAIL_SUDO=1 run_step 'Build guest kernel and check snapshot' || status=$?
[[ "$status" == 19 && ! -s "$GITHUB_OUTPUT" ]]
printf 'kernel staging cleanup failure stops the build\n'
