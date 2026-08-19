#!/usr/bin/env bash
# check-doc-install-commands.sh — doc/CLI parity gate for the install flows.
#
# Runs every c8s command from the fenced sh blocks of docs/QUICKSTART.md and
# docs/DEMO.md exactly as written (line continuations and heredocs included)
# against a dead kubeconfig. A command passes when it clears flag validation
# and the pre-cluster preflights: exit 0, or a failure whose output shows it
# reached cluster contact. Failing earlier — unknown/invalid/missing flag, a
# preflight refusal, an unreadable values file — fails the gate, so a doc
# command that stops parsing breaks the build.
#
# Usage: scripts/check-doc-install-commands.sh
# PATH must hold the built c8s binary plus helm, kubectl, and openssl.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docs=("$repo_root/docs/QUICKSTART.md" "$repo_root/docs/DEMO.md")

for tool in c8s helm kubectl openssl; do
  command -v "$tool" >/dev/null || { echo "check-doc-install-commands: '$tool' is not on PATH" >&2; exit 2; }
done
for doc in "${docs[@]}"; do
  [[ -f "$doc" ]] || { echo "check-doc-install-commands: $doc is missing" >&2; exit 2; }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The doc commands reference operator-pub.pem relative to the working dir.
openssl ecparam -genkey -name prime256v1 -noout -out "$work/operator.key" 2>/dev/null
openssl ec -in "$work/operator.key" -pubout -out "$work/operator-pub.pem" 2>/dev/null

# A server that refuses instantly, so cluster contact fails fast and
# deterministically.
cat > "$work/kubeconfig" <<'EOF'
apiVersion: v1
kind: Config
clusters: [{name: dead, cluster: {server: https://127.0.0.1:1}}]
users: [{name: dead, user: {token: dead}}]
contexts: [{name: dead, context: {cluster: dead, user: dead}}]
current-context: dead
EOF
export KUBECONFIG="$work/kubeconfig"

# Extract c8s command units from the fenced sh blocks of the docs: a unit
# starts at a line beginning "c8s ", continues over trailing-\ lines, and
# over a heredoc body when the command opens one. Units are separated by a
# 0x1E (record separator) byte.
extract() {
  awk '
    function emit() { printf "%s\036", unit; unit = ""; heredoc = "" }
    /^```/ {
      if (inblock && unit != "") emit()
      inblock = ($0 ~ /^```sh[ \t]*$/)
      next
    }
    !inblock { next }
    {
      if (unit == "" && $0 !~ /^c8s([ \t]|$)/) next
      unit = (unit == "") ? $0 : unit "\n" $0
      if (heredoc != "") { if ($0 == heredoc) emit(); next }
      if ($0 ~ /\\[ \t]*$/) next
      if ($0 ~ /<<-?[ \t]*/) {
        heredoc = $0
        sub(/^.*<<-?[ \t]*/, "", heredoc)
        gsub(/[^A-Za-z0-9_]/, "", heredoc)
        next
      }
      emit()
    }
    END { if (unit != "") emit() }
  ' "$@"
}

# Signatures of a run that reached the cluster-contact stage (kubectl/helm
# reporting the dead server), as opposed to a pre-cluster failure.
cluster_re='was refused|connection refused|Unable to connect|unreachable|no configuration has been provided|i/o timeout'

fail=0
count=0
while IFS= read -r -d $'\036' unit; do
  count=$((count + 1))
  echo "--- doc command #$count"
  echo "$unit"
  set +e
  out="$(cd "$work" && bash -c "$unit" 2>&1)"
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    echo "ok: ran to completion"
  elif grep -Eq "$cluster_re" <<<"$out"; then
    echo "ok: cleared flag validation and preflights (stopped at cluster contact, exit $rc)"
  else
    echo "::error::doc command failed before the cluster stage (exit $rc):"
    echo "$out"
    fail=1
  fi
  echo
done < <(extract "${docs[@]}")

if [[ $count -eq 0 ]]; then
  echo "::error::no c8s commands were extracted from ${docs[*]} — the extractor or the docs are broken" >&2
  exit 1
fi
if [[ $fail -ne 0 ]]; then
  echo "doc install commands FAILED parity (see ::error lines above)" >&2
  exit 1
fi
echo "all $count documented c8s commands cleared flag validation and the pre-cluster preflights"
