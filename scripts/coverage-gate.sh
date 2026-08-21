#!/usr/bin/env bash
# coverage-gate.sh — compute and gate Go test coverage.
#
# Usage:
#   scripts/coverage-gate.sh run [profile]        run tests, write coverage profile
#   scripts/coverage-gate.sh total <profile>      print total coverage (e.g. "67.94")
#
# The profile is produced with -coverpkg=./... so packages without their own
# test files are still measured (a brand-new untested package counts as 0%,
# not "absent"). CI compares the PR's total against the base branch's total
# and fails if it decreased.
set -euo pipefail

cmd="${1:-}"
profile="${2:-coverage.out}"

percent() { # per-package coverage table from a coverprofile: "<pct> <stmts> <pkg>"
  awk -F'[ :]' '
    NR==1 {next}
    {
      key=$1":"$2; stmts[key]=$3; if ($4>0) covered[key]=1;
    }
    END {
      for (k in stmts) {
        file=k; sub(/:[^:]*$/, "", file);
        pkg=file; sub(/\/[^\/]*$/, "", pkg);
        tot[pkg]+=stmts[k]; if (covered[k]) cov[pkg]+=stmts[k];
        T+=stmts[k]; if (covered[k]) C+=stmts[k];
      }
      for (p in tot) printf "%.1f %d %s\n", 100*cov[p]/tot[p], tot[p], p;
      # Two decimals: the gate compares this against a tolerance, and at one
      # decimal the smallest representable drop already exceeded it.
      printf "%.2f %d TOTAL\n", (T ? 100*C/T : 0), T;
    }' "$1"
}

case "$cmd" in
run)
  go test ./... -count=1 -coverprofile="$profile" -coverpkg=./...
  ;;
total)
  percent "$profile" | awk '$3=="TOTAL" {print $1}'
  ;;
*)
  echo "usage: $0 {run|total} [profile]" >&2
  exit 2
  ;;
esac
