#!/usr/bin/env bash
# Checks that every ground-truth detection for Auditable is still reported.
#
#   scripts/check-benchmark.sh <tracestate-binary> <auditable-checkout> [--online]
#
# Exits non-zero, listing what's missing, if any expected finding is gone.
set -euo pipefail

bin=$1
dir=$2
online=${3:-}
expected="$(dirname "$0")/../docs/benchmark/auditable-expected.txt"

args=(scan "$dir" --no-ledger --format json --fail-on none --quiet)
if [ "$online" = "--online" ]; then
  args+=(--online)
fi
actual=$("$bin" "${args[@]}" | jq -r '.findings[] | "\(.rule_id) \(.file):\(.line // 0)"' | sort -u)

total=0
missing=0
while read -r row rule loc tag; do
  if [ -z "$row" ] || [ "${row:0:1}" = "#" ]; then
    continue
  fi
  if [ "${tag:-}" = "online" ] && [ "$online" != "--online" ]; then
    continue
  fi
  total=$((total + 1))
  if ! grep -qxF "$rule $loc" <<<"$actual"; then
    echo "MISSING $row $rule $loc"
    missing=$((missing + 1))
  fi
done <"$expected"

echo "$((total - missing))/$total ground-truth detections present ($(wc -l <<<"$actual" | tr -d ' ') findings in total)"
[ "$missing" -eq 0 ]
