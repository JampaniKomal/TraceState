#!/usr/bin/env bash
# Runs the scan for the GitHub Action (action.yml). Inputs arrive as TS_*
# environment variables, never interpolated into the script.
set -uo pipefail

args=(scan "$TS_PATH" --fail-on "$TS_FAIL_ON" --sarif-output "$TS_SARIF" --markdown-output "$TS_MARKDOWN")
while IFS= read -r rule; do
  if [ -n "$rule" ]; then args+=(--rules "$rule"); fi
done <<<"$TS_RULES"
while IFS= read -r glob; do
  if [ -n "$glob" ]; then args+=(--exclude "$glob"); fi
done <<<"$TS_EXCLUDE"
if [ "$TS_NO_DEFAULT_RULES" = true ]; then args+=(--no-default-rules); fi
if [ "$TS_ONLINE" = true ]; then args+=(--online); fi
if [ -n "$TS_LEDGER" ]; then args+=(--ledger "$TS_LEDGER"); else args+=(--no-ledger); fi

tracestate "${args[@]}"
code=$?

{
  echo "exit-code=$code"
  if [ -f "$TS_SARIF" ]; then echo "sarif-file=$TS_SARIF"; fi
  if [ -f "$TS_MARKDOWN" ]; then echo "markdown-file=$TS_MARKDOWN"; fi
} >>"$GITHUB_OUTPUT"

# Report paths are relative to the scanned directory; code scanning wants
# them relative to the repository root.
prefix=${TS_PATH#./}
prefix=${prefix%/}
if [ -f "$TS_SARIF" ] && [ -n "$prefix" ] && [ "$prefix" != . ]; then
  if command -v jq >/dev/null; then
    jq --arg p "$prefix/" '(.runs[].results[]?.locations[]?.physicalLocation.artifactLocation.uri) |= $p + .' \
      "$TS_SARIF" >"$TS_SARIF.tmp" && mv "$TS_SARIF.tmp" "$TS_SARIF"
  else
    echo "::warning::jq not found; SARIF paths stay relative to $TS_PATH"
  fi
fi

# The job summary is limited to 1 MiB per step.
if [ "$TS_SUMMARY" = true ] && [ -f "$TS_MARKDOWN" ] && [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  if [ "$(wc -c <"$TS_MARKDOWN")" -lt 1000000 ]; then
    cat "$TS_MARKDOWN" >>"$GITHUB_STEP_SUMMARY"
  else
    head -c 990000 "$TS_MARKDOWN" >>"$GITHUB_STEP_SUMMARY"
    printf '\n\n_Report truncated; the full report is in %s._\n' "$TS_MARKDOWN" >>"$GITHUB_STEP_SUMMARY"
  fi
fi

exit "$code"
