#!/usr/bin/env bash
# Installs tracestate for the GitHub Action (action.yml) and puts it on PATH.
#
#   TS_VERSION=latest | vX.Y.Z | source
#
# Release archives are checked against the release's checksums.txt.
set -euo pipefail

version=${TS_VERSION:-latest}
if ! [[ $version =~ ^(latest|source|v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?)$ ]]; then
  echo "::error::version must be latest, source or a release tag such as v2.0.0 (got '$version')"
  exit 2
fi

case "${RUNNER_OS:-Linux}" in
  Linux) os=linux ;;
  macOS) os=darwin ;;
  Windows) os=windows ;;
  *) echo "::error::unsupported runner OS ${RUNNER_OS}"; exit 2 ;;
esac
case "${RUNNER_ARCH:-X64}" in
  X64) arch=amd64 ;;
  ARM64) arch=arm64 ;;
  *) echo "::error::unsupported runner architecture ${RUNNER_ARCH}"; exit 2 ;;
esac

bin_dir="${RUNNER_TEMP:-/tmp}/tracestate/bin"
mkdir -p "$bin_dir"

if [ "$version" = source ]; then
  (cd "$GITHUB_ACTION_PATH" && go build -trimpath -o "$bin_dir/" ./cmd/tracestate)
else
  ext=tar.gz
  if [ "$os" = windows ]; then ext=zip; fi
  asset="tracestate_${os}_${arch}.${ext}"
  base="https://github.com/JampaniKomal/TraceState/releases/download/$version"
  if [ "$version" = latest ]; then
    base="https://github.com/JampaniKomal/TraceState/releases/latest/download"
  fi
  work=$(mktemp -d)
  curl -fsSL --retry 3 -o "$work/$asset" "$base/$asset"
  curl -fsSL --retry 3 -o "$work/checksums.txt" "$base/checksums.txt"
  (
    cd "$work"
    grep "  $asset\$" checksums.txt >expected.txt
    if command -v sha256sum >/dev/null; then sha256sum -c expected.txt; else shasum -a 256 -c expected.txt; fi
  )
  if [ "$ext" = zip ]; then
    unzip -oq "$work/$asset" -d "$work/x"
  else
    mkdir -p "$work/x" && tar -xzf "$work/$asset" -C "$work/x"
  fi
  cp "$work"/x/tracestate* "$bin_dir/"
fi

echo "$bin_dir" >>"$GITHUB_PATH"
"$bin_dir/tracestate" version
