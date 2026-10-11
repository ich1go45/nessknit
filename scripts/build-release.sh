#!/usr/bin/env bash
# Build release archives for every supported platform.
#
#   scripts/build-release.sh VERSION [OUTDIR]
#
# Writes one archive per platform into OUTDIR (default: dist), each
# holding the nessknit binary, README.md and LICENSE, plus a
# checksums.txt of their SHA-256 sums.
set -euo pipefail

version=${1:?usage: scripts/build-release.sh VERSION [OUTDIR]}
outdir=${2:-dist}
root=$(cd "$(dirname "$0")/.." && pwd)

mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}
  arch=${target#*/}
  name="nessknit_${version}_${os}_${arch}"
  stage="$work/$name"
  mkdir -p "$stage"

  binary=nessknit
  if [ "$os" = windows ]; then binary=nessknit.exe; fi

  (cd "$root" && CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
    -ldflags "-s -w -X main.buildVersion=$version" \
    -o "$stage/$binary" ./cmd/nessknit)
  cp "$root/README.md" "$root/LICENSE" "$stage/"

  if [ "$os" = windows ]; then
    (cd "$stage" && zip -q -X "$outdir/$name.zip" "$binary" README.md LICENSE)
  else
    tar -C "$stage" -czf "$outdir/$name.tar.gz" "$binary" README.md LICENSE
  fi
  echo "built $name"
done

(cd "$outdir" && sha256sum nessknit_"${version}"_* > checksums.txt)
echo "checksums written to $outdir/checksums.txt"
