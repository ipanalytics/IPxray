#!/usr/bin/env sh
set -eu

VERSION="${1:-v0.3.0}"
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

build_one() {
  os="$1"
  arch="$2"
  ext=""
  if [ "$os" = "windows" ]; then
    ext=".exe"
  fi

  name="ipxray_${VERSION}_${os}_${arch}"
  out_dir="$DIST_DIR/$name"
  mkdir -p "$out_dir"

  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build \
    -trimpath \
    -ldflags="-s -w -X main.version=$VERSION" \
    -o "$out_dir/ipxray$ext" \
    "$ROOT_DIR/cmd/ipxray"

  cp "$ROOT_DIR/README.md" "$out_dir/README.md"
  cp "$ROOT_DIR/LICENSE" "$out_dir/LICENSE"

  if [ "$os" = "windows" ]; then
    (cd "$DIST_DIR" && zip -qr "$name.zip" "$name")
  else
    (cd "$DIST_DIR" && tar -czf "$name.tar.gz" "$name")
  fi

  rm -rf "$out_dir"
}

build_one linux amd64
build_one linux arm64
build_one darwin amd64
build_one darwin arm64
build_one windows amd64
build_one windows arm64

(cd "$DIST_DIR" && shasum -a 256 ipxray_${VERSION}_* > checksums.txt)

cat > "$DIST_DIR/RELEASE_NOTES.md" <<EOF
# ipxray ${VERSION}

Initial compiled release of ipxray.

## Highlights

- Offline IP/CIDR/ASN resolver after sync
- GitHub release/raw-content sync for ipanalytics datasets
- Evidence -> Fact -> Finding pipeline with provenance
- Coarse confidence: high, medium, low, conflict, unknown
- Text, JSON, YAML, Markdown, and JSONL bulk output
- Traffic-handling profiles for web and firewall use cases

## Artifacts

- linux amd64/arm64
- macOS amd64/arm64
- windows amd64/arm64
- SHA-256 checksums in checksums.txt

EOF

echo "Built release artifacts in $DIST_DIR"
