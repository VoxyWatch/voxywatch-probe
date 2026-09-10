#!/usr/bin/env bash
# CI builds artifacts only. A release owner verifies both architectures and signs
# their exact SHA-256 hashes separately; this script cannot publish or sign.
set -euo pipefail
version=${BUILD_VERSION:-0.2.1-beta}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9]+([.-][A-Za-z0-9]+)*)?$ ]] || {
  echo 'Invalid BUILD_VERSION' >&2; exit 1;
}
arch=$(go env GOARCH)
case "$(uname -m):$arch" in x86_64:amd64|aarch64:arm64) ;; *) echo 'Native build required' >&2; exit 1;; esac
[ "$arch" = "${EXPECTED_ARCH:-$arch}" ] || { echo 'Unexpected architecture' >&2; exit 1; }
[ "$(go env CGO_ENABLED)" = 1 ] || { echo 'CGO must be enabled' >&2; exit 1; }
go test -race -count=1 ./...
go vet ./...
python3 tools/test_installer.py
bash -n install.sh
mkdir -p dist
asset=voxywatch-probe-linux-$arch
go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$version" -o "dist/$asset" ./cmd/voxywatch-probe
"dist/$asset" -version
(cd dist && sha256sum "$asset" > "$asset.sha256")
printf 'version=%s\narch=%s\ncommit=%s\n' "$version" "$arch" "${GITHUB_SHA:-$(git rev-parse HEAD)}" > "dist/$asset.build-info"
go version >> "dist/$asset.build-info"
ldd --version | sed -n '1p' >> "dist/$asset.build-info"
