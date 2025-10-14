#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: sbom.sh <release-dir>" >&2
  exit 1
fi

RELEASE_DIR="$1"
KERNEL_PATH="$RELEASE_DIR/futura_kernel.elf"
TOOLS_SBOM="$RELEASE_DIR/tools.cdx.json"
KERNEL_SBOM="$RELEASE_DIR/futura_kernel.elf.cdx.json"
VERSION="unknown"
HEADER="include/generated/version.h"
if [[ -f "$HEADER" ]]; then
  VERSION=$(grep 'FUT_BUILD_GIT' "$HEADER" | cut -d '"' -f2)
fi

sha256_of() {
  sha256sum "$1" | awk '{print $1}'
}

if [[ ! -f "$KERNEL_PATH" ]]; then
  echo "kernel artifact $KERNEL_PATH missing" >&2
  exit 1
fi

KERNEL_HASH=$(sha256_of "$KERNEL_PATH")
cat >"$KERNEL_SBOM" <<JSON
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "components": [
    {
      "type": "file",
      "name": "futura_kernel.elf",
      "version": "$VERSION",
      "hashes": [ { "alg": "SHA-256", "content": "$KERNEL_HASH" } ]
    }
  ]
}
JSON

components=()
for tool in "mkfutfs.static" "fsck.futfs.static"; do
  path="$RELEASE_DIR/$tool"
  if [[ -f "$path" ]]; then
    hash=$(sha256_of "$path")
    components+=("    {\"type\": \"file\", \"name\": \"$tool\", \"version\": \"$VERSION\", \"hashes\": [ { \"alg\": \"SHA-256\", \"content\": \"$hash\" } ] }")
  fi
done

{
  echo '{'
  echo '  "bomFormat": "CycloneDX",'
  echo '  "specVersion": "1.4",'
  echo '  "version": 1,'
  echo '  "components": ['
for i in "${!components[@]}"; do
  if (( i > 0 )); then
    printf ",\n"
  fi
  printf "%s" "${components[$i]}"
done
if [[ ${#components[@]} -gt 0 ]]; then
  echo
fi
  echo '  ]'
  echo '}'
} >"$TOOLS_SBOM"
