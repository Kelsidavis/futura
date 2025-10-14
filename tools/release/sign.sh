#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: sign.sh <sign|verify> <artifact> <signature>" >&2
  exit 1
fi

CMD="$1"
ARTIFACT="$2"
SIGNATURE="$3"
COSIGN_BIN="${COSIGN:-cosign}"

case "$CMD" in
  sign)
    if [[ -n "${COSIGN_KEY:-}" ]]; then
      "$COSIGN_BIN" sign-blob --key "$COSIGN_KEY" --output-signature "$SIGNATURE" "$ARTIFACT"
    else
      "$COSIGN_BIN" sign-blob --output-signature "$SIGNATURE" "$ARTIFACT"
    fi
    ;;
  verify)
    if [[ ! -f "$SIGNATURE" ]]; then
      echo "signature $SIGNATURE missing" >&2
      exit 1
    fi
    if [[ -n "${COSIGN_PUB:-}" ]]; then
      "$COSIGN_BIN" verify-blob --key "$COSIGN_PUB" --signature "$SIGNATURE" "$ARTIFACT"
    else
      "$COSIGN_BIN" verify-blob --signature "$SIGNATURE" "$ARTIFACT"
    fi
    ;;
  *)
    echo "unknown command: $CMD" >&2
    exit 1
    ;;
 esac
