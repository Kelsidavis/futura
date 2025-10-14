#!/usr/bin/env python3
import hashlib
import json
import subprocess
import sys
from pathlib import Path

if len(sys.argv) != 3:
    print("usage: verify.py <metadata-json> <release-dir>", file=sys.stderr)
    sys.exit(1)

metadata_path = Path(sys.argv[1]).resolve()
release_dir = Path(sys.argv[2]).resolve()

if not metadata_path.is_file():
    print(f"metadata file '{metadata_path}' missing", file=sys.stderr)
    sys.exit(1)
if not release_dir.is_dir():
    print(f"release directory '{release_dir}' missing", file=sys.stderr)
    sys.exit(1)

metadata = json.loads(metadata_path.read_text())
targets = metadata.get("targets", {})

sign_script = Path(__file__).resolve().with_name("sign.sh")

for name, info in targets.items():
    artifact = release_dir / name
    if not artifact.is_file():
        raise SystemExit(f"artifact '{artifact}' missing")

    expected_hash = info.get("sha256")
    expected_size = info.get("size")
    if expected_hash is None or expected_size is None:
        raise SystemExit(f"metadata incomplete for '{name}'")

    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if digest != expected_hash:
        raise SystemExit(f"hash mismatch for '{name}'")

    actual_size = artifact.stat().st_size
    if actual_size != expected_size:
        raise SystemExit(f"size mismatch for '{name}' (expected {expected_size}, got {actual_size})")

    sig_name = info.get("sig")
    if sig_name:
        sig_path = release_dir / sig_name
        if not sig_path.is_file():
            raise SystemExit(f"signature '{sig_path}' missing")
        subprocess.run([str(sign_script), "verify", str(artifact), str(sig_path)], check=True)

print("[verify] hashes and signatures OK")
