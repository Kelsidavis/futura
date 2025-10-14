#!/usr/bin/env python3
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path

if len(sys.argv) != 2:
    print("usage: metadata.py <release-dir>", file=sys.stderr)
    sys.exit(1)

release_dir = Path(sys.argv[1]).resolve()
if not release_dir.is_dir():
    print(f"release directory '{release_dir}' not found", file=sys.stderr)
    sys.exit(1)

source_epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "1700000000"))
timestamp = datetime.datetime.utcfromtimestamp(source_epoch).strftime("%Y-%m-%dT%H:%M:%SZ")

def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

entries = {}
for item in sorted(release_dir.iterdir()):
    if not item.is_file():
        continue
    name = item.name
    if name.endswith('.sig') or name == 'targets.json':
        continue
    digest = file_sha256(item)
    size = item.stat().st_size
    sig_name = f"{name}.sig"
    entry = {
        "sha256": digest,
        "size": size,
    }
    if (release_dir / sig_name).exists():
        entry["sig"] = sig_name
    entries[name] = entry

metadata = {
    "version": 1,
    "timestamp": timestamp,
    "targets": entries,
}

json.dump(metadata, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
