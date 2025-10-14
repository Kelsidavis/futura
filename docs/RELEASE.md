# Release Pipeline

This repository ships a minimal, auditable release pipeline built entirely from
make targets and small helper scripts. The flow below keeps artifacts
reproducible, signed, and catalogued with SBOM + TUF-style metadata.

## Quick start

```bash
make repro            # sanity check: deterministic kernel + tooling builds
make release          # produce build/release/{futura_kernel.elf,...}
make sbom             # emit CycloneDX SBOMs alongside the artifacts
make sign             # cosign each artifact (certificate or key material via env)
make metadata         # generate build/release/targets.json (hashes + sig pointers)
make verify           # re-run reproducibility check and verify signatures/hashes
```

`make verify` prints `[RELEASE] all artifacts verified and reproducible` once all
checks pass. The individual steps are idempotent; feel free to iterate on
artifacts and re-run the pipeline as needed.

## Keys and cosign

The signing helpers wrap `cosign sign-blob` / `verify-blob`. Provide credentials
via environment variables:

- `COSIGN_KEY` / `COSIGN_PUB` for key-based signing.
- `COSIGN_EXPERIMENTAL=1` to enable keyless (OIDC) signing flows.

If the variables are absent the scripts fall back to keyless behaviour.

## SOURCE_DATE_EPOCH

Deterministic builds honour `SOURCE_DATE_EPOCH` (default `1700000000`). Override
it when cutting a release:

```bash
SOURCE_DATE_EPOCH=$(date -u +%s) make release sbom sign metadata verify
```

The timestamp feeds both the generated version header and the `targets.json`
metadata.

## Generated outputs

`make release` populates `build/release/` with:

- `futura_kernel.elf` – stripped kernel ELF
- `futura.iso` – bootable GRUB ISO (if `grub-mkrescue` is available)
- `mkfutfs.static`, `fsck.futfs.static` – statically linked tooling
- `futura_kernel.elf.cdx.json`, `tools.cdx.json` – CycloneDX SBOMs
- `*.sig` – cosign signatures (one per artifact, emitted by `make sign`)
- `targets.json` – TUF-style metadata (hashes, sizes, signature references)

Use `tools/release/verify.py` to validate metadata + signatures, or the `make
verify` wrapper which additionally re-runs the reproducibility guard.

## CI helpers

Two convenience targets are provided for automation:

- `make repro-ci` – alias for `make repro`
- `make release-ci` – performs a clean release + sbom + sign + metadata + verify

Both targets fail on any mismatch, signature error, or build drift.
