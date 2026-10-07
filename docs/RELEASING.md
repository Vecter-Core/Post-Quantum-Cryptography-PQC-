# Releasing

Status: pre-release (`0.0.x`), unaudited. Releases publish **files on GitHub**, not packages on
registries: every crate has `publish = false`, and that changes only after an external audit or
a deliberate decision to publish pre-release names.

## What a release contains

`.github/workflows/release.yml` runs for a tag `vX.Y.Z` (or by hand with *Run workflow*, which
builds everything but creates no release):

| Artifact | Contents |
|---|---|
| `vpqc-<platform>.tar.gz` / `.zip` | CLI, C library (`libvpqc_ffi` shared and static), `vpqc.h`; linux x86_64/aarch64, macOS arm64/x86_64, Windows x86_64 |
| `vpqc-linux-x86_64-static.tar.gz` | Fully static CLI (musl): runs on any Linux, no glibc requirement |
| `vpqc-*.whl`, `vpqc-*.tar.gz` | Python: one `abi3` wheel per platform (CPython 3.9+; manylinux 2_28 on Linux), and the sdist. Each wheel is installed and tested before upload |
| `vpqc-core-*.tgz` | npm package `@vpqc/core` (WebAssembly for Node and browsers); tested before packing |
| `Vecter.Vpqc.*.nupkg` | NuGet package with the native libraries for 5 runtime identifiers under `runtimes/` |
| `sbom-*.cdx.json` | CycloneDX 1.5 software bills of materials (CLI, TLS sidecar, C library): every dependency of the binaries, validated against the official schema |
| `cbom-vpqc.cdx.json` | CycloneDX 1.6 cryptographic bill of materials of the project's own source (which algorithms vpqc itself uses) |
| `SHA256SUMS` | Checksums of all of the above |

Every file also gets a build provenance attestation (GitHub artifact attestations). Verify a
download with `gh attestation verify FILE --repo Vecter-Core/Post-Quantum-Cryptography-PQC-`
and `sha256sum -c SHA256SUMS`.

A tag creates a GitHub **pre-release** with these files.

## Cutting a release

1. Update `CHANGELOG.md`, and the version in `Cargo.toml` (`[workspace.package]` and the path
   dependency versions), `bindings/*/` manifests (`pyproject.toml`, `bindings/js/package.json`,
   `bindings/dotnet/src/Vpqc.csproj`, Java `pom.xml`, the gems and composer files) to the same
   `X.Y.Z`.
2. Run the manual dry run: *Actions → release → Run workflow* on the branch. It must be green.
3. Merge, then `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. Check the pre-release page; verify one artifact with the commands above.

## Publishing to registries (not automated)

Not done by the workflow, on purpose. When the time comes, from the release artifacts:

- PyPI: use trusted publishing (OIDC) with `pypa/gh-action-pypi-publish` in a separate workflow
  bound to a protected environment; upload the wheels and sdist from the release.
- npm: `npm publish --provenance --access public` on the tarball.
- NuGet: `dotnet nuget push` with an API key stored as an environment secret.
- crates.io: remove `publish = false` crate by crate, in dependency order (`vpqc-core`,
  `vpqc-backend-libcrux`, `vpqc-hybrid`, `vpqc-format`, `vpqc-hpke`, `vpqc`, ...). Run
  `cargo publish --dry-run` first.

Publishing names on a registry is hard to undo: do it only for a version you are willing to
support.

## Reproducible builds

`scripts/repro-check.sh` (CI job *reproducible build*) builds the CLI twice from two different
directories and requires byte-identical binaries (`--locked`, path remapping, no incremental
state). The release builds use the same path remapping. Verified for the static Linux (musl)
CLI; glibc, macOS and Windows builds embed toolchain-specific data and are not checked.

## Reproducing a build locally

```sh
cargo build --release --locked -p vpqc-cli -p vpqc-ffi
(cd bindings/python && maturin build --release --locked --out dist)
(cd bindings/js && sh scripts/build.sh && npm pack)
(cd bindings/dotnet/src && dotnet pack -c Release)   # add runtimes/<rid>/native/* first
```

`--locked` makes the build use exactly `Cargo.lock`; `cargo deny check` (CI job *supply chain*)
guards the dependency set.
