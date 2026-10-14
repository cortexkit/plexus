# Plexus probe QuickJS guest

This standalone crate compiles QuickJS-NG through `rquickjs` for WASI Preview 1.
The host crate embeds the resulting module so a deployed Plexus binary does not
need a compiler, WASI SDK, or filesystem path at runtime.

From the repository root, rebuild the checked-in module with:

```sh
./scripts/build-probe-guest.sh
```

The script requires the Rust `wasm32-wasip1` target. It downloads and verifies
the pinned WASI SDK 24.0 archive, then passes the extracted SDK to
`rquickjs-sys` through `WASI_SDK`. For an offline build, set `WASI_SDK_ARCHIVE`
to a previously downloaded release archive; the same checksum is verified.
Review and commit guest source and the rebuilt module together.

The script remaps Rust panic locations and QuickJS C file names with
`--remap-path-prefix` and `-ffile-prefix-map`. The source root becomes `/plexus`,
the Cargo target directory `/plexus-target`, `CARGO_HOME` (defaulting to
`$HOME/.cargo`) `/cargo`, and the extracted SDK `/wasi-sdk`. Target-specific
`CFLAGS_wasm32_wasip1` keeps the mappings effective when `rquickjs-sys` sets
generic `CFLAGS` to its sysroot. The workspace test
`sandbox::tests::embedded_guest_has_no_absolute_build_paths` scans the entire
embedded asset, not only the guest's source locations, for home and worktree
paths.

## Build provenance

The checked-in asset was rebuilt on Linux x86_64 with Rust 1.99.0
(`b940084d7 2026-09-28`), the locked guest dependencies, and WASI SDK 24.0.
The SDK archive SHA-256 was
`c6c38aab56e5de88adf6c1ebc9c3ae8da72f88ec2b656fb024eda8d4167a0bc5`.
No guest source, dependency, release-profile or compiler-option changes were
made other than the path mappings.

Two clean builds used separate source roots, Cargo homes, extracted SDKs and
external `CARGO_TARGET_DIR` paths. Both outputs were byte-identical (`cmp`),
1,074,508 bytes, with SHA-256
`43c251d6e6c4d3641ccb837487fa15aae83a7e825860244a9573bcd9a5baf5a0`.
The transferred base64 artifact was decoded and its SHA-256 verified before
installation. The 12 Cargo registry source locations (eight in `rquickjs-core`,
three in `serde_json`, and one in `itoa`) now start with `/cargo/`; the two
QuickJS generated-C locations now start with `/plexus-target/`. Rust's existing
neutral `/rustc/` and `/rust/deps/` locations remain unchanged.

To repeat the path-independence check, prepare two clean copies of the source
with different absolute paths and separate Cargo homes containing the locked
dependencies. In each copy, run:

```sh
CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$target_dir" \
  WASI_SDK_ARCHIVE="$sdk_archive" ./scripts/build-probe-guest.sh
```

Use different absolute `cargo_home` and `target_dir` values for each copy, and
compare their installed `crates/plexus-probe/assets/plexus-probe-guest.wasm`
files with `cmp` and `sha256sum`. Build artifacts and caches must not be shared
between the two copies. The archive may be shared because each build verifies
it and extracts its own SDK.
