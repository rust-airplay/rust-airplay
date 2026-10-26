# Build guide

Chinese: [BUILD.zh-CN.md](BUILD.zh-CN.md).

## Toolchain

The crate needs Rust 1.85 or newer, because it uses edition 2024. The version is pinned in
`Cargo.toml`, so an older toolchain refuses to build with a message saying what it wants
instead of failing inside a macro.

A C linker is needed for Rust itself: the MSVC build tools on Windows, which `rustup`
installs with the default toolchain, and the system compiler elsewhere. This crate links no
C library of its own, and `cargo tree` shows no `-sys` dependency; that is a property worth
keeping, because it is what lets a machine with no media libraries build and test it.

## Reproducibility

`Cargo.lock` is committed. It is what CI, the MSRV job and a release build resolve against, so
a dependency cannot change between the run that passed and the run that publishes. A library
consumer still resolves its own graph; the lock is for this repository's builds.

Change a dependency with `cargo update` (or a direct version edit), run the full gates, and
commit `Cargo.lock` with the change. Do not let CI resolve a different graph by accident.

## Build and test

```sh
cargo build
cargo test
```

`cargo test` runs the unit tests, the integration tests and the doctests. The crate has no
features and no optional dependencies, so there is one build configuration.

## Gates

A change is finished when all of these pass. They run locally and in the repository's CI
workflow; a change is not finished because a branch exists.

```sh
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo test --doc --locked
cargo clippy --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
cargo package --list --locked
```

The last one is not a build: it lists what a published crate would contain, and it is the
cheap way to notice that a new document or example is not in `include` in `Cargo.toml`.

## Tests that are ignored by default

Some tests take a machine that has something this one may not: a long-running measurement, or
minutes of time for a throughput run. Each carries `#[ignore]` and a reason, so
`cargo test -- --ignored` runs them and the default run says how many were skipped.

## Publishing

```sh
cargo package --allow-dirty --locked
```

packages the crate without publishing it, which verifies the `include` list and the metadata
before a release. `cargo publish` is the release step and is done from a clean tree on `main`.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request on Ubuntu, Windows and macOS:
the format check, the tests, the doctests, clippy and rustdoc under `-D warnings`, and
`cargo package --list`, all with `--locked`. A separate job checks the crate on the minimum
supported Rust, so a dependency that raises its own MSRV cannot break the promise quietly. On
Ubuntu the workflow also regenerates `tests/fixtures/` and refuses a diff, so a generator and
its committed files cannot drift apart. Dependabot keeps the Cargo dependencies and the
GitHub Actions tags current.

`Publish to crates.io` is started by hand from the Actions tab. It runs the tests, doctests,
clippy, rustdoc and package listing again, then publishes from `main`. Prefer crates.io
Trusted Publishing (an OIDC identity bound to the repository) once it is configured; the
current workflow uses the `CARGO_REGISTRY_TOKEN` repository secret, which should be scoped to
this repository and rotated. A version bump and a changelog entry are part of the commit that
precedes a publish. `dry_run` packages and verifies without uploading.

## Playing media

Playing is a backend, not this crate. The GStreamer one is
[rust-airplay-gstream](https://github.com/rust-airplay/rust-airplay-gstream), and building it
needs the GStreamer development files; its README lists them per platform, along with the
elements a session needs at run time.
