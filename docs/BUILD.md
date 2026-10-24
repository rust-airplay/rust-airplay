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

## Build and test

```sh
cargo build
cargo test
```

`cargo test` runs the unit tests, the integration tests and the doctests. The crate has no
features and no optional dependencies, so there is one build configuration.

## Gates

A change is finished when all of these pass. They run locally; this repository has no CI
workflow, and a change is not finished because a branch exists.

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo package --list
```

The last one is not a build: it lists what a published crate would contain, and it is the
cheap way to notice that a new document or example is not in `include` in `Cargo.toml`.

## Tests that are ignored by default

Some tests take a machine that has something this one may not: a long-running measurement, or
minutes of time for a throughput run. Each carries `#[ignore]` and a reason, so
`cargo test -- --ignored` runs them and the default run says how many were skipped.

## Publishing

```sh
cargo package --allow-dirty
```

packages the crate without publishing it, which verifies the `include` list and the metadata
before a release. `cargo publish` is the release step and is done from a clean tree on `main`.

## Playing media

Playing is a backend, not this crate. The GStreamer one is
[rust-airplay-gstream](https://github.com/rust-airplay/rust-airplay-gstream), and building it
needs the GStreamer development files; its README lists them per platform, along with the
elements a session needs at run time.
