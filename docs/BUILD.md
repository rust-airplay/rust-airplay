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

## Gates

A change is finished when these pass:

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

## The differential test

One suite compares this implementation with UxPlay's own C code: the mirror keystream, the
counter, the audio decryption, the pairing vectors and the FairPlay transforms. It is ignored
by default because it needs a checkout of UxPlay and a compiler for it.

It needs a checkout at commit `57ea83411d5f7e0b38c5841987439340543f025c` in `upstream/UxPlay`
and MSYS2 UCRT64, and then:

```sh
pwsh -File tools/oracle/run.ps1
```

The exit code is the test result. `tools/oracle/README.md` says what each mode prints.

## Playing media

Playing is a backend, not this crate. The GStreamer one is
[rust-airplay-gstream](https://github.com/rust-airplay/rust-airplay-gstream), and building it
needs the GStreamer development files; its README lists them per platform, along with the
elements a session needs at run time.
