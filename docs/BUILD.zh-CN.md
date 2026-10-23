# 构建指南

English: [BUILD.md](BUILD.md)。

## 工具链

需要 Rust 1.85 或更新版本，因为使用了 edition 2024。版本固定在 `Cargo.toml` 里，太旧的工具链会直接说明它需要哪个版本，而不是在某个宏内部报一个看不懂的错。

C 链接器是 Rust 本身需要的：Windows 上是 MSVC 构建工具，`rustup` 装默认工具链时一并装好；其他平台用系统编译器。这个 crate 自己不链接任何 C 库，`cargo tree` 里也没有 `-sys` 依赖——这个性质值得保持，因为它让没有媒体库的机器照样能构建与测试。

## 构建与测试

```sh
cargo build
cargo test
```

## 门禁

改动完成前必须通过：

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

## 差分测试

有一组测试把本实现与 UxPlay 自身的 C 代码对比：镜像密钥流、计数器、音频解密、配对向量与 FairPlay 变换。它默认被忽略，因为需要 UxPlay 的检出以及编译它的编译器。

需要 `upstream/UxPlay` 下提交 `517cbb1240d9b9f69330c55b957cdd52b4175b2a` 的检出，以及 MSYS2 UCRT64，然后：

```sh
pwsh -File tools/oracle/run.ps1
```

退出码即测试结果。各模式打印什么见 `tools/oracle/README.md`。

## 播放媒体

播放属于后端，不属于这个 crate。GStreamer 后端是 [rust-airplay-gstream](https://github.com/rust-airplay/rust-airplay-gstream)，构建它需要 GStreamer 开发库；它的 README 按平台列出了依赖，以及运行时会话所需的元素。
