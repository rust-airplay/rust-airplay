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

`cargo test` 会跑单元测试、集成测试与 doctest。crate 没有 feature、没有可选依赖，所以只有一种构建配置。

## 门禁

改动完成前必须全部通过。这些在本地运行；本仓库没有 CI 工作流，分支存在不等于改动完成。

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo package --list
```

最后一条不是构建：它列出发布出去的 crate 会包含什么，是发现新文档或新示例漏进 `Cargo.toml` 的 `include` 的最省事办法。

## 默认忽略的测试

有些测试需要这台机器未必有的东西：一次长时间的测量，或者几分钟的吞吐测量时间。它们都带 `#[ignore]` 和原因，`cargo test -- --ignored` 会运行它们，默认运行会说明跳过了多少。

## 发布

```sh
cargo package --allow-dirty
```

打包但不发布，用来在发布前验证 `include` 列表与元数据。`cargo publish` 是发布步骤，在干净的 `main` 工作树上执行。

## 持续集成

`.github/workflows/ci.yml` 在每次 push 和 pull request 时于 Ubuntu 与 Windows 运行：格式检查、测试、doctest、`-D warnings` 下的 clippy 与 rustdoc，以及 `cargo package --list`。

`Publish to crates.io` 由 Actions 页面手动触发。它会重新运行测试与 clippy，然后从 `main` 用仓库 secret `CARGO_REGISTRY_TOKEN` 发布。`dry_run` 只打包与校验，不上传。发布前的提交应包含版本号与变更日志。

## 播放媒体

播放属于后端，不属于这个 crate。GStreamer 后端是 [rust-airplay-gstream](https://github.com/rust-airplay/rust-airplay-gstream)，构建它需要 GStreamer 开发库；它的 README 按平台列出了依赖，以及运行时会话所需的元素。
