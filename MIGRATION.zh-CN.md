# 迁移：一个工作区拆成四个仓库

English: [MIGRATION.md](MIGRATION.md)。

本仓库原先是一个包含三个 crate 的工作区：库、命令行接收端与 GStreamer 后端。现在它只是库，别的不含。另外两个 crate 各自成仓库，桌面客户端会跟在它们之后。

## 留在这里的

```
src/                    库
tests/                  协议与集成测试，以及其 fixtures
docs/                   API、构建指南、架构、后端指南，中英双语
examples/               一个完整的渲染器实现
tools/                  生成测试 fixtures 的辅助脚本
```

程序运行接收端所需的一切都在这里：发现、控制协议、配对、FairPlay、流解密、组帧、时序交换、节流，以及 `Renderer` 边界。解码与播放由后端仓库负责。

## 移出去的

| 移出 | 去向 | 说明 |
| --- | --- | --- |
| `crates/rust-airplay-gstreamer` | `https://github.com/rust-airplay/rust-airplay-gstream` | 更名为 `rust-airplay-gstream`；库名为 `rust_airplay_gstream` |
| `tools/eld_probe.c` | 同一个后端仓库 | 它是解码器诊断，应该紧挨解码器 |
| `crates/rust-airplay-cli` | `https://github.com/rust-airplay/parlor-cli` | 包名 `parlor-cli`，二进制 `parlor` |

后端与客户端通过 Git 依赖本库，而不是路径：

```toml
rust-airplay = { git = "https://github.com/rust-airplay/rust-airplay", branch = "main" }
```

这意味着首次推送的顺序有意义：先本仓库，再后端，最后客户端。在本仓库到远端之前，另两个仓库的 `cargo build` 会在解析依赖时失败——那不是代码问题。

## 本 crate 的变化

- 包就是工作区根。没有 `[workspace]` 表，也没有 `crates/` 目录：`cargo build`、`cargo test` 与各项门禁都在根目录运行。
- 不再提交 `Cargo.lock`。被其他 crate 依赖的库不应该替它们锁定依赖版本。
- 仓库与包元数据指向 `github.com/rust-airplay/rust-airplay`。
- `Renderer` 边界现在携带编码：`VideoConfig::codec` 为 `H264` 或 `H265`，从客户端发送的 codec 包读出。后端据此选择 parser 与解码器，会话中途切换编码不会被漏掉。
- 视频流在第一帧才打开，而不是连接建立时打开，因为客户端的 codec 配置在首帧之前到达，那是编码第一次可知的时刻。
- 文档只描述库。命令行选项移到客户端的 README。

## 门禁

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo package --list
```
