# 迁移：一个工作区拆成四个仓库

English: [MIGRATION.md](MIGRATION.md)。

这个仓库原本是一个工作区，装着三个 crate：库、命令行接收端、GStreamer 后端。现在它只是库，仅此而已。另外两个 crate 各自独立成仓库，桌面客户端随后跟进。

## 留在这里的

```
src/                    库
tests/                  协议测试与差分测试，以及它们的数据文件
docs/                   API、构建指南、架构，中英各一份
tools/oracle/           差分测试所对比的 C oracle
tools/plist_fixtures.py
upstream/               oracle 构建所用的 UxPlay 检出，不入库
```

运行一个接收端所需的一切都在这里：发现、控制协议、配对、FairPlay、流解密、组帧、时钟交换、节奏控制，以及 `Renderer` 边界。不在这里的是解码与播放。

## 移走的

| 内容 | 去向 | 说明 |
| --- | --- | --- |
| `crates/rust-airplay-gstreamer` | `https://github.com/rust-airplay/rust-airplay-gstream` | 更名为 `rust-airplay-gstream`，库名 `rust_airplay_gstream` |
| `tools/eld_probe.c` | 同上，后端仓库 | 它是解码诊断工具，应当与解码器放在一起 |
| `crates/rust-airplay-cli` | `https://github.com/rust-airplay/parlor-cli` | 包名 `parlor-cli`，可执行文件 `parlor` |

后端与客户端通过 Git 依赖本库，而不是路径依赖：

```toml
rust-airplay = { git = "https://github.com/rust-airplay/rust-airplay", branch = "main" }
```

因此首次推送的顺序很重要：本仓库、后端、客户端。在本仓库推送之前，另外两个仓库的 `cargo build` 会在解析依赖时失败——这不是代码问题。

## 本 crate 的变化

- 包就是仓库根目录。没有 `[workspace]` 表，也没有 `crates/`：`cargo build`、`cargo test` 与三条门禁都从根目录跑。
- 不再提交 `Cargo.lock`。被其他 crate 依赖的库不应替它们锁定版本。
- 仓库与包元数据指向 `github.com/rust-airplay/rust-airplay`。
- `Renderer` 边界现在携带编码：`VideoConfig::codec` 为 `H264` 或 `H265`，来自客户端发送的 codec 配置包。后端据此选择 parser 与解码器，会话中途更换编码也不会漏掉。
- 视频流改为首帧时打开，而不是连接建立时：客户端的 codec 配置先于首帧到达，那是编码第一次已知的时刻。
- 文档只描述库本身；命令行参数表移到了客户端的 README 里。

## 门禁

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

针对 UxPlay 的差分测试仍在这里，默认忽略；它需要 `upstream/UxPlay` 的固定提交与 MSYS2：

```sh
pwsh -File tools/oracle/run.ps1
```
