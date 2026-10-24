# rust-airplay

用于构建 AirPlay 1 与 AirPlay 2 接收端的 Rust 库。

它通过 mDNS 广播接收端、应答 AirPlay 控制协议、完成配对、接收投屏与音频、解密两者，并把编码后的帧交给渲染器。它停在编码边界：解码与播放是后端的事，因为一个后端就是一种技术和一棵依赖树。

## 库到哪里为止

| 库负责 | 程序负责 |
| --- | --- |
| 发现、配对、FairPlay、RTSP 路由 | 身份存在哪里 |
| 媒体套接字、解密、RTP、分帧 | 渲染器从哪里来 |
| 时间戳、节流、音量换算 | PIN 与错误怎么显示 |
| 为发生的每件事写一条 `log` 记录 | 打印哪些记录、打印到哪里 |

库不打开自己的任何文件、不读环境变量、不打印。它可能写下的文件都是显式要求的：`Config::trace_log` 与两个诊断转储。

## 引入

```toml
[dependencies]
rust-airplay = "0.2"
```

需要 Rust 1.85 或更新版本，2024 edition。crate 不链接任何 C 库。

## 启动接收端

```rust,no_run
use std::sync::Arc;

use rust_airplay::{Config, NullRenderer};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = Config::new("Living room", [0x42; 32], Arc::new(NullRenderer::new()));
rust_airplay::run(config).await?;
# Ok(())
# }
```

`Config::new` 填好所有默认值，只留下接收端无法凭空产生的三个值：客户端看到的名字、身份所派生的 32 字节种子、以及由什么播放媒体。这三个值和 `Config` 的其余字段一样，都是调用方已经决定好的值：库不读环境、不选路径、不解析命令行。

有三个字段决定程序要在 `run` 周围做什么：

- `seed` 是身份派生的秘密。同一个种子让接收端对之前配对过的客户端保持可识别，所以程序要保存它。
- `clients` 是已验证的客户端密钥集合，新密钥加入时 `on_client` 被调用。这张名单由程序读写。
- `on_pin` 在一次性 PIN 生成时被调用。它是坐在键盘前的人必须看到的唯一信息，而库不打印。

`run` 持续服务客户端直到进程停止：它不是带关闭句柄的服务器对象，程序像结束任何其他进程一样结束它。

## 播放媒体

`Renderer` 是接缝。它有三个方法——`open_audio`、`open_video`、`set_volume`——和两条流 `AudioStream` 与 `VideoStream`。越过接缝的东西已经是编码过的：一帧音频的负载，或一个 Annex-B 形式、参数集已前置的视频访问单元。所以后端需要的是解码器和设备，而不是任何 AirPlay 知识。

- [docs/BACKEND.zh-CN.md](docs/BACKEND.zh-CN.md) 是这份契约，按后端遇到的顺序写，包含一个完整的最小实现和检查清单。
- `examples/recorder.rs` 就是那个实现，随 crate 一起编译。
- [rust-airplay-gstream](https://github.com/rust-airplay/rust-airplay-gstream) 是一个完整后端：音频走 GStreamer，视频走 `gst-launch-1.0`。

`NullRenderer` 接受一切、什么都不播。它是没有声卡时也能跑通会话的东西，也是新后端用来对比的已知正确消费者。

## 文档

- [docs/BACKEND.zh-CN.md](docs/BACKEND.zh-CN.md) 与 [BACKEND.md](docs/BACKEND.md)：如何实现播放后端
- [docs/API.zh-CN.md](docs/API.zh-CN.md) 与 [API.md](docs/API.md)：配置、渲染 trait、模块
- [docs/BUILD.zh-CN.md](docs/BUILD.zh-CN.md) 与 [BUILD.md](docs/BUILD.md)：工具链与门禁
- [docs/ARCHITECTURE.zh-CN.md](docs/ARCHITECTURE.zh-CN.md) 与 [ARCHITECTURE.md](docs/ARCHITECTURE.md)：crate 划分与会话路径
- [CHANGELOG.md](CHANGELOG.md)：每个版本包含什么
- [MIGRATION.md](MIGRATION.md)：本仓库是如何从单一工作区拆出来的
- [AGENT.md](AGENT.md)：给自动化贡献者的说明

API 参考是源码构建出的 rustdoc：`cargo doc --open`，或 [docs.rs](https://docs.rs/rust-airplay) 上的渲染结果。

## 状态

版本 0.2.0。公开 API 就是本版本所记录的这一套；1.0 之前仍有可能发生破坏性变更，但并未计划。1.0 是 API 冻结的节点。

## 许可证

GPL-3.0-or-later，因为其中部分是 GPL 与 LGPL 源码的翻译。链接本 crate 的程序受同一许可证约束；见 [LICENSE](LICENSE) 与 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

English: [README.md](README.md)。
