# rust-airplay

作为库使用的 AirPlay 1/2 接收端。

`rust-airplay` 通过 mDNS 广播接收端、应答 AirPlay 控制协议、与客户端配对、接收屏幕镜像与音频、解密，并把编码后的帧交给渲染器。它不打开文件、不读环境变量、不打印任何东西，因此日志去哪里、身份存在哪里，都由嵌入它的程序决定。

库的职责停在编码边界上：交给渲染器的是参数集已前置的 Annex-B 访问单元，或一帧音频负载。解码与播放属于后端，因为一个后端就是一种技术、一个仓库。GStreamer 实现见 [rust-airplay-gstream](https://github.com/rust-airplay/rust-airplay-gstream)。

## 引入

```toml
[dependencies]
rust-airplay = "0.1"
```

需要 Rust 1.85 或更新版本。这个 crate 不链接任何 C 库。

## 启动接收端

```rust,no_run
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use rust_airplay::server::PinMode;
use rust_airplay::{AudioCodec, Config, NullRenderer};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = Config {
    name: "Living room".to_owned(),
    port: 7000,
    seed: [0x42; 32],
    device_id: None,
    pin: PinMode::OneTime,
    password: None,
    audio_codec: AudioCodec::AacEld,
    renderer: Arc::new(NullRenderer::new()),
    clients: Arc::new(Mutex::new(HashSet::new())),
    on_client: None,
    trace_log: None,
    dump_video: None,
    dump_audio: None,
    pace_video: false,
    audio_latency: std::time::Duration::from_millis(250),
    initial_volume: rust_airplay::Volume::FULL,
    volume_curve: rust_airplay::VolumeCurve::default(),
    log_streaming_reports: false,
    on_artwork: None,
    on_metadata: None,
    on_remote_control: None,
    features: None,
    client_policy: rust_airplay::server::ClientPolicy::default(),
    ports: rust_airplay::media::ports::MediaPorts::automatic(),
    nohold: false,
    feedback_timeout: None,
    display: rust_airplay::server::Display::default(),
};

rust_airplay::run(config).await?;
# Ok(())
# }
```

`run` 持续服务客户端，直到进程被要求停止。有两个字段值得解释，因为接收端跨重启的行为就来自它们。`seed` 是身份派生所用的秘密，传入同一个种子，接收端就还是同一个。`clients` 是已验证的客户端密钥集合，`on_client` 在新的密钥加入时被调用，那时正是把它写下来的时机。

## 播放媒体

`Renderer` 是边界：`open_audio`、`open_video`、`set_volume`。`VideoConfig::codec` 说明帧的编码，`VideoFrame` 携带 Annex-B 字节，所以后端只需要一个字节流解码器。`NullRenderer` 全部接受但不播放，适合测试，也适合在没有声卡的机器上检查会话。

## 日志

记录通过 `log` 以 `info`、`warn`、`debug` 输出。没有安装 logger 就什么也不打印。客户端需要输入的 PIN 也在 `info` 记录里，因此想把它显示得更醒目的程序应当安装自己的 logger。

## 文档

- [docs/API.zh-CN.md](docs/API.zh-CN.md)：配置、渲染 trait、模块
- [docs/PARAMETERS.zh-CN.md](docs/PARAMETERS.zh-CN.md)：上游每一个命令行参数，在本项目中的对应位置
- [docs/BUILD.zh-CN.md](docs/BUILD.zh-CN.md)：工具链与门禁
- [docs/ARCHITECTURE.zh-CN.md](docs/ARCHITECTURE.zh-CN.md)：crate 划分与会话路径
- [MIGRATION.md](MIGRATION.md)：本仓库是如何从单一工作区拆出来的
- [AGENT.md](AGENT.md)：给自动化贡献者的说明

## 许可证

GPL-3.0-or-later。见 [LICENSE](LICENSE) 与 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

English: [README.md](README.md)。
