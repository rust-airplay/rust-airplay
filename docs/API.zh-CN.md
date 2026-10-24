# API

English: [API.md](API.md)。生成式参考在
[docs.rs/rust-airplay](https://docs.rs/rust-airplay)；后端契约的完整说明见
[BACKEND.zh-CN.md](BACKEND.zh-CN.md)。

crate 的组织方式是一个程序级模块（[`receiver`]）加上它所用的协议部件。程序使用 `receiver`
以及 `Config` 中出现的类型；其余部分公开，是因为这些部件单独使用也有价值——测试可能只想要
镜像解密器而不开套接字，工具可能只想要发现服务的文本记录而不跑接收端。

## 启动接收端

```rust
pub async fn run(config: Config) -> Result<(), Error>
```

`run` 做完所有事：绑定控制服务、注册 mDNS 记录、绑定媒体套接字、等待进程被要求停止，并服务
客户端。每条控制连接有自己的处理器集合；媒体会话在连接之间共享，因为客户端的音频密钥在一个
`SETUP` 里到达，镜像流标识在之后的另一个 `SETUP` 里，而且可能走另一条连接。

`Ok()` 表示接收端被要求停止。`Err` 是阻止启动的失败：

- 控制端口无法绑定；
- mDNS 记录无法注册；
- 某个媒体套接字无法打开。

接收端已经运行后某场会话失败，会通过 `log` 报告，不会让接收端停止。

```rust
use std::sync::Arc;

use rust_airplay::{Config, NullRenderer};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = Config::new("Living room", [0x42; 32], Arc::new(NullRenderer::new()));
rust_airplay::run(config).await?;
# Ok(())
# }
```

[`Config::new`] 填好所有默认值，只取接收端无法凭空产生的三个值：名字、身份种子与渲染器。

## `Config`

接收端需要的一切都是字段。库不读环境变量、不做路径决定、不打印；它打开的文件只有调用方指定的
那几个（`trace_log`、`dump_video`、`dump_audio`）。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `name` | `String` | 客户端菜单里显示的名字 |
| `port` | `u16` | 控制端口；`0` 表示绑定临时端口，并广播实际拿到的那个 |
| `seed` | `[u8; 32]` | 所有身份密钥派生的秘密；同一种子让接收端跨重启保持可识别 |
| `device_id` | `Option<String>` | 要广播的硬件地址；`None` 时从种子派生 |
| `pin` | `PinMode` | `Disabled`、`OneTime` 或 `Fixed(数字)`。PIN 通过 `on_pin` 报告 |
| `password` | `Option<String>` | 设置后 `SETUP` 还要校验 digest 口令 |
| `audio_codec` | `AudioCodec` | 客户端从未在 `SETUP` 中声明 `ct` 时使用的编码；有声明时以声明为准 |
| `renderer` | `Arc<dyn Renderer>` | 由什么播放媒体 |
| `clients` | `Arc<Mutex<HashSet<[u8; 32]>>>` | 已验证的客户端密钥；启动时读取，验证通过时追加 |
| `on_client` | `Option<ClientCallback>` | 客户端首次验证通过时调用，供调用方持久化密钥 |
| `trace_log` | `Option<PathBuf>` | 设置后把请求轨迹追加到这里 |
| `dump_video` | `Option<PathBuf>` | 设置后把最初的视频帧以 Annex-B 追加到这里 |
| `dump_audio` | `Option<PathBuf>` | 设置后把音频负载（前面带长度）追加到这里 |
| `pace_video` | `bool` | 按采集间隔压住镜像视频。默认关闭：投屏看的是画面跟手的快慢 |
| `audio_latency` | `Duration` | 客户端排程所用的延迟，写在 `RECORD` 的 `Audio-Latency`；默认 250 毫秒，最多 10 秒 |
| `initial_volume` | `Volume` | 会话起始的线性增益；默认为 1.0 |
| `volume_curve` | `VolumeCurve` | 客户端的 dB 如何变成该增益：平坦或锥形，`-30..0` 区间可重映射 |
| `log_streaming_reports` | `bool` | 把客户端每秒一次的流报告写入日志 |
| `on_pin` | `Option<PinCallback>` | 一次性 PIN 生成时由后台线程调用 |
| `on_artwork` | `Option<ArtworkCallback>` | 客户端发送封面图时调用，给出内容类型与字节 |
| `on_metadata` | `Option<MetadataCallback>` | 客户端发送 DMAP 列表时调用；`media::dmap::text` 可转成行 |
| `on_remote_control` | `Option<RemoteControlCallback>` | 请求携带 `DACP-ID` 与 `Active-Remote` 时调用 |
| `features` | `Option<u64>` | 广播的 feature 位图；`None` 使用 `server::DEFAULT_FEATURES` |
| `display` | `server::Display` | 客户端从 `/info` 读到的尺寸、刷新率、帧率上限与 overscan |
| `client_policy` | `server::ClientPolicy` | 允许哪些客户端建立会话，在 `SETUP` 时判定；被拒客户端收到 `403 Forbidden` |
| `ports` | `media::ports::MediaPorts` | 四个媒体端口；`0` 由系统分配，`MediaPorts::legacy` 是传统的固定布局 |
| `nohold` | `bool` | 新客户端顶替当前连接，而不是被拒绝 |
| `feedback_timeout` | `Option<Duration>` | 客户端停止发送 `/feedback` 后关闭会话 |

回调类型都是 `Arc<dyn Fn(..) + Send + Sync>`，在遇到事件的那个线程上调用：`on_client` 在验证
客户端的连接上调用，`on_pin` 在监视待定 PIN 的线程上调用。耗时或阻塞的工作应交给另一个线程。

## 渲染器契约

```rust
pub trait Renderer: Debug + Send + Sync {
    fn open_audio(&self, config: AudioConfig) -> Result<Box<dyn AudioStream>, RenderError>;
    fn open_video(&self, config: VideoConfig) -> Result<Box<dyn VideoStream>, RenderError>;
    fn set_volume(&self, volume: Volume) -> Result<(), RenderError>;
}

pub trait AudioStream: Debug + Send + Sync {
    fn push(&self, frame: AudioFrame) -> Result<(), RenderError>;
    fn flush(&self) -> Result<(), RenderError>;
    fn close(&self) -> Result<(), RenderError>;
}

pub trait VideoStream: Debug + Send + Sync {
    fn push(&self, frame: VideoFrame) -> Result<(), RenderError>;
    fn set_pace(&self, until_next_seconds: f64) -> Result<(), RenderError> { Ok(()) }
    fn flush(&self) -> Result<(), RenderError>;
    fn pause(&self) -> Result<(), RenderError> { Ok(()) }
    fn resume(&self) -> Result<(), RenderError> { Ok(()) }
    fn close(&self) -> Result<(), RenderError>;
}
```

越过边界的是编码后的内容，不是解码后的画面：一个参数集已前置的 Annex-B 访问单元，或一帧音频的
负载。`VideoConfig::codec` 说明帧的编码——`h264parse` 读不了 HEVC 单元，HEVC 解码器也读不了
H.264——而且在第一帧之前就已知，因为客户端的 codec 包先于它到达。

两条流都是 `'static`，会被移到写出它们的线程上，所以 `push` 可以阻塞；接收循环在此期间继续读
套接字。完整契约（帧的单位、flush 与 pause 语义、一个完整实现）见
[BACKEND.zh-CN.md](BACKEND.zh-CN.md)。

`NullRenderer` 接受一切、什么都不播。它统计流、帧、字节、flush 与 close，因此既可用作测试替身，
也可在没有媒体栈的机器上跑通会话。

## 媒体值类型

| 类型 | 内容 |
| --- | --- |
| `AudioCodec` | `Alac` 或 `AacEld`；`from_compression_type` 把客户端的 `ct` 映射过来 |
| `AudioConfig` | 编码、采样率、声道数，以及来自客户端 `spf` 的每帧采样数 |
| `AudioFrame` | 编码负载；时间戳按会话采样率计采样数 |
| `VideoCodec` | `H264` 或 `H265` |
| `VideoConfig` | 客户端声明过的宽高，以及编码 |
| `VideoFrame` | Annex-B 访问单元、NTP Q32.32 时间戳、是否关键帧 |
| `Volume` | 从静音到原始电平的线性增益，构造时钳制 |
| `VolumeCurve` | 滑块位置到增益；平坦或锥形，分贝范围可配置 |
| `RenderError` | 机器无法提供该流时 `Unavailable`，播放出错时 `Failed` |

## 服务与控制类型

| 类型 | 用途 |
| --- | --- |
| `server::Server` | 绑定控制端口并服务连接；`Server::bind`、`local_addr`、`run` |
| `server::ServerConfig` | 绑定地址、连接上限、空闲超时、顶替、反馈超时 |
| `server::RouteHandlers` | 一条连接的 RTSP 路由，以及程序安装的回调 |
| `server::DeviceIdentity` | 客户端读到的名字、型号、地址与公钥 |
| `server::PinMode`、`server::PairingState` | PIN 策略与接收端级配对服务 |
| `server::SetupPorts`、`SetupRequest`、`SetupStream` | `SETUP` 承诺了什么、客户端要求了什么 |
| `server::Display` | `/info` 中广播的屏幕几何 |
| `server::ClientPolicy` | 允许与拒绝名单，在 `SETUP` 时应用 |
| `server::DEFAULT_FEATURES` | 接收端起步用的 feature 位图 |
| `control::Route`、`control::RouteHandler` | 路由表与处理器集合实现的 trait |
| `wire::MessageHead`、`control::RouteRequest`、`control::RouteReply` | 解析后的请求与处理器构建的应答 |

程序想要自己的连接策略时使用 `server::Server`；`receiver` 就是同一套工作已经组装好的版本。

## 发现

| 类型 | 用途 |
| --- | --- |
| `discovery::Protection` | 客户端需要 PIN、口令，还是什么都不需要 |
| `discovery::Advertisement` | 某个身份的 `_raop._tcp` 与 `_airplay._tcp` 记录 |
| `discovery::Advertiser` | 注册与注销它们，并保留完整名称 |
| `discovery::DiscoveryError` | 注册失败的原因 |

`Advertisement::txt_records` 返回两条文本记录的字节形式，`GET /info?txtAirPlay` 也返回同样的
内容，所以两处描述的是同一个接收端。

## 媒体模块

| 项 | 用途 |
| --- | --- |
| `media::ports::MediaPorts`、`MediaSockets` | 四个端口及绑定其上的套接字 |
| `media::audio::AudioSession`、`ReorderWindow`、`FlushHandle` | RTP 音频：解密、重排、重传请求、flush |
| `media::mirror::MirrorSession`、`StreamInfo`、`Geometry`、`MirrorKind` | 镜像流：头部解析、AES-CTR、codec 数据、几何、暂停 |
| `media::control::parse_control_packet`、`resend_request` | UDP 控制套接字 |
| `media::dmap::items`、`text` | 当前播放元数据 |
| `media::timing::RemoteClock` | 客户端时钟偏移 |
| `media::pace::Pacer` | 时间戳到本地时间的换算，用于节流 |

## 原语

`plist`、`wire`、`rtp`、`ntp`、`crypto`、`fairplay`、`srp` 是上面模块所依赖的协议原语。它们
公开，是因为测试、工具或协议实验可能只需要其中一个；每个都记录了自己的边界与错误情形，不会悄悄
规范化输入。

## 日志

库只写 `log` 记录，从不打印。`info` 是会话进度（接收端、端口、广播名、流打开），`warn` 是出错
的会话，`debug` 是包级细节。程序没有安装 logger 时什么都不会出现。

有两样东西不是日志：PIN 通过 `on_pin` 到达，阻止启动的错误是返回的 `Error`。程序可以按自己的
方式打印它们。

## 程序职责

| 库决定 | 程序决定 |
| --- | --- |
| 协议、媒体、时序 | 种子与客户端名单存在哪里 |
| 何时打开或冲刷一条流 | 用什么播放 |
| PIN 是什么 | PIN 怎么显示 |
| 一条轨迹包含什么 | 轨迹写到哪里 |

持久化种子与客户端名单的程序，得到的是跨重启保持可识别的接收端；不持久化的程序，得到的是每次
看起来都全新的接收端——这也是一个正当的选择。

## 版本

版本 0.2.0。公开 API 就是本版本所记录的这一套；1.0 之前的破坏性变更有可能，并会记录在变更日志。
许可证为 GPL-3.0-or-later。

[`receiver`]: https://docs.rs/rust-airplay/latest/rust_airplay/receiver/index.html
