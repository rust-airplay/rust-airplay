# API

English: [API.md](API.md)。生成的参考文档在 [docs.rs/rust-airplay](https://docs.rs/rust-airplay)。

## 运行接收端

```rust
pub async fn run(config: Config) -> Result<(), Error>
```

这一个 future 做完全部工作：绑定控制服务、注册 mDNS 记录、绑定媒体套接字、监听进程的停止信号，然后服务客户端。每条控制连接有自己的处理器集，但媒体会话是共享的。客户端的音频密钥在某次 `SETUP` 里到达，镜像流的标识在之后另一次 `SETUP` 里到达，而这两次未必是同一条连接。

进程被要求停止时返回 `Ok(())`；只有"接收端无法启动"才返回 `Err`：

- 控制端口绑不上；
- mDNS 记录注册不出去；
- 某个媒体套接字打不开。

接收端已经运行之后某个会话出问题，会通过 `log` 记录，接收端继续服务。丢弃这个 future 与停止信号等价。

## `Config`

接收端需要的一切都在这里；凡是调用方能决定的，都做成字段，而不是藏起来的默认值。库不读环境变量，也不打开文件。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `name` | `String` | 客户端菜单里显示的名字 |
| `port` | `u16` | 控制端口；`0` 绑定临时端口并广播该端口 |
| `seed` | `[u8; 32]` | 身份派生所用的秘密。传入保存的种子，接收端跨重启仍是同一个 |
| `device_id` | `Option<String>` | 要广播的硬件地址；`None` 时由种子派生 |
| `pin` | `PinMode` | `Disabled`、`OneTime` 或 `Fixed(digits)`。PIN 通过 `log` 输出，想用别的方式显示的程序可以自己装 logger |
| `password` | `Option<String>` | 设置后，`SETUP` 还需要这个 digest 口令 |
| `audio_codec` | `AudioCodec` | `Alac` 或 `AacEld`；客户端在 `SETUP` 中声明 `ct` 时以声明为准 |
| `renderer` | `Arc<dyn Renderer>` | 播放媒体的实现 |
| `clients` | `Arc<Mutex<HashSet<[u8; 32]>>>` | 已验证的客户端密钥。启动时读取，验证通过后就加进去 |
| `on_client` | `Option<ClientCallback>` | 客户端首次通过验证时调用，便于调用方持久化该密钥 |
| `trace_log` | `Option<PathBuf>` | 设置后把请求轨迹追加到该文件 |
| `dump_video` | `Option<PathBuf>` | 设置后把最早的视频帧以 Annex-B 追加到该文件 |
| `dump_audio` | `Option<PathBuf>` | 设置后把音频负载带长度前缀追加到该文件 |
| `pace_video` | `bool` | 是否按采集间隔节流镜像视频。默认关闭：投屏看的是画面跟手的快慢 |
| `audio_latency` | `Duration` | 客户端据此排程的音频延迟，在 `RECORD` 的 `Audio-Latency` 中报告；对应上游 `-al`，范围 0 到 10 秒 |
| `initial_volume` | `Volume` | 会话起始的滑块位置；对应上游 `-vol` |
| `volume_curve` | `VolumeCurve` | 客户端的 dB 如何变成增益：平坦或 taper，`-30..0` 区间的重映射；对应上游 `-db` 与 `-taper` |
| `log_streaming_reports` | `bool` | 把客户端每秒一次的流报告写入日志；对应上游 `-FPSdata` |
| `features` | `Option<u64>` | 广播的 feature 位图；`None` 用默认值，第 42 位允许 HEVC，第 4 位宣称 HLS |
| `display` | `server::Display` | 客户端从 `/info` 读到的尺寸、刷新率、帧率上限与 overscan；对应上游 `-s`、`-fps`、`-o` |
| `client_policy` | `server::ClientPolicy` | 允许哪些客户端建立会话，在 `SETUP` 时判定；被拒绝的客户端收到 `403 Forbidden` |
| `ports` | `media::ports::MediaPorts` | 四个媒体端口；`0` 表示由系统分配，`MediaPorts::legacy()` 是上游的固定布局 |
| `nohold` | `bool` | 新客户端顶替当前连接，而不是被拒绝 |
| `feedback_timeout` | `Option<Duration>` | 客户端停止发送 `/feedback` 后关闭会话；对应上游 `-reset` |

`ClientCallback` 的类型是 `Arc<dyn Fn(&[u8; 32]) + Send + Sync>`。它在验证客户端的连接上执行，因此写文件的实现应当让工作量足够小，或者干脆交给另一个线程。

## 渲染器 trait

```rust
pub trait Renderer: Debug + Send + Sync {
    fn open_audio(&self, config: AudioConfig) -> Result<Box<dyn AudioStream>, RenderError>;
    fn open_video(&self, config: VideoConfig) -> Result<Box<dyn VideoStream>, RenderError>;
    fn set_volume(&self, volume: Volume) -> Result<(), RenderError>;
}
```

库负责解密与组帧，**不负责解码**。交给渲染器的是编码后的帧：参数集已前置的 Annex-B 访问单元，或一帧音频负载。`VideoConfig::codec` 说明帧的编码，因为 `h264parse` 读不了 HEVC 单元，HEVC 解码器也读不了 H.264。

每个会话打开一次流，两者都是 `'static`，因为会话会把每一个移到只负责写帧的线程上。这是对实现者影响最大的设计点：写入可以阻塞任意长时间，接收循环 meanwhile 继续读套接字。也正因为如此，每个流前面都有一个队列；一个需要阻塞的后端在这里不是问题。

`AudioStream` 接收 `AudioFrame`，另有 `set_volume`、`flush`、`close`。`VideoStream` 接收 `VideoFrame`，另有 `set_pace`、`flush`、`close`。

- `push` 可以阻塞，它由专用线程调用。
- `close` 表示本会话没有更多媒体了，不要求销毁流。
- 丢弃流必须释放后端持有的资源。

`NullRenderer` 用"全部接受、什么都不播"实现这个 trait，并统计收到了什么，因此既适合检查会话，也适合写测试。

## 媒体类型

| 类型 | 内容 |
| --- | --- |
| `AudioConfig` | 编码、采样率、声道数、每帧采样数；客户端声明 `spf` 时以后者为准 |
| `AudioFrame` | 编码后的负载，以及以会话采样数计的时间戳 |
| `VideoConfig` | 客户端声明过的宽高，以及帧的编码 |
| `VideoFrame` | Annex-B 访问单元、时间戳、是否为关键帧 |
| `Volume` | 从静音到满音量，构造时夹紧 |
| `RenderError` | 无法播放用 `Unavailable`，播放出错用 `Failed` |

音频时间戳的单位是采样数而非纳秒，因为客户端就是这么发的。按时间排程的渲染器需要换算；GStreamer 后端已经这样做。

## 模块

运行接收端只需要 `receiver`；其余模块公开，是因为单个部件本身有用，例如测试里想只验证解密而不启动服务器。

| 模块 | 内容 |
| --- | --- |
| `receiver` | `run`、`Config`、`Error`、`ClientCallback` |
| `render` | 上文那些渲染 trait 与媒体类型 |
| `discovery` | `Advertisement`、`Advertiser`、`Protection` 与文本记录 |
| `server` | `Server`、`RouteHandlers`、`DeviceIdentity`、`PairingState`、`PinMode`、`SetupPorts` |
| `control` | RTSP 请求解析与路由表 |
| `media` | 音频重排、镜像解密、数据报套接字、时钟交换 |
| `pairing` | `/pair-verify` 与 `/pair-setup` 的密码学 |
| `srp`、`crypto`、`fairplay`、`plist`、`rtp`、`ntp`、`wire` | 上述模块赖以构建的原语 |

## 命令行接收端

命令行接收端是独立的程序，不属于这个 crate：[parlor-cli](https://github.com/rust-airplay/parlor-cli)。参数列表见它的 README。库刻意不包含这类决定——不读环境变量、不选路径、不打印——所以这些都属于程序。

## 日志

库通过 `log` 输出记录。`info` 记录旁观会话的人想看到的进度，`warn` 记录出问题的会话，`debug` 记录包级细节。没有安装 logger 就什么也不打印。命令行接收端安装的 logger 把 `info` 及以下写到标准输出，把警告写到标准错误。
