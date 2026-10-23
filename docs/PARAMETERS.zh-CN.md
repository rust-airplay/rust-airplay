# 参数：上游的命令行，本库的 API

English: [PARAMETERS.md](PARAMETERS.md)。

UxPlay 是一个程序，它能被配置的一切都是命令行参数。本项目是一个库，同样的决定必须以值的形式可达。本页把它们双向对照，并说明哪些已实现、哪些是计划。读者应当能查到某个上游参数，知道对应物在哪里——或者知道它还不存在。

涉及三处：

- **本 crate 的 `Config`**（`rust_airplay::Config`）：协议、会话、媒体策略、发现。
- **后端的 `Options`**（`rust_airplay_gstream::Options`）：解码与播放。
- **程序**：文件位置、日志格式、打印。库刻意不拥有这些。

## 已实现

| 上游参数 | 作用 | 这里 |
| --- | --- | --- |
| `-n name` | 客户端看到的名字 | `Config::name` |
| `-nh` | 不在名字后追加 `@hostname` | 名字由调用方构造；库不会追加 hostname |
| `-pin[xxxx]` | 要求 PIN，可固定 | `Config::pin`（`PinMode::OneTime` 或 `PinMode::Fixed`） |
| `-pw [pwd]` | 要求 `SETUP` 的 digest 口令 | `Config::password` |
| `-m [mac]` | 广播的硬件地址 | `Config::device_id`；为 `None` 时由种子派生 |
| `-key [fn]` | 私钥及其文件 | `Config::seed`；保存它是程序的职责 |
| `-reg [fn]` | 已配对客户端的名单 | `Config::clients` 与 `Config::on_client` |
| `-p n` | 控制端口 | `Config::port` |
| `-p`（无值） | 上游的固定媒体端口布局 | `Config::ports` 设为 `MediaPorts::legacy()` |
| `-p` 后跟显式端口 | 固定的 timing、control、data、mirror 端口 | `Config::ports` |
| `-al x` | 报告给客户端的音频延迟 | `Config::audio_latency` |
| `-s wxh@r` | 提供给客户端的显示尺寸、刷新率与帧率上限 | `Config::display` |
| `-fps n` | 要求客户端的最高帧率 | `Config::display.max_fps` |
| `-o` | overscan 显示 | `Config::display.overscanned` |
| `-h265` | 允许 HEVC 并提供 4K | `Config::features` 置第 42 位，且 `Config::display` 为 3840x2160；默认尺寸由程序决定 |
| `-hls`（仅 feature 位） | 告知客户端支持 HLS | `Config::features` 置第 4 位；路由本身仍返回 `501` |
| `-restrict` | 只允许名单中的设备 | `Config::client_policy.restrict` |
| `-allow <deviceID>` | 允许的设备 | `Config::client_policy.allow` |
| `-block <deviceID>` | 永远拒绝的设备 | `Config::client_policy.block` |
| `-vol <v>` | 会话起始音量 | `Config::initial_volume` |
| `-as ...` | 音频 sink | 后端的 `Options::audio_sink` |
| `-vs ...` | 视频 sink | 后端的 `Options::video_sink` |
| `-vp ...` | 视频 parser | 后端的 `Options::video_parser` |
| `-vd ...` | 视频解码器 | 后端的 `Options::video_decoder` |
| `-d` 等 | 日志 | `log` crate；由程序安装 logger |

有两个行为在上游没有对应参数，但库同样不能替调用方决定：`Config::pace_video`（按采集间隔节流视频）与 `Config::renderer`（由什么播放媒体）。

## 只属于后端

这些关于解码与呈现，属于后端的 `Options`，不属于本 crate：

| 上游参数 | 作用 | 位置 |
| --- | --- | --- |
| `-avdec` | 强制软件解码 | `Options::video_decoder` 里的解码器字符串 |
| `-vc ...` | 视频转换器 | 属于 `Options::video_decoder` |
| `-v4l2`、`-bt709`、`-srgb` | 平台解码与色彩 | 管线字符串，尚未暴露 |
| `-f {H,V,I}`、`-r {R,L}` | 翻转与旋转 | 尚未暴露 |
| `-fs` | 全屏 | sink 属性，尚未暴露 |
| `-vs 0`、`-as 0`、`-a` | 不要视频窗口、不要音频 | `--render null`，或后端里的空 sink |
| `-vrtp`、`-artp` | 把解码后的流再打包发往别处 | 未实现 |
| `-nc`、`-nofreeze` | 会话结束后窗口的处理 | 未实现 |

## 只属于程序

| 上游参数 | 作用 | 位置 |
| --- | --- | --- |
| `-key [fn]`、`-reg [fn]` | 种子与客户端名单保存位置 | 由程序决定；`parlor-cli` 放在用户应用数据目录下 |
| `-d` | 日志级别与格式 | 程序的 logger |

## 计划中

已映射、未实现。字段名就是 `Config` 将来会有的名字，让调用方在代码存在之前就看到形状。

| 上游参数 | 作用 | 计划中的接口 |
| --- | --- | --- |
| `-reset n` | 无反馈 n 秒后重置 | `Config::client_timeout` |
| `-nohold` | 新客户端顶掉当前连接 | `Config::single_client` |
| `-vsync`、`-async` | 时间戳同步模式 | `Config::sync` |
| `-db`、`-taper` | 音量曲线 | `Config::volume_curve` |
| `-ca`、`-md` | 封面图与元数据 | `Config` 上的回调 |
| `-dacp [fn]` | 导出遥控信息 | `Config` 上的回调 |
| `-FPSdata` | 显示客户端的流报告 | `Config::trace_log` 已包含这些；类型化回调是计划 |
| `-mp4 [fn]` | 录制会话 | 媒体路径支持之前不计划 |
| `-lang`、`-slang`、`-custom`、`-rpi` | HTTP Live Streaming 调优 | HLS 存在之前不计划 |
| `-p2p` | 点对点发现 | 不计划；`mdns-sd` 没有点对点模式 |
| `-scrsv` | 屏保策略 | 程序策略 |

## 本版本新增

`Config::audio_latency` 与 `Config::initial_volume` 是新的。前者对应上游 `-al`：客户端据此排程自己的播放，接收端在 `RECORD` 的 `Audio-Latency` 里报告它。后者对应 `-vol`：在客户端连接之前把电平告诉渲染器一次，流从该电平开始，而不是从满音量开始。

两者都在设置处校验：音频延迟超出 0 到 10 秒会在接收端启动时被拒绝，与上游解析参数时的行为一致；渲染器拒绝音量会记录一条警告，接收端继续工作。
