# 参数：上游的命令行，本库的 API

English: [PARAMETERS.md](PARAMETERS.md)。

UxPlay 是一个程序，它能被配置的一切都是命令行参数。本项目是一个库，同样的决定必须以值的形式可达。本页把它们双向对照，并说明哪些已实现、哪些没有。读者应当能查到某个上游参数，知道对应物在哪里——或者知道它没有对应物，以及为什么。

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
| `-p n` | 整套布局的基准端口 | 控制端口对应 `Config::port`，其余对应 `Config::ports` |
| `-p`（无值） | 上游的固定媒体端口布局 | `Config::ports` 设为 `MediaPorts::legacy()` |
| `-p` 后跟显式端口 | 固定的 timing、control、data、mirror 端口 | `Config::ports` |
| `-al x` | 报告给客户端的音频延迟 | `Config::audio_latency` |
| `-s wxh@r` | 提供给客户端的显示尺寸、刷新率与帧率上限 | `Config::display` |
| `-fps n` | 要求客户端的最高帧率 | `Config::display.max_fps` |
| `-o` | overscan 显示 | `Config::display.overscanned` |
| `-h265` | 允许 HEVC 并提供 4K | `Config::features` 置第 42 位，且 `Config::display` 为 3840x2160；默认尺寸由程序决定 |
| `-hls`（仅 feature 位） | 告知客户端支持 HLS | 不支持：`Config::features` 可以带第 4 位，但没有任何路由实现，下面的清单说明了为何应保持关闭 |
| `-nohold` | 新客户端顶替当前连接 | `Config::nohold` |
| `-reset n` | 无反馈超过 n 秒就关闭会话 | `Config::feedback_timeout` |
| `-FPSdata` | 显示客户端的流报告 | `Config::log_streaming_reports` |
| `-ca [fn]` | 封面图，或写入指定文件 | `Config::on_artwork`；写文件是程序的职责 |
| `-md <fn>` | 元数据文本写入文件 | `Config::on_metadata` 配合 `media::dmap::text` |
| `-dacp [fn]` | 导出遥控标识 | `Config::on_remote_control` |
| `-taper` | 锥形音量曲线 | `Config::volume_curve.taper` |
| `-db l:h` | 滑块重映射到的分贝范围 | `Config::volume_curve.low_db` 与 `high_db` |
| `-restrict` | 只允许名单中的设备 | `Config::client_policy.restrict` |
| `-allow <deviceID>` | 允许的设备 | `Config::client_policy.allow` |
| `-block <deviceID>` | 永远拒绝的设备 | `Config::client_policy.block` |
| `-vol <v>` | 会话起始音量 | `Config::initial_volume` |
| `-as ...` | 音频 sink | 后端的 `Options::audio_sink` |
| `-vs ...` | 视频 sink | 后端的 `Options::video_sink` |
| `-vp ...` | 视频 parser | 后端的 `Options::video_parser` |
| `-vd ...` | 视频解码器 | 后端的 `Options::video_decoder` |

有两个行为在上游没有对应参数，但库同样不能替调用方决定：`Config::pace_video`（按采集间隔节流视频）与 `Config::renderer`（由什么播放媒体）。

`-pw` 需要一句说明：上游在该参数不带口令时于每次连接生成一个口令，而 `parlor-cli` 为整个进程生成一个并打印。库里的值是固定的 `Config::password`，程序可以围绕它实现任一种行为。

## 只属于后端

这些关于解码与呈现，属于后端的 `Options`，不属于本 crate：

| 上游参数 | 作用 | 位置 |
| --- | --- | --- |
| `-avdec` | 强制软件解码 | `Options::video_decoder` 里的解码器字符串 |
| `-vc ...` | 视频转换器 | 属于 `Options::video_decoder` |
| `-v4l2`、`-bt709`、`-srgb` | 平台解码与色彩 | 管线字符串，尚未暴露 |
| `-f {H,V,I}`、`-r {R,L}` | 翻转与旋转 | 尚未暴露 |
| `-fs` | 全屏 | sink 属性，尚未暴露；overscan 由 `Config::display.overscanned` 控制 |
| `-vs 0`、`-as 0`、`-a` | 不要视频窗口、不要音频 | `--render null`，或后端里的空 sink |
| `-vrtp`、`-artp` | 把解码后的流再打包发往别处 | 未实现 |
| `-nc`、`-nofreeze` | 会话结束后窗口的处理 | 未实现 |

## 只属于程序

| 上游参数 | 作用 | 位置 |
| --- | --- | --- |
| `-key [fn]`、`-reg [fn]` | 种子与客户端名单保存位置 | 由程序决定；`parlor-cli` 放在用户应用数据目录下，`-key`/`-reg` 可以搬动它们 |
| `-d`、`-q`、`-v`、`--log-level` | 日志级别与格式 | 程序的 logger；`parlor-cli` 把它们映射到 `log` 级别 |

## 表格到此为止

上游的每一项现在都恰好落在一个位置：已实现的库值、后端选项、程序决定，或下面这份带理由的"不支持"清单。程序的命令行也使用上游的名字，见 CLI 仓库的 README。不再有"计划中"这一层让人误读成承诺。

## 不支持

以下不是"还没做"，而是有理由不做。

| 上游参数 | 原因 |
| --- | --- |
| `-hls`、`-lang`、`-slang`、`-custom`、`-rpi` | HTTP Live Streaming 需要播放器、播放列表抓取与到客户端的事件通道。相关路由返回 `501` 而不是"回 200 却什么都不做"，接收端也不应为它无法提供的功能广播第 4 位。 |
| `-mp4` | 录制需要媒体路径在会话之间保留封装器与文件；库既不拥有文件，也不拥有编解码器。 |
| `-p2p` | Apple 的点对点发现在 `mdns-sd` 中没有对应物，发现层需要再长出一种传输。 |
| `-scrsv` | 屏保是程序的职责，这个库是程序用的库。 |
| `POST /reverse` | 事件通道的作用，是把 HLS 播放列表请求从接收端送到客户端。没有 HLS 就没有要送的东西，所以路由回 `501`，而不是挂着一个永远不会写入的套接字。 |
| `-vsync`、`-async` | 两者都在选择"对齐哪个时钟"。本接收端以每条流首帧到达为锚，并按流自身时间戳推进；真机会话证明这样就能让音画保持在一起，而时钟交换的精度只有整秒，无法支撑绝对对齐。 |
