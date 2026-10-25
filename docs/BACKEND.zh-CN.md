# 编写播放后端

`rust-airplay` 负责接收并解密会话，不负责播放。播放是程序注入的一个值：一个
[`Renderer`][renderer] 实现。本文按后端实际遇到的顺序说明这份契约。

`rust-airplay-gstream` 是参考实现，读它时对着本文看。

## trait

```rust
pub trait Renderer: Debug + Send + Sync {
    fn open_audio(&self, config: AudioConfig) -> Result<Box<dyn AudioStream>, RenderError>;
    fn open_video(&self, config: VideoConfig) -> Result<Box<dyn VideoStream>, RenderError>;
    fn set_volume(&self, volume: Volume) -> Result<(), RenderError>;
}
```

三个方法对应接收端对一场会话做的三件事：打开音频流、打开视频流、改音量。会话可以只有音频（纯音频客户端），也可以只有视频（无声投屏），所以两条流彼此独立。一个渲染器可以同时服务两者，程序也可以给两个接收端各配一个；trait 不假设它们是同一个对象。

所有方法都取 `&self`。接收端持有渲染器的同时，媒体线程持有各自的流；客户端重连后 `open_audio` 可能再次被调用。可变状态由后端自己加锁——参考实现把正在播放的流的音量元素放在 `Mutex<Option<WeakRef<Element>>>` 里。

## 线程模型

- 渲染器是 `Send + Sync`，音频与视频路径共享它。
- `push` 由拥有该流的线程调用：视频是写入线程，音频是读取音频套接字的任务。它不是从协议连接线程调用的，且不能长时间阻塞——慢的 `push` 会变成网络读取的反压，而不是暂停。
- 需要自己线程的后端（管线线程、渲染循环）在 `open_*` 里启动，在 `Drop` 与 `close` 两处都停止。接收端可能在会话异常结束时直接丢弃流而不调用 `close`，只在 `close` 里停止的后端会漏掉一个线程或一台设备。

## 打开音频流

客户端声明音频编码后，`open_audio` 被调用。

`AudioConfig` 带有在收到第一帧之前就构建解码器所需的全部信息：

| 字段 | 含义 |
| --- | --- |
| `codec` | `Alac` 或 `AacEld`，来自客户端的 `ct`（客户端没说时用 `Config::audio_codec`） |
| `sample_rate` | 44100，本 crate 支持的所有 AirPlay 音频格式都是这个采样率 |
| `channels` | 目前见到的客户端都是 2 |
| `samples_per_frame` | 客户端的 `spf`，即一帧携带多少采样 |

一个编码帧就是一次 `push`。与视频不同，音频帧没有起始码：唯一的分界就是这次 push，所以后端必须按缓冲区解码，而不是扫描字节。参考后端对音频用 `appsrc`、对视频用字节流，原因就在这里。

## 帧

`AudioFrame`：

```rust
pub struct AudioFrame {
    pub data: Vec<u8>,
    pub timestamp: u64,
}
```

- `data` 是一帧编码数据，解密后的原样内容，外面没有容器。
- `timestamp` 是客户端的 RTP 时间戳。它计的是**采样数**，不是秒也不是纳秒：相邻帧相差 `samples_per_frame`（44.1 kHz 下是 480）。与墙上时钟比较之前要除以采样率；把它当纳秒会让每一帧落到与播放时刻无关的时间上。

`VideoFrame`：

```rust
pub struct VideoFrame {
    pub data: Vec<u8>,
    pub timestamp: u64,
    pub keyframe: bool,
}
```

- `data` 是 Annex-B 形式的访问单元：参数集（SPS/PPS，HEVC 则是 VPS/SPS/PPS）在变化时被前置，每个 NAL 单元以 `00 00 00 01` 开始。
- `timestamp` 是 NTP 定点数 Q32.32：高 32 位是秒，低 32 位是小数。投屏客户端的时钟不是接收端的时钟，所以它适合用来拉开帧间距，不适合直接对本地时钟排程。
- `keyframe` 在 IDR 帧上为真。解码器从那里开始；它之前的帧无法解码。

## 节流

收到镜像帧就以最快速度写出去，解码会比实时快。镜像流是一帧关键帧加一串只描述变化的帧，解得太快就会丢掉后续帧依赖的帧，画面会一直有部分是错的。

接收端因此提供两个钩子：

- `VideoStream::set_pace(seconds)`：在每帧之前调用，给出到下一帧的间隔。默认什么都不做；有时间基准的后端可以睡眠或排程。
- `Config::pace_video`：让接收端自己在调用 `push` 前按时间压住每一帧。默认关闭：投屏看的是画面跟手的快慢，节流用延迟换均匀。

## 冲刷、暂停与关闭

- `flush` 表示已经交出去的媒体过期了。客户端发了 `FLUSH`（拖动、模式切换），或接收端因落后丢弃了帧。丢掉排队的内容；解码器还应重置，好让下一个关键帧开始一张干净的画面。
- `pause` 与 `resume` 跟随客户端自己声明的停止与恢复。默认什么都不做：停止接收帧的管线本来就停在最后一帧。
- `close` 结束这条流；下一场会话会打开新的流。

## 音量

`Renderer::set_volume` 收到的是 `Volume`：从 `0.0` 到 `1.0` 的线性增益，`1.0` 是原始电平。客户端说分贝，由库负责换算；后端永远见不到分贝值。

`set_volume` 会在任何客户端连接之前调用一次（参数是 `Config::initial_volume`，同样是线性增益），之后每次客户端拖动滑块再调用。后端必须做两件事：

1. 把增益应用到**正在播放**的流上；
2. 为之后打开的流记住它，因为管线通常在客户端说音量之前就已经启动。

参考实现把属性写到运行中的 `volume` 元素，同时保存下来供下一次 `open_audio` 使用。

## 错误

`RenderError::Unavailable` 表示这台机器无法提供所请求的东西（缺解码器、没有声卡、没有显示）。会话继续，只是少了那条流，并报告原因：静默地什么都不播的接收端，比说清楚原因的接收端更糟。

`RenderError::Failed` 表示后端被要求做一件事却做不到。接收端报告它，不重试；后端内部的自动重试循环是隐藏自身失败的后端。

## 一个最小后端

下面这个把收到的内容写进文件。它是完整的：打开两条流、写入每一帧、冲刷时不丢任何东西（文件是追加的历史），并在 drop 时关闭。

```rust
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};

use rust_airplay::{
    AudioConfig, AudioFrame, AudioStream, RenderError, Renderer, VideoConfig, VideoFrame,
    VideoStream, Volume,
};

struct Recorder {
    audio: Arc<Mutex<Option<File>>>,
    video: Arc<Mutex<Option<File>>>,
    volume: Mutex<Volume>,
}

struct RecordingStream {
    file: Arc<Mutex<Option<File>>>,
}

impl AudioStream for RecordingStream {
    fn push(&self, frame: AudioFrame) -> Result<(), RenderError> {
        let mut slot = self.file.lock().expect("the recorder lock");
        if let Some(file) = slot.as_mut() {
            file.write_all(&frame.data).map_err(|error| RenderError::Failed(error.to_string()))?;
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), RenderError> {
        Ok(())
    }

    fn close(&self) -> Result<(), RenderError> {
        *self.file.lock().expect("the recorder lock") = None;
        Ok(())
    }
}

impl VideoStream for RecordingStream {
    fn push(&self, frame: VideoFrame) -> Result<(), RenderError> {
        let mut slot = self.file.lock().expect("the recorder lock");
        if let Some(file) = slot.as_mut() {
            file.write_all(&frame.data).map_err(|error| RenderError::Failed(error.to_string()))?;
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), RenderError> {
        Ok(())
    }

    fn close(&self) -> Result<(), RenderError> {
        *self.file.lock().expect("the recorder lock") = None;
        Ok(())
    }
}

impl Renderer for Recorder {
    fn open_audio(&self, _config: AudioConfig) -> Result<Box<dyn AudioStream>, RenderError> {
        let file = File::create("audio.aac").map_err(|error| RenderError::Unavailable(error.to_string()))?;
        *self.audio.lock().expect("the recorder lock") = Some(file);
        Ok(Box::new(RecordingStream { file: Arc::clone(&self.audio) }))
    }

    fn open_video(&self, _config: VideoConfig) -> Result<Box<dyn VideoStream>, RenderError> {
        let file = File::create("video.h264").map_err(|error| RenderError::Unavailable(error.to_string()))?;
        *self.video.lock().expect("the recorder lock") = Some(file);
        Ok(Box::new(RecordingStream { file: Arc::clone(&self.video) }))
    }

    fn set_volume(&self, volume: Volume) -> Result<(), RenderError> {
        *self.volume.lock().expect("the volume lock") = volume;
        Ok(())
    }
}
```

可编译的完整版本在 `examples/recorder.rs`。

真实后端还多两件这个例子不需要的东西：

- **时钟。** 帧带着时间戳到达，播放器要把它们变成呈现时间。
- **设备。** 一个 sink、一个窗口，或两者；它们从哪来是后端的事。

### 音频与视频在一起

两种时间戳量的是不同的时钟：音频从随机 RTP 原点开始按采样率计数，视频是客户端自己纪元里的 NTP 定点数。接收端把每条流锚在它第一帧到达的时刻，并按各自的速率排程；它**不会**交给后端一个共同的本地时基。同时播放两者的后端必须自己从两条流建立时基（它们的第一帧是同一时刻采集的，到达时间只差一个网络宽度），或者接受唇音同步是后端自己的问题。这是写明的边界，不是隐藏的假设：crate 不会把两个任意原点当成同一个时钟。

`NullRenderer` 是另一端的对照：接受一切、统计帧数、什么都不播。它的存在是为了让会话在没有媒体库的情况下端到端跑通，也让后端的行为能和已知正确的消费者对比。

## 测试后端

- `NullRenderer` 验证协议路径。
- 录制型后端验证帧本身：写出来，用普通播放器打开。Annex-B 单元组成的视频文件就是合法的 `.h264` 或 `.h265` 流；编码帧组成的音频文件需要容器和该编码的配置，参考后端仓库里的测试展示了怎么构造。
- 运行时测试应放在 `#[ignore]` 后面，并带一个"环境里没有媒体栈就跳过"的守卫；`cargo test -- --ignored` 在有媒体栈的机器上运行它们。

## 检查清单

- [ ] `Renderer` 是 `Send + Sync`；可变状态在锁后面。
- [ ] `push` 不长时间阻塞；耗时的工作放在后端自己的线程上。
- [ ] 流在 `Drop` 时也会停止，而不只是 `close`。
- [ ] 音频时间戳变成时间之前除以了采样率。
- [ ] 视频帧按 Annex-B 处理，参数集是前置的。
- [ ] `flush` 丢掉排队的媒体并重置解码器。
- [ ] `set_volume` 应用到正在播放的流，并为下一次记住。
- [ ] 无法提供某条流时用 `Unavailable`；请求无法完成时用 `Failed`。
- [ ] 媒体栈缺失只报告一次，接收端继续服务客户端。

[renderer]: https://docs.rs/rust-airplay/latest/rust_airplay/render/trait.Renderer.html
