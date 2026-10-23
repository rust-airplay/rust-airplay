# 差分测试 oracle

一个小 C 程序，链接上游源码并打印它们的中间值，从而让本实现可以与它所遵循的代码对比，而不是与关于那份代码的描述对比。

## 构建

需要 `upstream/UxPlay` 下提交 `517cbb1240d9b9f69330c55b957cdd52b4175b2a` 的检出，以及 MSYS2 UCRT64：

```powershell
pwsh -File tools/oracle/build.ps1
```

它编译哪些源码写在 `build.ps1` 里。那份清单中的内容不会被链接进 Rust 产品；oracle 的存在只是为了给测试打印可对比的值。

## 运行

```powershell
pwsh -File tools/oracle/run.ps1            # 缺失时先构建，然后比对
pwsh -File tools/oracle/run.ps1 -Rebuild   # 先重新构建
```

退出码就是测试结果，可以据此在流水线中设卡。它等价于把 `AIRPLAY_UPSTREAM_ORACLE` 指向构建出的可执行文件，再运行被忽略的测试：

```powershell
$env:AIRPLAY_UPSTREAM_ORACLE = "$PWD/tools/oracle/oracle.exe"
cargo test -p rust-airplay --test upstream_oracle -- --ignored
```

## 打印什么

| 模式 | 内容 |
| --- | --- |
| `srp` | SRP-6a 的中间值 |
| `pairing` | `/pair-verify` 与 `/pair-setup` 的向量 |
| `fairplay` | FairPlay 变换 |
| `mirror` | 镜像解密器逐包从哪里取密钥流，以及给定块号处的计数器值 |

画面不正确时先看 `mirror`。它打印计数器与解密器读取的位置，因此不一致能指出两条规则中哪一条错了，而不只是输出不同。

English: [README.md](README.md)。