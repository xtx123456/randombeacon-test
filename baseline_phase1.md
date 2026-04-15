# Phase 1: 环境跑通与基线验证 (Baseline Setup) 结果

## 环境配置

| 项目 | 版本/配置 |
|------|-----------|
| OS | Ubuntu 22.04 LTS |
| Rust | rustc 1.68.0 (2c8cc3432 2023-03-06) |
| Cargo | cargo 1.68.0 (115f34552 2023-02-26) |
| Python | Python 3.11.0rc1 |
| 系统依赖 | build-essential, libssl-dev, pkg-config, tmux, clang, libgmp-dev |

## 编译结果

- `cargo build --release` **全部通过**
- `consensus/hashrand` (beacon) 编译成功
- `consensus/ppt_beacon` 编译成功
- `consensus/glow_dvrf` 编译成功（2个warnings，非错误）
- `node` 二进制: 11.5 MB
- `genconfig` 二进制: 5.4 MB

## 基线测试结果 (N=4, batch=20, frequency=10)

### hashrand (bea) 基线
- 完成轮次: 2019 (completed round events)
- 重构事件: 39,939
- 运行时间: ~52 秒 (09:44:20 ~ 09:45:12)
- 约 **768 beacons/sec** (39939 / 52)

### ppt_beacon (ppt) 当前状态
- 完成轮次: 2019 (completed round events)
- 重构事件: 39,939
- 运行时间: ~72 秒 (09:46:03 ~ 09:47:15)
- 约 **554 beacons/sec** (39939 / 72)
- ACS scaffold 已加载，但尚未连接到重构流程
- 当前走的仍是旧路径 (terminated_secrets → gather → BAA → reconstruct)

## 结论

两个协议均可正常编译和运行。ppt_beacon 当前性能略低于 hashrand 基线，
因为 ACS 脚手架增加了额外的消息开销但尚未带来实际收益。
这为后续 Phase 2-4 的重构提供了清晰的对比基准。
