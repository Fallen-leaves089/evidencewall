# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 的结构，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Planned

- T0/T1 多 IP、多端口、NAT/代理测试床与真实部署验收。
- Collector 管理面认证和 TLS 终止方案。
- 保留期删除任务，并与 active Legal Hold 联动。

## [0.4.0] - 2026-11-09

### Added

- Sensor 周期签名健康上报，以及 Collector `POST /v1/sensors/health` 接口。
- Collector 侧展示 Sensor 和端点健康、待传队列、缓冲占用、磁盘余量、版本、Profile 版本、时钟偏差和签名失败次数。
- 跨 `direct`/`nat` 来源的同一 Canary 关联合并；基础案件键仍保留来源质量，避免混淆 `edge-provided` 与直接来源。
- `sensor run --once` 和 `--flush-only` 统一为一次性补传后退出。
- 平台用户数据目录作为默认 `--home` 根目录，并支持 `EVIDENCEWALL_HOME` 覆盖。

### Changed

- Sensor 缓冲上限按未发送事件计算；批次确认后只保留有限本地历史，避免历史总行数触发永久阻塞。
- 字节上限达到且未发送队列已下降时，自动 checkpoint/VACUUM 回收 SQLite 高水位；回收失败时继续阻断并显示原因。
- 连接数限制在并发获取槽位前预留来源计数，并在超时或任务取消时释放，修复同一来源瞬时绕过限制和计数泄漏的问题。
- Evidence Package 改为单 SQLite 读事务快照，并在导出前校验案件摘要、事件哈希和来源集合一致性。
- 默认 Collector 密钥缺失、不完整或公私钥不匹配时失败关闭，不再静默生成新身份。
- 版本提升到 `0.4.0`。

### Security

- 健康上报严格校验 Sensor/Matrix、端点归属、数值边界和签名；签名失败累计展示。
- JSON 配置、Canary 快照和密钥相关写入改为原子写入并尽量使用受限文件模式。
- 缓冲达到数量、字节或低磁盘阈值，或最近写入失败时，Sensor 暂停监听而不是继续接收后丢弃证据。
- 本地缓冲统计读取失败时按阻断状态处理，避免监控故障后继续接收新事件。
- 文档补充 Windows ACL 限制、时钟偏差符号约定和健康遥测边界。

## [0.3.0] - 2026-11-08

首个公开版本。

### Added

- HTTP/1.1 诱饵监听和通用 TCP 元数据监听，支持单 Sensor 多端点矩阵。
- `admin-panel`、`ollama`、`comfyui`、`tcp-metadata` 四个受限 JSON Profile。
- Canary Group、轮换、跨端点部署和签名增量同步。
- 跨来源、跨端点、同 Canary、同指纹、服务定向和 24 小时滑动窗口关联。
- 人工案件复核、案件时间线和保管链记录。
- Legal Hold 记录、查询和显式确认解除。
- Evidence Package 目录/ZIP 导出，以及文件哈希、Collector/Sensor 签名和事件哈希链离线校验。
- Highwall 白名单事件导入和查询，只作为已有案件的辅助佐证。
- Collector 独立 Ed25519 身份，以及可固定外部信任锚的离线校验。
- 非回环 Collector 绑定必须显式使用 `--allow-remote` 的保护门槛。
- Windows/Linux、Python 3.10–3.13 CI 和 wheel/sdist 打包检查。

### Security

- 记录和证据默认不保存完整正文、Cookie、Authorization 或真实密钥。
- 明确记录无内置管理员认证、无内置 TLS、Legal Hold 尚无删除保护等边界。
- 拒绝分块请求体，避免 `Transfer-Encoding` 绕过 Collector 的 2 MiB 请求上限。
- 项目不自动封禁、不主动扫描、不反制、不执行 hack-back。

### Known limitations

- 真实多 IP、多端口和 NAT/代理拓扑尚未完成 T0/T1 部署验收。
- Collector 管理面仍依赖回环绑定或外部认证/TLS 反向代理。
- Legal Hold 尚未与保留期删除任务联动。
- 尚未提供 UI、HTTPS 诱饵和完整协议仿真。

