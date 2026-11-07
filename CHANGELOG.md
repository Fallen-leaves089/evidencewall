# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 的结构，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Planned

- T0/T1 多 IP、多端口、NAT/代理测试床与真实部署验收。
- Collector 管理面认证和 TLS 终止方案。
- 保留期删除任务，并与 active Legal Hold 联动。

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

