# EvidenceWall v0.3.0

首个公开预览版 / First public preview

发布日期：2026-11-08

EvidenceWall 是一个独立、旁路、多端点的诱饵流量监控与证据保全传感器。它面向人工复核和后续维权，不接管生产流量，不自动封禁，不主动扫描，也不进行反制。

## 主要能力

- 单一 Sensor 支持多端点矩阵，可按端点配置监听地址、对外映射和服务 Profile。
- 真实 HTTP/1.1 诱饵监听与通用 TCP 首包元数据监听，只保留受限元数据、长度和哈希。
- 内置 `admin-panel`、`ollama`、`comfyui`、`tcp-metadata` 四个受限 JSON Profile。
- Canary Group 创建、跨端点部署、轮换、匹配和签名增量同步。
- 跨来源、跨端点、同 Canary、同指纹、服务定向和 24 小时滑动窗口确定性关联。
- 人工案件复核、时间线、保管链和显式 Legal Hold。
- Evidence Package 目录/ZIP 导出，以及文件哈希、Collector/Sensor 签名和事件哈希链离线校验。
- 可选导入 Highwall 白名单审计事件，仅作为已有案件的辅助佐证。

## 验证范围

- 25 项自动化测试在 Python 3.10 和 Python 3.12 的干净虚拟环境中通过。
- CI 配置覆盖 Windows/Linux 和 Python 3.10、3.11、3.12、3.13。
- `pip check`、`compileall`、`twine check` 通过。
- wheel 和 sdist 已在隔离环境中安装，CLI 报告版本 `0.3.0`。

当前验证覆盖真实本地 socket 监听、合成事件关联、Collector API、证据包导出/篡改检测和 CLI，不代表已经完成公网多 IP/NAT 拓扑验收。

## 安装

从本 Release 下载 wheel 后：

```powershell
python -m pip install .\evidencewall-0.3.0-py3-none-any.whl
evidencewall --version
```

也可以从源码安装：

```powershell
python -m pip install .
```

## 重要安全边界

- 这是可用但尚未完成生产加固的 public preview，不应直接暴露在不可信网络。
- Collector 管理面没有内置管理员认证或 TLS。默认只绑定 `127.0.0.1`；非回环绑定必须显式使用 `--allow-remote`，并且只能放在带认证、TLS 和来源限制的反向代理后。
- Highwall 导入接口属于管理面，必须和案件查询接口一起放在认证与来源限制之后；导入事件没有上游 Highwall 签名。
- Legal Hold 当前只持久化保留记录、审计和显式确认解除。本版本没有保留期删除任务，因此不能宣称自动删除已被可靠阻止。
- 真实多 IP、多端口、NAT 和代理拓扑尚未完成 T0/T1 部署验收。
- Evidence Package 内自带的 Collector 公钥只能证明包内自洽；对抗性校验或第三方移交必须固定外部可信公钥。
- HTTP 诱饵不包含 TLS 终止；本版本也没有 UI、托盘程序、生产流量镜像或 inline 代理。
- 项目不做自动封禁、主动扫描、反制或 hack-back。Canary 命中只生成证据和告警。

## 发布资产

- `evidencewall-0.3.0-py3-none-any.whl`
  - SHA256：`8e44e7301bf76acf12b3d10555195f1eb4ae604c92ee6cfa95c0c0d56e4cf6b3`
- `evidencewall-0.3.0.tar.gz`
  - SHA256：`e23d00c0767fb3362056c51514dcd910722c2aa15cb3844b2ead8e08e021debe`
- `SHA256SUMS.txt`

## 文档

- [README](README.md)
- [English README](README.en.md)
- [产品规格](EVIDENCEWALL-SPEC.md)
- [变更记录](CHANGELOG.md)
- [安全策略](SECURITY.md)
- [贡献指南](CONTRIBUTING.md)

## 许可证

Apache License 2.0。见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。

---

## English

**EvidenceWall v0.3.0 - First public preview**

Released: 2026-11-08

EvidenceWall is an independent, out-of-band, multi-endpoint decoy traffic monitoring and evidence-preservation sensor. It is designed for human-led review and later evidence preservation. It does not take over production traffic, auto-ban, actively scan, or counter-attack.

### Highlights

- Multi-endpoint matrix for one Sensor, with per-endpoint listen addresses, advertised mappings, and service Profiles.
- HTTP/1.1 decoy listeners and generic TCP first-payload metadata listeners that retain only bounded metadata, lengths, and hashes.
- Four constrained JSON Profiles: `admin-panel`, `ollama`, `comfyui`, and `tcp-metadata`.
- Canary Groups with creation, cross-endpoint deployment, rotation, matching, and signed incremental synchronization.
- Deterministic correlation across sources, endpoints, Canaries, fingerprints, targeted services, and a 24-hour sliding window.
- Manual case review, case timelines, custody records, and explicit Legal Hold.
- Evidence Package directory/ZIP export with offline verification of file hashes, Collector/Sensor signatures, and the event hash chain.
- Optional import of allow-listed Highwall audit events as supporting evidence for existing cases only.

### Verification

- 25 automated tests pass on Python 3.10 and 3.12 in clean virtual environments.
- CI covers Windows and Linux with Python 3.10 through 3.13.
- `pip check`, `compileall`, and `twine check` pass.
- The wheel and sdist install in isolated environments, and the CLI reports version `0.3.0`.
- Current validation covers real local socket listeners, synthetic event correlation, the Collector API, evidence export/tamper detection, and the CLI. It does not prove public multi-IP, multi-port, NAT, or proxy deployment.

### Installation

After downloading the wheel from this release:

```powershell
python -m pip install .\evidencewall-0.3.0-py3-none-any.whl
evidencewall --version
```

Or install from source:

```powershell
python -m pip install .
```

### Important security boundaries

- This is a usable but not production-hardened public preview. Do not expose it directly to an untrusted network.
- The Collector management API has no built-in administrator authentication or TLS. It binds to `127.0.0.1` by default; non-loopback binding requires the explicit `--allow-remote` flag and must sit behind an authenticated, TLS-terminating proxy with source restrictions.
- The Highwall import endpoint is part of the management surface. It must be protected together with case-query endpoints. Imported events are not signed by an upstream Highwall instance.
- Legal Hold currently records, audits, and requires explicit confirmation for release. This release has no retention-deletion worker, so it does not claim that automatic deletion is reliably blocked.
- Real multi-IP, multi-port, NAT, and proxy topology has not yet completed T0/T1 deployment acceptance.
- The Collector public key embedded in an Evidence Package only proves internal consistency. Adversarial or third-party verification must pin an external trusted key.
- HTTP decoys do not terminate TLS. This release has no UI, tray application, production traffic mirroring, or inline proxy.
- EvidenceWall does not auto-ban, actively scan, counter-attack, or perform hack-back. Canary hits create evidence and alerts only.

### Release assets

- `evidencewall-0.3.0-py3-none-any.whl`
  - SHA256: `8e44e7301bf76acf12b3d10555195f1eb4ae604c92ee6cfa95c0c0d56e4cf6b3`
- `evidencewall-0.3.0.tar.gz`
  - SHA256: `e23d00c0767fb3362056c51514dcd910722c2aa15cb3844b2ead8e08e021debe`
- `SHA256SUMS.txt`

### Documentation

- [README](README.md)
- [Product specification](EVIDENCEWALL-SPEC.md)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

### License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
