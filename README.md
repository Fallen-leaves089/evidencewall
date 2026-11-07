# EvidenceWall

![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Status](https://img.shields.io/badge/status-public%20preview-orange.svg)

[English](README.en.md) | 中文

> 独立、旁路、多端点（多 IP、多端口）、证据优先的欺骗与流量溯源传感器。

EvidenceWall 监听诱饵端点收到的流量，记录探测与扫描行为，并通过签名、哈希链、Legal Hold 记录和 Evidence Package 支持后续人工复核与维权。它面向人工处置，不自动封禁、不主动扫描、不反制，也不接管生产流量。

## 项目状态

`0.3.0` 是首个公开版本。M1/M2/M3 共 25 项自动化测试已在 Python 3.10 和 Python 3.12、干净虚拟环境中通过；CI 配置覆盖 Python 3.11、3.13，以及 Linux 环境。

这是**可用但尚未完成生产加固的 public preview**。真实多 IP、多端口拓扑还没有完成 T0/T1 部署验收；当前测试覆盖真实本地 socket 监听、合成流量关联和 Collector API，不代表已经完成公网拓扑验收。面向互联网或不可信网络的部署，请先阅读“安全边界与当前限制”。

## v0.3.0 已实现

- 真实 HTTP/1.1 诱饵监听：有界读取请求，记录方法、Host、路径、Headers 指纹、请求体哈希、来源与目的 socket 地址、首包特征、响应状态和 tarpit 时长。
- 通用 TCP 元数据监听：有界读取首包，记录首包长度与 SHA-256、来源与目的地址、advertised 映射和 tarpit 时长，不保存完整正文。
- 内置 Profile：`admin-panel`、`ollama`、`comfyui`、`tcp-metadata`。Profile 是受限 JSON 数据，不执行任意代码。
- Canary Group：创建、跨端点部署、匹配和轮换；Sensor 保存原始 token 用于注入，Collector 只保存哈希与部署映射。
- 诱饵响应与 Canary 注入：HTTP 返回假管理页/错误页，TCP Profile 可配置假 banner；命中 Canary 时记录 token 哈希，不记录原文。
- 确定性关联：跨端点、跨来源、同 Canary、同指纹、服务定向和 24 小时滑动窗口检测；不使用 LLM，不自动封禁。
- 案件复核：人工设置 `new`、`reviewing`、`confirmed` 或 `dismissed`，复核记录进入保管链。
- Evidence Package：导出案件、签名事件、批次、Sensor 公钥、Highwall 辅助记录、哈希链、保管记录和 manifest；支持目录和 ZIP。
- 离线校验：验证文件哈希、Collector 签名、Sensor 事件/批次签名、事件哈希链和 Highwall 记录完整性；可用 `--collector-key` 固定信任锚。
- Legal Hold：持久化保留原因、操作者和期限；解除必须显式确认并留审计。
- Highwall 兼容：导入白名单化的审计事件，去除查询串、片段和任意头部/正文，只作为辅助佐证，不单独创建案件。
- Canary 增量同步：Sensor 用自身 Ed25519 私钥签名公开部署映射和哈希快照，Collector 验证签名并处理轮换。
- Collector 独立身份：首次初始化生成 Ed25519 密钥；证据包只包含公钥，私钥不得进入证据包。
- CLI：`profile list`、`canary create/list/rotate`、`case list/show`、真实监听入口 `sensor run`，以及 M1 的矩阵、身份、注册、缓冲和上报命令。
- Collector API：案件列表/详情、复核、Legal Hold、导出、证据校验、Canary 同步和 Highwall 导入已接入真实存储。

## 快速开始

以下命令以项目根目录为工作目录。数据目录全部由 `--home` 指定，不依赖当前工作目录或用户主目录。

建议先创建虚拟环境：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

初始化 Collector，并在终端一运行：

```powershell
evidencewall collector init --home .\evidencewall-data\collector
evidencewall collector run --home .\evidencewall-data\collector --host 127.0.0.1 --port 8787
```

Collector 默认只监听回环地址。若必须跨主机访问，请先放在带认证、TLS 和来源限制的反向代理后，再显式增加 `--allow-remote`；直接绑定 `0.0.0.0` 会被拒绝。

另开终端，初始化 Sensor、端点矩阵和 Canary，然后注册并启动真实监听：

```powershell
evidencewall sensor init --home .\evidencewall-data\sensor
evidencewall endpoint add --home .\evidencewall-data\sensor `
  --listen-ip 127.0.0.1 --listen-port 18080 `
  --advertised-ip 203.0.113.10 --advertised-port 18080 `
  --transport http1 --profile admin-panel --exposure nat

# Canary 需要在 Sensor 注册前创建，注册时会把公开部署映射写入 Collector
evidencewall canary create --home .\evidencewall-data\sensor --type admin-token

$enrollToken = Read-Host "粘贴 collector init 输出的一次性令牌"
$enrollToken | evidencewall sensor enroll --home .\evidencewall-data\sensor `
  --collector-url http://127.0.0.1:8787 --token-stdin
Remove-Variable enrollToken

# 启动真实监听与周期上报；Ctrl+C 停止
evidencewall sensor run --home .\evidencewall-data\sensor
```

从本机验证 HTTP 诱饵。`/api/config` 返回 `401` 假响应，并把 admin-token Canary 注入响应：

```powershell
curl.exe -i -H "Host: evil.example" http://127.0.0.1:18080/api/config
```

等待一个上报周期后查看案件：

```powershell
evidencewall case list --home .\evidencewall-data\collector --json
evidencewall case show --home .\evidencewall-data\collector <case_id>
```

`203.0.113.10` 是文档示例地址。真实部署时填写路由器或反向代理实际暴露的地址。

人工复核、保留和导出：

```powershell
# 人工确认案件；未确认案件导出时会在 manifest 中带告警
evidencewall case review <case_id> --home .\evidencewall-data\collector `
  --status confirmed --note "人工复核通过"

# 设置 Legal Hold；解除必须显式确认
evidencewall case hold <case_id> --home .\evidencewall-data\collector `
  --reason "平台投诉材料保全"
evidencewall case hold <case_id> --home .\evidencewall-data\collector `
  --release --reason "保全结束" --confirm

# 默认导出到 collector\exports；也可用 --output 指定目录
evidencewall case export <case_id> --home .\evidencewall-data\collector

# 使用 Collector 公钥固定信任锚，做离线校验
evidencewall evidence verify <package-dir-or-zip> `
  --collector-key .\evidencewall-data\collector\identity\collector.pub
```

Canary 轮换后可以立即同步公开映射：

```powershell
evidencewall canary rotate --home .\evidencewall-data\sensor --group-id <group_id>
evidencewall canary sync --home .\evidencewall-data\sensor `
  --collector-url http://127.0.0.1:8787
```

Highwall 事件通过 Collector API 导入。只接受白名单字段；`path` 的查询串和片段会被移除，`headers`、Cookie、Authorization 和正文会被拒绝：

```powershell
$body = @{
  source = "highwall"
  events = @(
    @{
      external_id = "hw-2026-0001"
      event_type = "rule.match"
      observed_at = "2026-11-08T00:00:00Z"
      source_ip = "198.51.100.10"
      source_port = 45678
      destination_port = 443
      transport = "https"
      method = "GET"
      host = "example.invalid"
      path = "/.env?token=redacted"
      action = "observe"
      rule_id = "rule.env-probe"
      severity = "high"
    }
  )
} | ConvertTo-Json -Depth 6

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8787/v1/highwall/events `
  -ContentType "application/json" -Body $body
```

Highwall 事件只按同一 `source_ip` 且前后 24 小时的窗口关联到已有案件；它不会单独创建案件，也不会自动写回封禁规则。

常用检查命令：

```powershell
evidencewall profile list
evidencewall canary list --home .\evidencewall-data\sensor --json
evidencewall sensor status --home .\evidencewall-data\sensor
evidencewall doctor --home .\evidencewall-data\sensor --json
```

`sensor run --once` 和 `sensor run --flush-only` 只执行缓冲上报，不启动监听；用于排障或定时补传。

## 内置 Profile

| Profile | Transport | 用途 |
|---|---|---|
| `admin-panel` | HTTP/1.1 | 通用管理面板诱饵 |
| `ollama` | HTTP/1.1 | Ollama 兼容模型服务诱饵 |
| `comfyui` | HTTP/1.1 | ComfyUI 兼容工作流服务诱饵 |
| `tcp-metadata` | TCP | 通用 TCP 首包元数据监听 |

## 安全边界与当前限制

- Collector 默认只绑定 `127.0.0.1`，且绑定非回环地址必须显式传入 `--allow-remote`。管理接口仍未内置独立管理员认证；不要直接暴露公网，必须保持回环访问，或放在带认证、TLS 和来源限制的反向代理后。
- Highwall 导入接口属于管理面；未认证暴露会允许他人注入辅助证据，必须和案件查询接口一起放在认证与来源限制之后。
- Collector 传输是明文 HTTP/1.1，代码本身不提供 TLS。远程部署必须由受控 HTTPS 反向代理补足。
- HTTP 诱饵是明文 HTTP/1.1，不包含 TLS 终止。HTTPS 诱饵和可信代理头处理属于后续工作；不要把经过代理的来源自动当作直接来源。
- Canary 部署映射可在注册后通过签名同步更新；同步只发送公开部署映射和 token 哈希，不发送原始 token。
- Legal Hold 当前只是持久化保留记录、审计和显式确认解除。**本版本没有保留期删除任务，因此无法宣称自动删除已被可靠阻止。** 在保留期清理功能实现前，不要手工删除处于 active 状态的案件、事件或证据包；后续删除任务必须先查询 active Legal Hold 并拒绝删除。
- 真实多 IP、多端口拓扑尚未完成部署验收；当前只验证了本地真实 socket 监听、API、关联逻辑和证据包流程。WSL、路由器和代理环境的来源 IP、广告映射和 NAT 行为需要单独验收。
- 不保存完整正文、Cookie、Authorization 或真实密钥；只保留受限元数据、长度和哈希。
- 不做自动封禁、主动扫描、反制或 hack-back；Canary 命中只生成证据和告警。
- 不做 UI、托盘程序、生产流量镜像或 inline 代理。
- Highwall 是可选辅助入口，不是运行依赖。本项目不修改 Highwall 仓库；导入事件不创建案件、不自动回写封禁规则，也不被独立上游签名验证。
- 证据包自带 Collector 公钥只能证明包内自洽；对抗性校验或第三方移交必须固定可信 Collector 公钥，否则无法抵抗连同公钥整体替换。
- Windows 上 `os.chmod` 不能提供完整 ACL 保护；请把数据目录放在仅当前用户可读写的路径，并用 ACL 限制访问。
- 批次号或事件号被复用但签名内容不同，会被 Collector 拒绝，不会被误报为重复成功。

## 测试

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

当前共 25 项测试，覆盖签名、注册、断网缓冲、批次重试、幂等、Canary、HTTP/TCP 监听、跨来源关联、Highwall 导入、证据包导出/篡改、Legal Hold、远程绑定保护、API 与 CLI 错误处理。

## 目录结构

```text
src/evidencewall/
  analysis.py  确定性关联、扫描形态和置信度
  batch.py     批次构造与验证
  canary.py    Canary Group、轮换与匹配
  cli.py       命令行入口
  collector.py Collector 运行时
  config.py    数据目录与 JSON 配置
  crypto.py    Ed25519、canonical JSON、SHA-256
  domain.py    Endpoint、Matrix、Event、Canary、Case
  evidence.py  Evidence Package 导出与离线校验
  listener.py  HTTP/TCP 诱饵监听
  net.py       最小 HTTP 客户端
  profiles.py  Profile 加载与校验
  profiles/    内置 Profile JSON
  sensor.py    Sensor 运行时与批量上报
  server.py    Collector FastAPI 应用
  storage.py   Sensor/Collector SQLite 存储
```

规格文件：[EVIDENCEWALL-SPEC.md](EVIDENCEWALL-SPEC.md)

## 参与贡献

开发、测试和安全报告方式见 [CONTRIBUTING.md](CONTRIBUTING.md) 与 [SECURITY.md](SECURITY.md)。不要在公开 issue 中粘贴真实凭据、私钥、案件数据或未脱敏的证据包。

## 许可证

Apache License 2.0。见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。
