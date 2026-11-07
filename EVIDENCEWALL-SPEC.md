# EvidenceWall 产品与架构规格 v0.1

状态：v0.1 规格已评审；M1、M2、M3 已实现并通过自动化测试，`0.3.0` 为首个公开版本。M3 的证据包、人工复核、Legal Hold 记录、Highwall 导入和 Canary 增量同步已落地；真实多 IP/多端口拓扑和保留期删除任务仍待部署验收。本文不包含实现代码。

日期：2026-11-08

> **一句话**：EvidenceWall 是独立、旁路、多端点（多 IP、多端口）、证据优先的欺骗与流量溯源传感器；它不阻断生产、不主动反制，负责引诱、拖延、采集、保全、关联并导出可复核的证据案件，为人工处置和后续维权提供依据。

## 1. 定位

EvidenceWall 面向自托管服务，尤其是暴露在公网或局域网中的 AI 服务、管理面板和内部工具。同一个 Sensor 可以同时监听多个 `IP:port`，组成诱饵监听矩阵；Collector 负责跨端点关联、证据保全和案件导出。

监控范围是**诱饵端点收到的流量**，以及用户显式导入的 Highwall 审计事件；v0.1 不镜像全量生产流量，不做 inline 代理。

它不是 WAF，不是反向代理的替代品，也不是 Highwall 内部插件。Highwall 是可选入口，EvidenceWall 可以完全独立运行。

核心职责按顺序是：

1. **发现证据**：记录扫描、探测、登录尝试、路径遍历和工具指纹。
2. **关联溯源**：把多个端口/IP 上的行为归并到同一来源、工具链或活动。
3. **保全证据**：用签名、哈希链、时间线和保管记录保证案件可复核。
4. **支持维权**：按需导出证据包，供内部处置、平台投诉、民事维权或执法初筛使用。

核心价值：

- 不接触生产流量，部署风险低。
- 不追求自动封禁，避免误杀和不可逆处置。
- 把攻击者的行为变成可复核的案件，而不是一堆日志。
- 通过多端点矩阵和 canary 关联，区分背景扫描和针对性活动。
- 证据保全和导出是产品主链路，不是事后附加功能。
- Sensor 可以按“随时可能被攻破”设计，坏了就丢弃重建。

## 2. 问题

单点蜜罐只能看到局部，无法判断一次扫描是互联网背景噪音，还是同一攻击活动在多个端口和 IP 上出现。普通日志也缺少跨端点关联、证据链、保全和可读时间线。

EvidenceWall 要解决的是：

1. 一个 Sensor 如何统一管理多 IP、多端口的诱饵矩阵。
2. 同一行为如何在端点之间、以及多个 Sensor 之间关联。
3. NAT、路由器或反向代理后面的公网入口如何准确映射到实际端点。
4. 如何生成人能快速看懂、可复核的证据案件。
5. 如何在保留期内保全证据，并在需要时导出用于投诉或维权。
6. 如何证明证据没有被篡改、缺失或张冠李戴。
7. 如何在不接触生产、不主动反制的前提下完成以上目标。

## 3. 设计原则

1. **观察优先**：默认不阻断、不反制、不修改生产配置。
2. **旁路优先**：Sensor 独立部署，失败不影响业务。
3. **证据优先**：案件、时间线、哈希和签名优先于告警数量。
4. **多端点优先**：单个监听器只能算蜜罐，`IP:port` 矩阵和跨端点关联才是产品。
5. **保全优先**：进入复核或维权流程的案件，关键证据进入只追加存储，并受保留策略和法律保留控制。
6. **可牺牲**：Sensor 是诱饵，允许被攻破；前提是隔离、无真实凭据、可重建。
7. **可解释**：每条关联都说明依据和置信度，不把推断写成事实。
8. **数据最小化**：默认不存完整正文、Cookie、Authorization 和真实密钥。
9. **用户掌控**：保留期、导出、删除、告警和采集范围由用户配置。
10. **不做 hack-back**：不主动扫描、不利用、不登录攻击者基础设施。
11. **不冒充生产**：诱饵必须可识别为本项目部署的诱饵，不能用于收集真实用户凭据。

## 4. 目标用户与场景

### 4.1 目标用户

- 在 Windows、WSL、小 VPS 或家庭网络中运行自托管 AI 服务的开发者。
- 想把 Ollama、ComfyUI、Open WebUI 或管理面板暴露给少量用户的小团队。
- 有多个公网/内网端口或 IP，希望观察谁在探测并保留证据的用户。
- 需要为扫描、骚扰、入侵尝试或数据泄露事件保留材料的个人和小团队。
- 需要跨端点证据的小型安全团队或研究环境。

### 4.2 典型场景

- 在同一主机或同一路由器后监听多个 `IP:port`，观察同一来源是否纵向扫端口、横向扫 IP。
- 在真实 AI 服务旁边部署诱饵端口，记录针对默认端口和默认路径的探测。
- 在 Highwall、Nginx、Caddy 或 Traefik 后挂一个诱饵上游，记录命中诱饵路径的请求。
- 用唯一 canary 判断某个自动化工具是否在多个端点复用同一套探测逻辑。
- 把确认过的案件导出为证据包，用于内部复盘、平台投诉或后续维权。

## 5. 非目标

- 不做生产流量的阻断、清洗或自动封禁。
- 不做全量生产流量镜像或 inline 代理。
- 不做通用 WAF 规则市场。
- 不做 AI 意图识别或“是不是 AI Agent”的分类器。
- 不做完整 SSH、Redis、SMB、MySQL 等协议仿真；首版只做 HTTP/1.1 诱饵和通用 TCP 元数据监听。
- 不做主动扫描、反制、取证入侵或 hack-back。
- 不承诺识别具体自然人；L5 身份归因需要 ISP、平台或司法程序。
- 不提供法律代理，也不承诺证据必然被法院或平台采信。
- 不做多租户 SaaS、计费系统或独立 UI。
- 不替代认证、WAF、EDR、SIEM、NDR 或 Highwall。

## 6. 术语

| 术语 | 含义 |
|---|---|
| Sensor | 部署在一台主机或容器中的采集组件，可管理一个端点矩阵 |
| Collector | 接收、校验、去重、关联、保全和导出案件的中央组件 |
| Endpoint | 一个监听或对外暴露的 `IP:port`，是事件归属的最小网络单位 |
| Endpoint Matrix | 同一 Sensor 管理的一组端点，可跨多个 IP、多个端口 |
| Advertised Endpoint | 路由器/NAT/代理对公网暴露的地址，可能与监听地址不同 |
| Observed Endpoint | Sensor 实际接受连接的本地监听地址 |
| Profile | 某个服务的诱饵形态配置，数据而非代码 |
| Event | Sensor 记录的一次连接、请求或行为 |
| Case | 跨端点关联后的案件，证据的最小展示单位 |
| Canary | 唯一假凭据、假 URL、假 Cookie 或假 webhook |
| Canary Group | 为检测复用而部署到多个端点的一组受控 canary |
| Evidence Package | 可离线复核的证据包，含案件、事件、清单、哈希和保管记录 |
| Legal Hold | 法律保留：在保留期外冻结删除，直到显式解除并留审计 |
| Trace ID | 用于关联一次行为和案件的稳定标识 |
| Campaign | 由多个 Event/Case 关联出的攻击活动，不指具体人 |

## 7. 总体架构

```text
                Endpoint Matrix（多 IP × 多端口）
        ┌───────────────┼────────────────┐
   HTTP/1.1 诱饵   通用 TCP 元数据监听   Canary 注入
        └───────────────┼────────────────┘
                        ↓
              Sensor：本地缓冲 / 脱敏 / 批次签名
                        ↓ HTTPS 出站
   Collector：验签 → 去重 → 关联 → Case → 证据存储 → 告警/导出
                        ↓
        Markdown / JSONL / Evidence Package（可离线复核）
```

核心约束：

- 一个 Sensor 负责一个端点矩阵；端点可以是多个本机 IP、端口或 NAT 映射后的公网入口。
- `destination_ip:port` 必须来自实际监听 socket，不能相信请求里的 `Host` 头。
- `advertised_ip:port` 必须来自用户配置的端点映射。
- Sensor 只主动出站，不开放管理入站端口。
- Collector 不向 Sensor 下发命令，不提供远程执行通道。
- Collector 只接收脱敏事件和有界证据，不接收生产流量。
- 证据存储只追加；删除、保留期变更和 Legal Hold 都留审计。
- Highwall 只是可选入口；没有 Highwall 也能完整运行。

## 8. 组件

### 8.1 Sensor

职责：

- 按端点矩阵配置同时监听多个 `IP:port`。
- 按 Profile 提供 HTTP/1.1 诱饵，以及通用 TCP 元数据监听。
- 记录实际接收端点、来源、首包/首字节、时序和可选 tarpit 行为。
- 对命中诱饵的请求做延迟、tarpit 和假响应。
- 生成并注入 canary，在本地缓冲事件。
- 对事件批次签名并上报 Collector。
- 在断网时继续本地记录，恢复后补传。
- 定期上报端点健康、队列和时钟偏差。

不负责：

- 不做生产反向代理，不镜像生产流量。
- 不自动封禁来源。
- 不执行目标仓库或攻击者提供的代码。
- 不保存真实密钥和生产凭据。
- 不承诺完整模拟 SSH、Redis、SMB、MySQL 等协议。

### 8.2 Collector

职责：

- 接收 Sensor 事件批次并验证签名。
- 去重、排序、关联并生成 Case。
- 维护 Sensor 注册、端点清单、健康、时钟偏差和队列状态。
- 维护只追加证据存储、保留期、Legal Hold 和保管记录。
- 生成 Markdown/JSONL 案件包和可离线验证的 Evidence Package。
- 执行访问控制和导出策略。

不负责：

- 不控制 Sensor，不下发命令。
- 不执行诱饵请求，不主动访问攻击者。
- 不自动修改 Highwall 或防火墙策略。

### 8.3 CLI

首版提供命令行管理：

- 初始化 Sensor 和 Collector。
- 注册、查看和轮换 Sensor。
- 添加、检查和测试端点，验证 advertised/observed 映射。
- 查看案件、标记复核、设置 Legal Hold、导出案件。
- 检查 Sensor 健康、队列、时钟和同步状态。
- 校验 Evidence Package 的哈希和签名。

首版不做 UI；案件以 Markdown 和 JSONL 呈现。

### 8.4 Profile

Profile 是数据文件，描述某个服务的诱饵形态：

- 服务名、传输协议、默认端口、Host/路径匹配。
- 假响应状态码、Headers、Body 模板。
- 延迟/tarpit 策略。
- 需要记录和脱敏的字段。
- canary 注入位置和 canary group。

首版内置：

- Ollama
- ComfyUI
- 通用管理面板
- 通用 TCP 元数据监听器

通用 TCP 监听器只接受连接、记录首字节/banner/时序，可选 tarpit；不做完整协议交互。首版不支持仓库内自动加载任意代码插件；自定义 Profile 只能使用受限的数据字段。

## 9. 部署模式

| 模式 | 说明 | 生产影响 |
|---|---|---|
| 单机端点矩阵 | 同一 Sensor 监听多个本机 IP/端口，并关联 NAT 映射入口 | 无 |
| 代理上游 | Highwall/Nginx/Caddy/Traefik 把诱饵路径转发给 Sensor | 低，仅诱饵路径 |
| Highwall 伴生 | Highwall 路由诱饵路径，或导入 Highwall 审计事件 | 低，可选 |
| 多 Sensor 汇聚 | 多个 Sensor 各自管理端点矩阵，向一个 Collector 上报 | 无 |
| 离线导出 | Sensor 本地记录，人工导出 JSONL | 无 |

第一版优先支持单机端点矩阵、代理上游和多 Sensor 汇聚。Highwall 伴生作为适配器，不改变 Highwall 核心。

## 10. Highwall 兼容

兼容目标：EvidenceWall 独立运行，Highwall 可选接入，双方不共享进程、权限或生产配置。

### 10.1 路由接入

Highwall 可以把诱饵路径或诱饵 Host 路由到 Sensor，例如：

- `/.env`
- `/admin`
- `/api/tags`
- `/v1/models`

这些路径命中后由 Sensor 返回假响应并记录。Highwall 只做路由，不需要知道 EvidenceWall 的内部逻辑。

### 10.2 事件导入

Highwall 的审计或告警事件可以通过 Webhook/JSONL 导入 Collector，用于：

- 把 Highwall 的 `threat_suspected` / `threat_confirmed` 与 Sensor 事件关联。
- 在案件中标注“该来源也被 Highwall 看到”。
- 为人工研判提供双视角证据。

### 10.3 兼容边界

- 不改 Highwall 核心代码。
- 不把 EvidenceWall 的发现自动写回 Highwall 封禁规则。
- EvidenceWall 挂了不影响 Highwall。
- Highwall 挂了不影响独立 Sensor。
- 两者只共享 Profile 和证据 schema 的稳定契约。

## 11. 多端点矩阵监控

多端点矩阵是 v0.1 的硬要求，不是后续增强。

### 11.1 端点定义与最低验证规模

Endpoint 是一个 `IP:port`。Endpoint Matrix 是同一 Sensor 下的一组端点，至少覆盖多个端口；当主机或 NAT 提供多个地址时，也要覆盖多个 IP。

最低验证规模：

- 一个 Sensor 至少管理 2 个监听 IP（可以是回环、LAN、bridge）和 8 个诱饵端口。
- 测试矩阵至少包含 4 个 HTTP Profile 端点和 2 个通用 TCP 元数据端点。
- v0.1 不要求多个公网 IP 或 ASN；多 Sensor 汇聚是可选扩展。
- 每个 Sensor 有独立 ID、独立签名密钥；每个端点有稳定 `endpoint_id`。
- canary group 可跨端点复用，但必须记录部署位置。

### 11.2 端点映射

每个端点至少记录：

- `endpoint_id`
- `listen_ip` / `listen_port`
- `advertised_ip` / `advertised_port`
- `transport`（HTTP/1.1、TCP）
- `profile_id`
- `exposure`（direct、nat、proxy、edge）
- `source_quality`（direct、nat、edge-provided）

约束：

- 实际收到连接的地址来自监听 socket，不能从 `Host` 或 `X-Forwarded-For` 反推。
- 路由器/NAT 的端口映射必须显式配置，不能靠猜测。
- 反向代理或 Cloudflare Tunnel 后，来源 IP 标记为 `edge-provided`，不能当成直接来源。
- 同一个 `IP:port` 不得被两个端点重复注册。
- 端点配置变更要留版本和审计。

### 11.3 扫描形态

第一版至少识别：

- **纵向扫描**：同一来源在时间窗口内打同一 IP 的多个端口。
- **横向扫描**：同一来源打多个 IP 的同一端口或同一 Profile。
- **服务定向**：同一来源反复访问某个 Profile、路径或管理接口。
- **分布式复用**：不同来源复用同一 canary、指纹或路径序列。

扫描形态只作为关联信号，不等于确认攻击；必须在案件中显示依据和时间窗口。

### 11.4 同步与健康

- Sensor 只主动出站，使用 HTTPS 上报。
- 本地磁盘缓冲，断网不丢事件。
- 批量上报，至少一次投递，Collector 幂等去重。
- 事件带单调序号、时间和批次签名。
- 时钟偏差超过 60 秒要标记并告警，不静默当成准确时间。
- 缓冲达到上限时告警并停止接收新诱饵连接，不能静默丢弃旧证据。
- Collector 必须展示每个 Sensor 和端点的健康状态。

Collector 必须展示：

- 最后上报时间
- 待传队列长度
- 磁盘占用
- 时钟偏差
- 签名校验失败次数
- 版本和 Profile 版本
- 端点启用/禁用状态
- advertised/observed 映射是否一致

## 12. 流量溯源模型

EvidenceWall 使用“分层溯源”，避免把 IP 当成身份。每一层都要区分**记录到的事实**、**配置映射**和**推断**。

| 层级 | 证据 | 结论强度 |
|---|---|---|
| L1 来源 | IP、端口、ASN、网段、地区、反向 DNS、来源质量 | 请求来自哪里，不等于谁 |
| L2 指纹 | Header 顺序/形状、UA、TLS 指纹、首字节、路径序列、节奏 | 可能是同一工具或同一批行为 |
| L3 Canary | 唯一假凭据/假 URL/假 Cookie 在多个端点被复用 | 同一诱饵或同一工具链的强关联 |
| L4 端点案件 | 跨端点的时间线、扫描形态、指纹、来源和 canary 综合 | 可能是同一场攻击活动 |
| L5 身份 | ISP、VPN、平台、司法程序 | 具体是谁；本项目不承诺 |

证据分级：

- **观测事实**：实际收到的连接、监听地址、时间、Header 形状、报文摘要。
- **配置事实**：用户配置的 `advertised_ip:port` 和 NAT/代理映射。
- **推断**：同一工具、同一活动、同一来源；必须显示依据和置信度。
- **未验证**：具体身份和主观意图；不得写成结论。

对外表述必须使用“活动关联”“同一批行为”“置信度”，不能写成“锁定攻击者本人”。

禁止：

- 根据单个 IP 推断具体人。
- 把共享 NAT、VPN、Tor 出口或云厂商 IP 当成身份。
- 主动访问攻击者 IP 做“验证”。
- 使用攻击者提供的凭据登录任何系统。

## 13. Canary Token

Canary 是跨端点溯源的锚点。

类型包括：

- 假 API Key
- 假模型下载 URL
- 假 webhook URL
- 假 Cookie
- 假管理 token
- 假对象存储地址

要求：

- 每个 canary token 使用至少 128 位随机值，全局唯一。
- 可以按 **Canary Group** 把同一个 token 部署到多个端点，用于检测同一工具链的复用；必须记录 token 到端点的部署映射。
- 不在无关项目、租户或真实用户之间复用 token。
- Sensor 保存原始 token 用于注入诱饵；Collector 只保存哈希。
- 任何 Sensor 或 Collector 看到相同 token 哈希，都可以建立跨端点关联。
- Canary 不能是真凭据，不能指向真实生产资源。
- Canary 命中只生成证据和告警，不自动封禁。
- 轮换 canary 时保留旧哈希和历史命中，避免破坏既有案件。

Canary 的价值是关联工具链和活动，不是证明具体身份。

## 14. 关联规则

第一版使用确定性规则，不接 LLM 判定。

关联信号：

1. 相同 canary token 哈希：高置信。
2. 相同行为指纹 + 相似路径序列 + 时间窗口：中高置信。
3. 同一来源在时间窗口内扫同一 IP 的多个端口（纵向扫描）：中置信。
4. 同一来源在时间窗口内扫多个 IP 的同一端口或 Profile（横向扫描）：中置信。
5. 同一来源反复命中同一 Profile、路径或管理接口：中置信。
6. 相同来源 IP/网段 + 时间接近：中低置信。
7. 相同 ASN/托管商 + 相同工具特征：低置信，只作线索。
8. Highwall 事件与 Sensor 事件的时间、来源、路径匹配：辅助证据。

案件合并建议：

- 高置信信号可以直接合并。
- 中置信信号生成“疑似关联”，等待人工确认。
- 低置信信号不自动合并，只展示为相关线索。
- 扫描形态必须显示命中的端点列表、时间窗口和判定阈值。
- `edge-provided` 来源不得与直接来源共用“同一 IP”结论。
- 误关联必须能手动拆分并记录原因。

置信度必须在 Markdown 案件中显示，不能只显示“已关联”。

## 15. 数据模型

### 15.1 Sensor

- `sensor_id`
- `matrix_id`
- `public_key`
- `endpoint_ids`
- `profile_ids`
- `version`
- `last_seen`
- `clock_skew_ms`
- `queue_depth`
- `status`

### 15.2 Endpoint

- `endpoint_id`
- `sensor_id`
- `matrix_id`
- `listen_ip` / `listen_port`
- `advertised_ip` / `advertised_port`
- `transport`
- `profile_id`
- `exposure`
- `source_quality`
- `enabled`
- `config_version`

### 15.3 Event

- `event_id`（全局唯一）
- `sensor_id`
- `matrix_id`
- `endpoint_id`
- `sequence`
- `observed_at`
- `received_at`
- `source_ip`
- `source_port`
- `source_asn` / `source_prefix`（可选）
- `source_quality`
- `destination_ip` / `destination_port`
- `advertised_ip` / `advertised_port`
- `transport`
- `method` / `scheme` / `host` / `path`
- `headers_fingerprint`
- `tls_fingerprint`（仅 Sensor 终止 TLS 时）
- `body_size` / `body_sha256`
- `first_payload_size` / `first_payload_sha256`
- `canary_hashes`
- `response_status`
- `tarpit_ms`
- `profile_id`
- `highwall_event_id`（可选）
- `sensor_signature`

`destination_ip:port` 必须来自监听 socket；`advertised_ip:port` 必须来自端点配置，不能用请求头反推。

默认不保存完整 body、Cookie、Authorization、查询串原值。需要时只保存有界、脱敏后的摘要。通用 TCP Profile 如开启首字节记录，默认只保存最多 256 字节的脱敏前缀和哈希。

### 15.4 Case

- `case_id`
- `title`
- `first_seen` / `last_seen`
- `sensor_ids`
- `endpoint_ids`
- `source_ips` / `asns`
- `source_quality`
- `fingerprints`
- `canary_hashes`
- `scan_shape`
- `event_count`
- `confidence`
- `status`：new / reviewing / confirmed / dismissed
- `timeline`
- `evidence_hashes`
- `evidence_package_id`
- `legal_hold_id`
- `recommended_actions`
- `not_checked`

Case 是给人看的单位；Event 是机器记录的单位。

## 16. 证据完整性、保全与维权导出

### 16.1 完整性

- 每个 Sensor 生成 Ed25519 密钥对；Collector 注册公钥。
- 每个事件批次单独签名；Collector 验证签名、序号和时间。
- Case 内证据使用 SHA-256 哈希链，可选对整个案件签名。
- 导出案件时附带版本、哈希、生成时间和 Collector ID。
- 签名失败、序号回退、时间异常的事件不能静默进入正式案件。
- 证据缺失必须写入 `not_checked`，不能只展示成功部分。
- 条件成熟后可增加 RFC 3161 可信时间戳；v0.1 不承诺外部时间公证。

### 16.2 证据生命周期

| 阶段 | 动作 | 产物 |
|---|---|---|
| 采集 | Sensor 记录连接、请求和端点映射 | Event、脱敏摘要 |
| 保全 | 进入只追加证据存储，记录哈希和保管日志 | Evidence Record |
| 关联 | 跨端点归并来源、指纹、canary 和扫描形态 | Case、Timeline |
| 复核 | 人工确认或拆分，必要时设置 Legal Hold | Review Record |
| 导出/移交 | 生成可离线验证的证据包 | Evidence Package |

### 16.3 Legal Hold

- 用户可以按案件、来源或时间范围设置 Legal Hold。
- 必须记录原因、范围、操作者、开始时间和预期期限。
- Legal Hold 期间不得自动删除相关事件、案件和证据包。
- 解除 Legal Hold 必须显式确认并留审计；不能由保留期任务自动解除。
- Legal Hold 只冻结已有证据，不扩大采集范围，也不改变隐私默认值。

**M3 实际能力边界**：当前版本已持久化 Legal Hold 的原因、操作者、期限、状态和审计记录；CLI/API 解除时必须显式确认。当前版本**没有保留期删除任务**，因此不能宣称“自动删除已被可靠阻止”。在删除任务实现前，操作者不得手工删除处于 active 状态的案件、事件或证据包；未来删除任务必须先查询 active Legal Hold 并拒绝删除，解除 hold 只能通过显式确认和审计完成。

### 16.4 Evidence Package

导出目录至少包含：

- `case.md`：一页式案件摘要、时间线和置信度。
- `events.jsonl`：脱敏后的事件记录。
- `batches.jsonl`：签名批次记录。
- `sensors.jsonl`：相关 Sensor 公钥和注册信息。
- `chain.jsonl`：事件证据哈希链。
- `highwall.jsonl`：已关联 Highwall 事件的有界归一化记录；只作为辅助证据，不含上游签名，且不包含任意 headers、Cookie、Authorization 或正文。
- `timeline.md`：按时间排序的端点、来源和行为。
- `manifest.json`：schema 版本、Collector ID、生成时间、文件哈希、签名、保留期和 Legal Hold 状态。
- `custody.jsonl`：采集、访问、导出、保留期变更和 Legal Hold 操作记录。
- `not_checked.md`：未覆盖端点、未采集字段、证据缺口和限制。
- `README.md`：包内离线校验说明和信任边界。

导出前应确认案件状态、Legal Hold 和保留期；对外维权只使用已复核案件。导出包默认只读，不修改原始证据；离线校验命令验证文件哈希、Collector 签名、Sensor 事件/批次签名、事件哈希链、Highwall 记录哈希和 manifest 完整性。Highwall 记录与 Sensor 事件不同，没有上游系统签名，不能单独用本包证明其原始来源。证据包用于内部处置、平台投诉、民事维权或执法初筛；是否采信由对应机构判断，本项目不提供司法鉴定承诺。

## 17. 隐私与法律边界

- 默认只记录请求元数据和脱敏摘要，不记录完整正文。
- 默认不保存 Cookie、Authorization、真实密钥和完整查询串。
- 完整 IP 只放在受限证据存储，报告中默认截断或分级展示。
- 支持按案件、Sensor、端点和时间设置保留期。
- 支持导出和删除；删除动作本身要留审计。
- Legal Hold 可以延长保留期，但不能绕过数据最小化原则。
- 不同司法辖区部署要遵守当地数据保护、取证和存储法律。
- 不采集真实用户登录凭据；诱饵不得伪装成真实的登录页面骗取密码。
- 不做主动反制、报复、入侵或“反黑”。
- 维权材料由用户授权导出；导出和移交动作进入保管链。

建议默认值：原始事件保留 90 天，案件元数据保留 365 天；均可配置。进入 Legal Hold 的案件不受默认删除影响。**M3 当前只交付了 Legal Hold 记录和审计，尚未实现 `retention set`、保留期任务或删除功能；上述默认值是后续实现目标，不是当前运行时行为。**

## 18. 安全边界

### 18.1 Sensor

- 独立容器或低权限用户运行。
- 每个端点独立监听，只开放诱饵端口；管理口不暴露公网。
- 不挂载真实 SSH、云凭据、生产配置或 Docker socket。
- 不使用 privileged。
- 根文件系统只读，数据目录独立。
- 默认无出站，只允许 Collector 和告警出口。
- 端点配置、advertised 映射和 Profile 必须校验，禁止从请求动态生成监听目标。
- 优先放在独立网络或 VLAN；路由器只转发诱饵端口，关闭 UPnP。
- 被攻破时：隔离、导出证据、轮换 Sensor 密钥、销毁重建。

### 18.2 Collector

- 不提供 Sensor 命令通道。
- 不执行 Sensor 提交的任何代码或模板逻辑。
- 管理 API 和接入 API 分开。
- 当前实现：管理查询与上报共用一个 FastAPI 应用，且没有内置管理员认证；生产环境必须放在带认证、TLS 和来源限制的反向代理后，或只绑定回环地址。
- 证据存储只追加，定期校验哈希链并备份。
- 最小权限、速率限制、审计和备份。
- 与生产网络、生产凭据隔离。

### 18.3 供应链

- 固定依赖版本，生成 SBOM。
- 发布物带 SHA256；条件成熟后签名。
- Profile 只允许受限数据字段，不允许执行脚本。
- 不从目标仓库自动加载插件。

## 19. API 与传输

首版建议接口：

| 接口 | 用途 |
|---|---|
| `POST /v1/sensors/enroll` | Sensor 一次性注册 |
| `POST /v1/events:batch` | 签名批次上报 |
| `GET /v1/endpoints` | 端点矩阵和映射状态 |
| `POST /v1/endpoints/{id}/test` | 端点本地连通性和映射检查 |
| `GET /v1/cases` | 案件列表 |
| `GET /v1/cases/{id}` | 案件详情 |
| `POST /v1/cases/{id}/review` | 记录人工复核状态和备注 |
| `GET /v1/cases/{id}/evidence` | 证据清单和校验状态 |
| `POST /v1/cases/{id}/hold` | 设置或解除 Legal Hold |
| `POST /v1/cases/{id}/export` | 生成 Evidence Package |
| `GET /v1/sensors` | Sensor 健康 |
| `GET /healthz` | Collector 健康 |
| `POST /v1/highwall/events` | 可选 Highwall 事件导入 |
| `GET /v1/highwall/events` | 可选 Highwall 事件查询 |

M3 实现状态：

- 已实现：`/healthz`、`/v1/sensors/enroll`、`/v1/events:batch`、`/v1/sensors`、`/v1/endpoints`、`/v1/cases`、`/v1/cases/{id}`、案件复核、Legal Hold、证据导出/校验、`/v1/canaries`、Canary 签名同步、Highwall 导入和查询。
- 尚未实现：`/v1/endpoints/{id}/test` 的管理 API 端点（CLI 已有本地端点测试）；管理员认证；保留期删除任务。
- Collector 是明文 HTTP/1.1，管理接口没有内置独立认证；生产部署必须使用带认证和来源限制的 HTTPS 反向代理。非回环绑定必须显式传入 `--allow-remote`，否则 CLI 拒绝启动。

传输要求：

- HTTPS。
- Sensor 出站连接。
- 批次签名 + 幂等键。
- Collector 不接受任意远程命令。
- 管理接口使用独立凭据和来源限制（当前尚未内置，需由部署层补足）。
- 证据导出必须签名并带 manifest；导出动作进入保管链。

## 20. CLI

目标命令：

- `evidencewall matrix init`
- `evidencewall endpoint add`
- `evidencewall endpoint list`
- `evidencewall endpoint test <id>`
- `evidencewall sensor init`
- `evidencewall sensor run`
- `evidencewall collector run`
- `evidencewall sensor list`
- `evidencewall case list`
- `evidencewall case show <id>`
- `evidencewall case review <id>`
- `evidencewall case hold <id> --reason <text>`
- `evidencewall case export <id> [--output <dir>] [--no-archive]`
- `evidencewall evidence verify <bundle>`
- `evidencewall retention set`
- `evidencewall doctor`

M3 已实现：`matrix init`、`endpoint add/list/test`、`sensor init/enroll/run/status`、`collector init/run/status/token rotate`、`profile list`、`canary create/list/rotate/sync`、`case list/show/review/hold/export`、`evidence verify`、`doctor`、`sensor emit-test`。`collector run` 在绑定非回环地址时要求显式 `--allow-remote`。其中 `retention set` 尚未实现；Legal Hold 目前只记录和审计，没有删除任务可被阻止。

不在首版做 GUI、托盘程序或嵌入壳。

## 21. v0.1 范围

必须：

- 端点矩阵配置：至少 2 个监听 IP、8 个端口，支持 advertised/observed 映射
- HTTP/1.1 诱饵和通用 TCP 元数据监听
- 3 个内置 HTTP Profile + 通用 TCP Profile
- Sensor + Collector
- 本地缓冲与断网补传
- Canary Group 生成和跨端点复用关联
- 跨端点案件关联，识别纵向/横向/服务定向/分布式复用
- Markdown + JSONL + Evidence Package
- 证据哈希链、Legal Hold、保留期
- Sensor 和端点健康、时钟偏差、映射一致性
- 脱敏、导出、离线校验
- Highwall 路由接入
- Highwall 审计事件导入（可选）

不做：

- UI
- 完整 SSH/Redis/SMB/MySQL 协议仿真
- 自动封禁
- 主动扫描
- 多租户 SaaS
- 全量 PCAP
- 生产流量镜像或 inline 代理
- 法律代理或司法鉴定承诺

### 21.1 M2 已交付边界（历史）

M2 已交付真实 HTTP/1.1 和通用 TCP 元数据监听、4 个内置 Profile、Canary Group、候选事件生成、基础案件聚合、Canary 部署查询和 CLI。M2 阶段案件按 `source_quality + source_ip` 聚合，只提供案件列表、详情和时间线；该阶段边界已由 M3 扩展。

M2 当时尚未交付跨端点扫描形态、工具链关联、证据包、Legal Hold、离线校验、Highwall 事件导入和管理员认证。这些缺口已由 M3 补齐（管理员认证除外）。

### 21.2 M3 已交付边界

M3 已交付：

- 确定性跨来源、跨端点关联、纵向/横向扫描形态、服务定向、Canary 和指纹复用、24 小时滑动窗口。
- Collector 独立 Ed25519 身份和证据包签名；Sensor 事件和批次签名仍作为链式证据保留。
- Evidence Package 目录/ZIP、事件哈希链、custody、Highwall 辅助记录、manifest 签名和离线校验。
- 人工复核、Legal Hold 记录/解除确认、Highwall 白名单导入、Canary 签名增量同步。
- 案件证据 API 在 ZIP 丢失时回退到仍存在的目录。

尚未交付：

- 管理员认证、TLS 终止和来源限制；仍需部署层补足。
- 保留期删除任务；因此 Legal Hold 目前只有记录和审计，不能宣称自动删除被阻止。
- 真实公网多 IP、多端口 T0/T1 拓扑验收；当前只有本地真实 socket、合成事件和 API/CLI 测试。
- 上游 Highwall 事件签名；`highwall.jsonl` 是 Collector 对导入内容的记录，不是 Highwall 的签名证明。

## 22. 验证与指标

### 22.1 资产受限测试床

测试床资源：本地 Windows/WSL、Docker bridge、家用路由器和受控代理即可开始；不要求先购买 VPS。按 T0 → T1 → T1.5 逐级验证，T2 不作为 v0.1 门槛。

截至 M3，自动化测试使用本地真实 socket、合成事件和 Collector API；T0/T1 的真实多入口拓扑尚未执行，因此不能把当前结果当作公网部署验收。

| 层级 | 环境 | 能验证 | 不能宣称 |
|---|---|---|---|
| T0 | WSL + Docker，多 bridge 网络、多 IP、多端口、合成攻击器 | 端点模型、纵向/横向扫描、canary 复用、签名/缓冲/证据包 | 公网暴露、真实背景扫描 |
| T1 | 路由器只转发高位诱饵端口到 WSL，单点真实公网入口 | NAT advertised/observed 映射、真实探测、来源质量 | 多公网 IP/ASN |
| T1.5 | 手机热点或已有反向隧道，有限第二入口 | 多 Sensor 汇聚、跨网络来源标记 | 独立公网 IP 或真实多地区 |
| T2 | 真正独立公网 IP/ASN | 真实多网络观测 | 当前资产不足，暂不做 |

边界：

- WSL 多 bridge/IP 只叫逻辑多端点，不是公网多 IP。
- Clash/V2Ray 等出站代理只能模拟攻击源，不是 Sensor 入口。
- Cloudflare Tunnel 或 CGNAT 后的来源标记为 `edge-provided`，不当作直接来源。
- 只转发诱饵端口；不暴露 Collector、SSH、RDP、Docker API。
- 关闭 UPnP；诱饵放独立网络或防火墙规则后。
- T0/T1 通过前不购买 VPS。

### 22.2 验证项

| 测试 | 通过条件 |
|---|---|
| 端点注册与映射 | 每个 `listen_ip:port` 有稳定 ID，`advertised_ip:port` 与路由器映射一致 |
| 纵向扫描 | 同一来源打同一 IP 的多个端口，生成可解释的扫描形态 |
| 横向扫描 | 同一来源打多个 IP 的同一端口/Profile，生成可解释的扫描形态 |
| Canary 复用 | 同一 token 在多个端点命中时能形成高置信关联 |
| 证据完整性 | 批次签名、哈希链、manifest 和离线校验全部通过 |
| 故障恢复 | 断网期间继续缓冲，恢复后补传且不重复 |
| 时钟异常 | 偏差超过阈值时标记，不静默进入正式案件 |
| Legal Hold | 当前版本：记录、查询和显式确认解除并留审计；自动删除任务尚未实现，所以“阻止自动删除”这一项待后续实现后验证 |
| Highwall 兼容 | Highwall 开启或关闭都不影响 Sensor 独立运行 |
| 生产隔离 | 诱饵故障、端口暴露或 Sensor 被攻破不影响生产服务 |

验证范围以 T0/T1 为主；T1.5 可选；T2 只在资产具备后再做。

### 22.3 指标

- 首次诱饵命中时间
- 跨端点关联案件数
- 高置信关联占比
- 误关联率
- 从事件到案件的延迟
- 报告阅读和人工确认率
- 端点在线率、时钟偏差、队列积压
- 部署到首次成功上报的时间
- Evidence Package 离线校验通过率
- Legal Hold 操作可追溯率
- 用户是否愿意继续运行

### 22.4 成功条件

- T0 受控测试至少形成一组跨端点关联。
- 能识别纵向扫描和横向扫描，并显示命中的端点、时间窗口和依据。
- canary 在同一工具链的多个端点复用时可关联。
- 1 页案件能让人判断“背景扫描还是针对性活动”。
- 用户能在 10 分钟内部署一个端点矩阵。
- Evidence Package 能在离线环境完成哈希、签名和 manifest 校验。

### 22.5 失败条件

- T0 受控测试无法形成任何跨端点关联。
- 无法准确区分监听端点与对外暴露端点。
- 30 天内没有可用证据，或报告看完无法做决定。
- 证据包无法离线校验，或 Legal Hold 不能可靠阻止删除。
- 部署复杂到需要维护者全程协助。
- 只能记录背景噪音，无法形成案件价值。


## 23. 风险与开放问题

风险：

- 诱饵不可发现，导致长期零命中。
- NAT、CGNAT、反向代理或 Cloudflare Tunnel 隐藏真实来源，导致来源判断错误。
- 端点时间不同步，导致错误关联。
- Canary 被攻击者识别并故意污染。
- Collector 成为集中攻击目标。
- 证据包含隐私数据，带来合规风险。
- Profile 太假，扫描器不感兴趣。
- 跨端点关联过度自信，误导研判。
- 路由器端口映射配置错误，暴露非诱饵服务。
- 证据保留与磁盘容量冲突，导致过早删除或无法保全。
- 范围蔓延成完整协议仿真器或全量 NDR。

开放问题：

- Collector 首版用 SQLite 还是嵌入式 KV。
- Sensor 注册使用一次性 token 还是预共享密钥 + 公钥。
- 是否默认启用离线 ASN/GeoIP 数据。
- Highwall 审计事件的最小映射字段。
- 是否允许用户自定义 Profile，以及允许到什么程度。
- 原始证据保留 90 天是否合理。
- 是否需要可选的 PCAP 有界采集。
- 是否需要 RFC 3161 可信时间戳，以及放在哪个里程碑。
- Legal Hold 的 CLI 是否需要二次确认和导出审批。

## 24. 里程碑

| 阶段 | 交付 |
|---|---|
| M0（已完成） | 本规格评审通过 |
| M1（已完成） | 端点矩阵、事件 schema、签名与本地缓冲 |
| M2（已完成） | HTTP/1.1 + 通用 TCP 元数据监听、4 个 Profile、Canary Group、基础案件生成 |
| M3（已完成） | 跨端点关联、扫描形态、Evidence Package、Legal Hold 记录、Highwall 导入、Canary 增量同步 |
| M4（待开始） | T0/T1 测试床、真实多入口验收、30 天证据报告；保留期删除任务和 Legal Hold 运行时保护需在删除功能落地时同步完成 |

## 25. Kill Criteria

出现以下任一情况，停止投入或重新定位：

- T0 受控测试无法形成任何跨端点关联。
- 无法准确区分 advertised/observed 端点。
- Evidence Package 无法离线校验，或 Legal Hold 不可靠。
- 关联结果无法被人复核，或误关联率不可接受。
- T1 暴露后长期零命中，调整 Profile/端点后仍无改善。
- 部署需要暴露管理端口或高风险管理面。
- 为支持更多协议而被迫变成完整协议仿真器、第二个高墙或全量 NDR。
- 证据报告没人看，或无法帮助决策。

## 26. 决策记录

- 独立产品，不作为 Highwall 内部插件。
- 多端点矩阵和跨端点溯源是 v0.1 硬要求，不以多地区/多 ASN 为前提。
- 证据发现、保全、溯源和后续维权导出是产品主链路。
- 保留期和 Legal Hold 由用户控制；Legal Hold 解除需要显式确认和审计。
- 不自动封禁，不做 hack-back，不做主动反制。
- 不做 UI；CLI + Markdown/JSONL + Evidence Package。
- M2 的基础案件聚合只作为 M3 关联的输入；M3 已完成确定性跨端点归因，但仍需真实 T0/T1 拓扑验收。
- Canary 部署映射在 Sensor 注册时写入 Collector；M3 已实现轮换后的签名增量同步。
- M3 的 Legal Hold 是持久化记录和审计，不是删除保护；删除任务实现前不得宣称自动删除被阻止。
- M3 的 Highwall 记录是辅助导入，不创建案件、不回写封禁规则，也没有上游签名。
- Collector 非回环绑定必须显式使用 `--allow-remote`；默认回环保守，避免未认证管理面被误暴露。
- 首版做 HTTP/1.1 + 通用 TCP 元数据监听，不做完整协议仿真。
- 单端点只算蜜罐；跨端点关联才叫 EvidenceWall。
- 先通过 T0/T1 验证，不购买 VPS 作为前置条件。
- Highwall 可选接入，不共享进程/权限，不自动回写封禁规则。
