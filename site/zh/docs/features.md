---
title: 特性
description: Vigilyx 的核心产品能力，覆盖旁路镜像、Inline MTA、检测流水线、DLP、YARA、隔离区、SOAR 与远程部署工作流。
---

# 特性

Vigilyx 不是只给一个“风险分”的黑盒网关。它把邮件会话采集、MIME 解析、检测模块、证据融合、隔离处置和运维部署都放在同一个开源工程里，安全团队可以直接查看规则、调试模块、扩展检测逻辑，并按自己的邮件链路选择旁路或 Inline。

## 一页看懂

| 能力 | Vigilyx 实际做了什么 |
| --- | --- |
| 旁路镜像监控 | 通过 `vigilyx-sniffer` 基于 libpcap 捕获 SMTP、POP3、IMAP 流量，不改现有邮件服务器链路；HTTP/Webmail 捕获要求 API 返回非空 Webmail 列表。标准 API 默认列表为空，需在 UI/API 配置目标服务器 |
| Inline MTA 代理 | `vigilyx-mta` 作为 SMTP relay，在投递前完成解析和检测，并按当前策略转发、隔离、拒收或临时失败 |
| 同一套检测栈 | sniffer 和 MTA 共用 `vigilyx-parser`、`vigilyx-engine` 与 verdict 逻辑，旁路告警和投递前拦截不会分裂成两套规则 |
| 可解释判定 | 每个模块输出 threat level、confidence、category、evidence，最后进入 evidence fusion，而不是只给不可复核的模型分数 |
| 数据安全 | HTTP/Webmail DLP、草稿箱滥用、分片上传重组、自发自收、文件中转、JR/T 0197-2020 分类映射和独立的 SMTP 外发邮件审查 |
| 隐私访问 | 默认内容遮罩、独立审计审批和按资源/范围授权的短时访问租约 |
| 自主部署 | Docker Compose 部署；AGPL-3.0-only；AI、ClamAV、Sandbox 都是可选集成 |

## 部署形态

### 旁路镜像模式

旁路模式适合先观察、后处置的安全团队。Vigilyx 从镜像口或主机网卡读取流量，重组邮件和 Webmail 会话，再通过 Redis Streams 交给独立 engine 处理。

- 不需要改 MX、MTA 或业务邮件服务器配置
- 支持 SMTP、POP3、IMAP 流量入口；标准 Compose 部署应通过 UI/API 配置 HTTP 捕获；API 会返回已保存设置或内置默认值，并覆盖响应中存在的 Sniffer 环境字段。内置 Webmail 列表为空，因此默认关闭 HTTP 捕获
- 可检查的 SMTP 内容可重建；POP3/IMAP 当前只提供协议元数据和覆盖信号，不重建分析邮件正文。加密或不完整载荷保留覆盖缺口。
- 成功写入且仍保留在 Stream 中的消息由 Redis Streams + consumer groups 按 at-least-once 语义处理；发布重试耗尽和 `MAXLEN` 修剪仍可能造成消息丢失
- 单条、批量与隔离区释放重扫请求使用 Streams；Pub/Sub 用于 reload 命令及 verdict/status 通知
- PostgreSQL 持久化会话、verdict、YARA 规则、隔离区和数据安全事件

### Inline MTA 代理模式

MTA 模式适合需要投递前处置的场景。`vigilyx-mta` 在 25 端口先完成 SMTP greeting/EHLO，再按策略协商 STARTTLS；465 端口在连接后立即进行隐式 TLS。随后解析 MIME 并执行 inline engine 判定，再决定 relay、quarantine、reject 或临时失败。

- 支持 25/465 入口和本地域名配置
- `MTA_INLINE_TIMEOUT_SECS` 控制 inline 判定超时，编译与 Compose 默认值均为 8 秒
- `MTA_FAIL_OPEN` 可配置引擎故障后返回 451，或尝试继续转发；出站 DLP 仍可隔离或阻断
- 当前代码默认从 Medium 起隔离、从 Critical 起以 `550 5.7.1` 拒收；这两个阈值不是环境变量
- 完整检查后的 Safe/Low 才会按默认策略转发；判定已完成但覆盖不完整的 Safe/Low 会隔离，阻断判定的模块失败/超时或必需依赖不可用时默认返回 451，fail-open 可尝试继续转发。出站 DLP 会扫描并记录审计，但只有投递计划原本会中继的邮件才执行告警、隔离或阻断处置。
- 最终动作还会受到 DLP 策略、引擎可用性和当前运行时配置影响
- 隔离邮件保留 raw EML，后续可以在控制台或 API 中放行、删除和审计

## 解析与会话重建

Vigilyx 的解析层不是 UI 上的展示字段拼接，而是 sniffer、MTA、engine 之间共享的基础能力。

- `vigilyx-parser` 提供 SMTP 状态、MIME、正文、附件和头部解析
- `vigilyx-sniffer` 负责 TCP 会话管理和被动协议识别
- `vigilyx-mta` 使用同一套 parser 构造投递前 `EmailSession`
- engine 同时处理 `EmailSession` 和 `HttpSession`
- 附件会进入类型识别、内容启发式、哈希、QR 和 YARA 等模块；AV 仅在 ClamAV 已启用且可达时运行
- HTML 会进入隐藏元素、CSS cloaking、像素画、iframe、跳转链和 landing page 分析

旁路和 MTA 邮件使用共享的 `EmailSession` 与邮件 `SecurityVerdict` 模型。Webmail 的 HTTP 上传下载使用独立的 `HttpSession`、`DataSecurityIncident` 模型和数据安全表，不会写入邮件 verdict 存储路径。

## 检测流水线

当前编译默认顺序包含 29 个 pipeline 配置项，其中包括最终 `verdict` 阶段以及需要外部服务或显式 opt-in 才能工作的条目。PostgreSQL 保存的活动配置可以覆盖代码默认值；“配置项存在”不等于对应外部能力正在运行。核心条目包括：

| 模块 | 关注点 |
| --- | --- |
| `header_scan` | 发件人伪造、SPF/DMARC/Received 链、头部 IOC |
| `content_scan` | 资金、密码、紧急、钓鱼话术和可配置关键词 |
| `semantic_scan` | 本地语义规则、可选 CPU ONNX 意图模型和可选 Python NLP |
| `link_scan` | 短链、IDN、homoglyph、可疑参数、URL 结构异常 |
| `link_reputation` | OTX、VirusTotal、AbuseIPDB 与本地 IOC 缓存 |
| `link_content` | DGA、品牌仿冒、混合字符域名和登陆诱导 |
| `landing_page_scan` | 链接落地页内容、表单、认证诱导和重定向风险 |
| `url_sandbox_scan` | 延迟 URL 动态分析结果；默认关闭，不参与 Inline MTA 判定 |
| `process_sandbox_scan` | 显式启用后由独立进程记录有界行为；不独立判定威胁，内核隔离尚未完成 |
| `aitm_detect` | Evilginx/Tycoon2FA/EvilProxy 一类 AitM 反向代理钓鱼特征 |
| `rmm_detect` | 远程管理工具话术、链接与载荷线索 |
| `prompt_injection_scan` | 邮件内容中的提示注入式指令线索 |
| `toad_detect` | 以回拨电话号码为核心的攻击投递线索 |
| `html_scan` | HTML 混淆、隐藏元素、零宽字符、CSS 欺骗 |
| `html_pixel_art` | HTML 表格/像素画二维码、跟踪像素、隐形 iframe |
| `mime_scan` | MIME 结构异常、头注入、边界和内容声明问题 |
| `attach_scan` | 扩展名与 magic bytes 不一致、可执行伪装 |
| `attach_content` | 宏、脚本、压缩包、敏感诱导内容 |
| `attach_qr_scan` | 附件和图片中的二维码钓鱼入口 |
| `attach_hash` | 附件 SHA-256 与恶意样本/IOC 命中 |
| `yara_scan` | EML 和附件的内置 + 数据库自定义 YARA 规则扫描 |
| `domain_verify` | Envelope、DKIM、链接域名和可信域对齐 |
| `identity_anomaly` | 首次联系、发件身份漂移、历史通信异常 |
| `transaction_correlation` | 跨会话业务流程与欺诈链路关联 |
| `anomaly_detect` | 统计特征异常 |
| `verdict` | 汇总模块证据并生成最终风险等级与处置建议 |

ClamAV 可注册 `av_eml_scan` 和 `av_attach_scan`，CAPEv2 URL 与 token 同时配置后才会注册 `sandbox_scan`。AI 关闭时 `semantic_scan` 不提供远程 NLP 证据，但其余 Rust 检测链仍可运行。当前默认顺序的源码在 `crates/vigilyx-engine/src/pipeline/config.rs`，实际模块注册逻辑在 `crates/vigilyx-engine/src/modules/registry.rs`。

### 语义模型模式

本地语义规则不依赖 Python AI 服务。提供有效的 `SEMANTIC_INTENT_MODEL_DIR`
和 `ORT_DYLIB_PATH` 产物后，引擎可在 CPU 上运行 bge/e5 ONNX 集成模型。
默认只在影子模式记录 `semantic_intent_model` 诊断；有效的
`SEMANTIC_INTENT_SCORE_THRESHOLD` 显式切换到计分模式，替代本地语义规则及后续
Python NLP/OCR 路径。达到阈值时以 Low 模块分数 0.20 进入融合，不保证最终等级
或处置。加载失败会警告并禁用模型，检查不完整仍保留覆盖缺口。当前 Compose
的模型接线在旁路 engine，MTA 需要单独配置。

## 证据融合与时序分析

Vigilyx 会在融合、风险约束和最终模式处置中保留模块证据与因果来源。

- 默认运行策略是 `clustered_ds_v2`；历史配置名 `ds_murphy`、`clustered_ds_v1`、`legacy_ds_murphy` 会归一到该策略
- 可显式选择 TBM（`tbm_v5`）、Noisy-OR、Weighted Max
- 模块会保留 evidence、category、confidence 和命中原因，方便分析师复盘
- 运行证据保留因果键，便于去除同一产物的重复视图
- 时序分析包含 CUSUM、EWMA、Hawkes 自激过程、HMM 攻击阶段建模和通信图特征

学习得到的 D-S 参数另有候选、验收、安装与回退流程，反馈或训练不会自动启用新模型。风险等级是检测输出，不是“已证实恶意”的结论；部署前仍需用本地样本验证阈值和处置策略。

## AitM、HTML 与 YARA

Vigilyx 对现代钓鱼邮件做了几类比较具体的检测，而不只是搜索“verify your account”。

- AitM 模块会为托管平台域名、认证路径、OAuth redirect、MFA/验证码话术、CAPTCHA 和品牌同形域名等线索生成证据
- HTML 模块会分析隐藏表单、CSS 隐藏、零宽字符、可疑 iframe 和追踪像素等结构线索
- `html_pixel_art` 分析 HTML 表格或像素块构造的图形线索；附件与内嵌图片 QR 由 `attach_qr_scan` 处理
- YARA 引擎加载内置规则、管理员自定义数据库规则以及显式配置的受治理规则包；规则数量会随版本和运行配置变化
- YARA 扫描 raw EML、正文片段和附件字节流，但单条规则命中仍需结合规则来源和其他证据复核

## DLP 与数据安全

数据安全包含 HTTP/Webmail 事件和独立的 SMTP 外发邮件审查，两者均与邮件威胁 verdict 分开记录。

- DLP 使用可审计的 pattern family 覆盖通用敏感信息和 JR/T 0197-2020 映射；具体数量以当前源码/种子为准
- 扫描采用 512 KiB 窗口、256 字节重叠、50 MiB 总输入上限和 10 秒预算，并保持 UTF-8 边界安全
- 支持 Coremail 等 Webmail 表单字段抽取
- `chunked_upload` 会按 composeId、attachmentId、offset 重组分片上传
- `draft_detect` 识别草稿箱中转敏感数据的行为
- `self_send_detect` 识别自发自收绕过外发审计
- `file_transit_detect` 识别通过附件、下载、转发构造的数据中转路径
- `jrt_compliance` 会按用户/IP 统计 24 小时累计 C3/C4 敏感数据触发阈值

这部分适合银行、企业邮箱、内网 Webmail 和需要把“邮件安全”扩展到“数据外发治理”的环境。

### SMTP 外发邮件审查

SMTP 外发审查独立于 HTTP 事件和邮件威胁 verdict。旁路模式只能审计可检查的邮件，
不能阻断或隔离；MTA 出站 DLP 可按策略对原本会中继的邮件告警、隔离或阻断。
方向判定使用可信来源、域名及收件人证据，仅有看似本地的 `MAIL FROM` 不足以认定外发。
加密、方向未知、载荷不完整及检查失败保留为未知状态。列表、统计和详情接口为
`GET /api/data-security/email-reviews`、`GET /api/data-security/email-reviews/stats`
及 `GET /api/data-security/email-reviews/{id}`。

## 隐私与临时内容访问

隐私模式默认遮罩内容，仍可查看安全分析。管理员填写具体资源、访问范围及用途，
并使用本人已配置的验证因子提出申请；独立 audit 用户使用单独的因子审批或拒绝。
申请人随后获取绑定本人、JWT 登录会话、精确资源及访问范围的租约。
申请时长限制在 60–300 秒，租约最长五分钟。

在「系统设置 → 隐私」管理策略与申请。策略接口为 `GET/PUT /api/config/privacy`，
申请使用 `GET/POST /api/privacy/access-requests` 及对应的 approve、reject、revoke、
lease 子路由。策略缺失或不可读取时默认开启遮罩；关闭隐私后凭据仍被遮罩，
已脱敏持久化的审查证据不能通过修改策略还原。

## 隔离区、SOAR 与审计

Vigilyx 的处置链路覆盖自动动作和人工复核。

- 风险等级从 Safe、Low、Medium、High 到 Critical；它们表示风险分段，不代表恶意性已被证明
- MTA 模式按当前策略隔离或拒收，部署前应验证实际持久化配置
- 隔离区支持列表、统计、放行、删除和原始 EML 保存
- 放行前，API 会让引擎重新扫描隔离区保存的原始 EML；复扫达到 High 或 Critical 时会阻止放行
- 引擎、复扫通道、解析或超时导致无法取得新判定时，放行按 fail-closed 处理并恢复为隔离状态；投递失败也会回滚放行状态
- SOAR 支持告警分发、邮件通知、Webhook 和处置规则
- API 与 WebSocket 给前端控制台提供实时 verdict、会话详情和系统状态

## 运维与工程工作流

项目按远程优先部署设计，适合一台 Rocky Linux 服务器上直接跑完整栈，也能按 profile 拆开能力。

- `./deploy.sh` 默认使用 `release-fast` 和持久化 `vigilyx-rust-builder`，日常改动走增量编译
- `./deploy.sh --production` 切换到完整 Dockerfile 和 `cargo --release`
- `--frontend`、`--backend`、`--sniffer`、`--mta` 可以按组件更新
- 前端 React SPA 打包进 `vigilyx` 镜像，镜像 tag 对应确定的前端版本
- API 默认绑定 `127.0.0.1:8088`，生产建议用 Caddy/Nginx 做 TLS 终结
- AI、ClamAV、Sandbox、TLS reverse proxy 都通过 Compose profile 或配置启用
- 核心服务不需要联网授权；外部情报源和 AI 服务可以按环境关闭

Compose profile 不会自动停止由其他 profile 启动的服务。运行中的主机切换拓扑时，请使用部署脚本。

除仅初始化的 `--init` 外，每次部署（包括 `--frontend`）都会先短暂停止当前运行的
API、engine、sniffer、MTA，再协调依赖和数据库角色，成功或失败都会尝试恢复原运行状态。
需为抓包和 Inline SMTP 中断安排维护窗口。
仅本次生成新 API 二进制时执行 schema 迁移：后端/完整部署及生产模式的前端构建。
快速前端、仅 sniffer 和配置部署保留已安装的 SQL 函数。部署还会核对 PostgreSQL
生效参数及旁路队列积压，不自动调整宿主机/网络设置。

## 代码位置

| 能力 | 主要代码路径 |
| --- | --- |
| SMTP/MIME 解析 | `crates/vigilyx-parser/` |
| 旁路抓包与会话管理 | `crates/vigilyx-sniffer/src/capture/`、`crates/vigilyx-sniffer/src/session/` |
| 检测模块注册 | `crates/vigilyx-engine/src/modules/registry.rs` |
| Inline 判定 | `crates/vigilyx-engine/src/pipeline/engine.rs` |
| MTA 代理 | `crates/vigilyx-mta/src/server/`、`crates/vigilyx-mta/src/relay/` |
| AitM 检测 | `crates/vigilyx-engine/src/modules/aitm_detect.rs` |
| HTML 像素画检测 | `crates/vigilyx-engine/src/modules/html_pixel_art.rs` |
| YARA 引擎与规则 | `crates/vigilyx-engine/src/yara/`、`crates/vigilyx-db/src/security/yara.rs` |
| DLP 与数据安全 | `crates/vigilyx-engine/src/data_security/` |
| 隔离区 API | `crates/vigilyx-api/src/handlers/security/quarantine.rs` |
| 数据表与索引 | `crates/vigilyx-db/src/security/migrate.rs` |

## 相关页面

- [快速开始](/zh/docs/quick-start)
- [部署说明](/zh/docs/deployment)
- [架构说明](/zh/docs/architecture)
- [邮件威胁知识库](/zh/docs/knowledge/)
