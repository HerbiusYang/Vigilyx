---
title: 特性
description: Vigilyx 的核心产品能力，覆盖旁路镜像、Inline MTA、检测流水线、DLP、YARA、隔离区、SOAR 与远程部署工作流。
---

# 特性

Vigilyx 不是只给一个“风险分”的黑盒网关。它把邮件会话采集、MIME 解析、检测模块、证据融合、隔离处置和运维部署都放在同一个开源工程里，安全团队可以直接查看规则、调试模块、扩展检测逻辑，并按自己的邮件链路选择旁路或 Inline。

## 一页看懂

| 能力 | Vigilyx 实际做了什么 |
| --- | --- |
| 旁路镜像监控 | 通过 `vigilyx-sniffer` 基于 libpcap 捕获 SMTP、POP3、IMAP、HTTP/Webmail 流量，不改现有邮件服务器链路 |
| Inline MTA 代理 | `vigilyx-mta` 作为 SMTP relay，在投递前完成解析、检测、隔离、拒收或转发 |
| 同一套检测栈 | sniffer 和 MTA 共用 `vigilyx-parser`、`vigilyx-engine` 与 verdict 逻辑，旁路告警和投递前拦截不会分裂成两套规则 |
| 可解释判定 | 每个模块输出 threat level、confidence、category、evidence，最后进入 evidence fusion，而不是只给不可复核的模型分数 |
| 数据安全 | HTTP/Webmail DLP、草稿箱滥用、分片上传重组、自发自收、文件中转和 JR/T 0197-2020 分类映射 |
| 自主部署 | Docker Compose 一键部署；AGPL-3.0-only；不需要联网授权；AI、ClamAV、Sandbox 都是可选集成 |

## 部署形态

### 旁路镜像模式

旁路模式适合先观察、后处置的安全团队。Vigilyx 从镜像口或主机网卡读取流量，重组邮件和 Webmail 会话，再通过 Redis Streams 交给独立 engine 处理。

- 不需要改 MX、MTA 或业务邮件服务器配置
- 支持 SMTP、POP3、IMAP 和 HTTP/Webmail 流量入口
- 数据面使用 Redis Streams + consumer groups，提供 at-least-once session 投递
- 控制面仍使用 Pub/Sub，适合 reload、rescan、verdict/status 通知
- PostgreSQL 持久化会话、verdict、YARA 规则、隔离区和数据安全事件

### Inline MTA 代理模式

MTA 模式适合需要投递前处置的场景。`vigilyx-mta` 接收 SMTP 连接，完成 TLS 终结、MIME 解析和 inline engine 判定，再决定 relay、quarantine、reject 或临时失败。

- 支持 25/465 入口和本地域名配置
- `MTA_INLINE_TIMEOUT_SECS` 控制 inline 判定超时，默认按秒级预算处理
- `MTA_FAIL_OPEN` 可配置超时时放行或失败关闭
- `MTA_QUARANTINE_THRESHOLD` 默认从 Medium 起进入隔离区
- Medium/High 可透明隔离，Critical 可直接 `550 5.7.1` 拒收
- 隔离邮件保留 raw EML，后续可以在控制台或 API 中放行、删除和审计

## 解析与会话重建

Vigilyx 的解析层不是 UI 上的展示字段拼接，而是 sniffer、MTA、engine 之间共享的基础能力。

- `vigilyx-parser` 提供 SMTP 状态、MIME、正文、附件和头部解析
- `vigilyx-sniffer` 负责 TCP 会话管理和被动协议识别
- `vigilyx-mta` 使用同一套 parser 构造投递前 `EmailSession`
- engine 同时处理 `EmailSession` 和 `HttpSession`
- 附件会进入类型识别、内容启发式、哈希、QR、YARA、AV 等模块
- HTML 会进入隐藏元素、CSS cloaking、像素画、iframe、跳转链和 landing page 分析

这意味着旁路看到的历史邮件、MTA 拦截的实时邮件、Webmail 上传下载行为，最终会落到统一的 session/verdict 数据模型里。

## 检测流水线

当前默认引擎会注册二十余个分析入口，外加按配置启用的 ClamAV、CAPEv2 sandbox 与 AI 远程语义模块。核心模块包括：

| 模块 | 关注点 |
| --- | --- |
| `header_scan` | 发件人伪造、SPF/DMARC/Received 链、头部 IOC |
| `content_scan` | 资金、密码、紧急、钓鱼话术和可配置关键词 |
| `semantic_scan` | 可选 AI/NLP 语义钓鱼分析，AI 关闭时核心规则仍可运行 |
| `link_scan` | 短链、IDN、homoglyph、可疑参数、URL 结构异常 |
| `link_reputation` | OTX、VirusTotal、AbuseIPDB 与本地 IOC 缓存 |
| `link_content` | DGA、品牌仿冒、混合字符域名和登陆诱导 |
| `landing_page_scan` | 链接落地页内容、表单、认证诱导和重定向风险 |
| `aitm_detect` | Evilginx/Tycoon2FA/EvilProxy 一类 AitM 反向代理钓鱼特征 |
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

可选模块会按服务可用性注册。例如 ClamAV 可启用 `av_eml_scan` 和 `av_attach_scan`，CAPEv2 sandbox 可启用 `sandbox_scan`。

## 证据融合与时序分析

Vigilyx 的 verdict 不是“命中一条规则就结束”。模块输出会转换为 BPA 证据，再进行分组融合和冲突处理。

- 默认聚合采用 clustered Dempster-Shafer 风格的 evidence fusion
- 支持 Murphy 修正、TBM、Noisy-OR、Weighted Max 等策略入口
- 模块会保留 evidence、category、confidence 和命中原因，方便分析师复盘
- 对相互相关的模块做分组，降低同类证据重复放大风险
- 时序分析包含 CUSUM、EWMA、Hawkes 自激过程、HMM 攻击阶段建模和通信图特征

这类设计的目标是让“多个弱信号”能组合成可信告警，同时避免单个低质量 IOC 把整封正常邮件直接推成高危。

## AitM、HTML 与 YARA

Vigilyx 对现代钓鱼邮件做了几类比较具体的检测，而不只是搜索“verify your account”。

- AitM 检测覆盖 Cloudflare Workers/Pages、反向代理登录路径、OAuth redirect 不一致、MFA/验证码诱导、Turnstile/CAPTCHA、品牌域名拼接和同形字域名
- HTML 检测覆盖隐藏表单、CSS 隐藏、零宽字符、暗色文字、可疑 iframe 和追踪像素
- `html_pixel_art` 专门处理通过 HTML 表格或像素块拼出来的二维码，补足传统附件 QR 扫描的盲区
- YARA 引擎内置 6 类 41 条规则起步，并会把内置规则同步到数据库，支持新增、启停、校验和热加载自定义规则
- YARA 扫描对象包含 raw EML、正文片段和附件字节流，适合覆盖 SVG smuggling、ClickFix、脚本木马、可执行伪装和 APT 样本特征

## DLP 与数据安全

数据安全不是邮件 verdict 的附属标签，而是独立子系统，主要处理 HTTP/Webmail 场景中的敏感数据外发。

- DLP 内置 30 个 pattern family，覆盖通用敏感信息和 JR/T 0197-2020 映射
- 扫描前做归一化与 UTF-8 安全截断，降低全角、空白、分隔符和超长文本绕过
- 支持 Coremail 等 Webmail 表单字段抽取
- `chunked_upload` 会按 composeId、attachmentId、offset 重组分片上传
- `draft_detect` 识别草稿箱中转敏感数据的行为
- `self_send_detect` 识别自发自收绕过外发审计
- `file_transit_detect` 识别通过附件、下载、转发构造的数据中转路径
- `jrt_compliance` 会按用户/IP 统计 24 小时累计 C3/C4 敏感数据触发阈值

这部分适合银行、企业邮箱、内网 Webmail 和需要把“邮件安全”扩展到“数据外发治理”的环境。

## 隔离区、SOAR 与审计

Vigilyx 的处置链路覆盖自动动作和人工复核。

- 风险等级从 Safe、Low、Medium、High 到 Critical
- MTA 模式可按阈值隔离或拒收
- 隔离区支持列表、统计、放行、删除和原始 EML 保存
- 放行流程会先 claim 隔离记录，投递失败时回滚状态，避免 UI 显示“已放行”但实际未投递
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
- 不回传遥测，不需要联网授权，外部情报源和 AI 服务都可以按环境关闭

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
