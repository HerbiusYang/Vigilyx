---
title: 架构说明
description: Vigilyx 怎么把一封邮件变成可解释的判定：旁路与 Inline 两条入口，同一套检测引擎。
---

# 架构说明

一封邮件从两条路进来，检测只走一套。旁路负责看，Inline 负责在投递前拦。判定、证据和审计都落到同一个控制台。

<ArchitectureFlow locale="zh" />

图从上往下读。上面两条是入口，中间汇成同一套引擎，下面是存储、控制台和四种处置。

## 两条入口

**旁路。** `vigilyx-sniffer` 从网卡上抓流量，把 SMTP 会话重新拼出来。拼好的会话放进 Redis Streams，由独立的 `vigilyx-engine-standalone` 取走。邮件已经投递，这一路做的是看见、告警和审计。

**Inline。** `vigilyx-mta` 自己收 SMTP。解析和检测嵌在代理进程里，不等队列。检测完才决定这封信是转发、隔离、拒收，还是暂时失败。只有转发会送到下游邮件服务器。

两条路用同一个解析器和同一套检测模块。换部署方式，不换判定逻辑。

运行时是一个控制面加一个数据面：

| | 进程 | 做什么 |
| --- | --- | --- |
| 控制面 | `vigilyx`、PostgreSQL、Valkey/Redis | 接口、页面、结果、队列 |
| 旁路数据面 | `vigilyx-sniffer`、`vigilyx-engine-standalone` | 抓包、异步检测 |
| Inline 数据面 | `vigilyx-mta` | 收信、当场检测、处置 |

## 引擎里看什么

默认流水线有 29 项，写在 `vigilyx-engine` 的 `default_modules` 里。前面 28 项各自出证据，最后一项 `verdict` 做融合。

| 模块 | 看什么 |
| --- | --- |
| `content_scan` | 正文规则：催促、付款、凭据、回复地址诱导 |
| `html_scan` | HTML 结构、隐藏内容和外链 |
| `html_pixel_art` | 用网页表格或像素画出来的二维码 |
| `attach_scan` | 附件类型、扩展名和危险文件 |
| `attach_content` | 附件里的文字 |
| `attach_qr_scan` | 附件图片里的二维码 |
| `attach_hash` | 附件哈希，用来对已知样本 |
| `mime_scan` | MIME 结构是否异常 |
| `header_scan` | 头部、发件域和回复地址是否对得上 |
| `link_scan` | 短链、国际化域名、形近字、可疑参数 |
| `link_reputation` | 链接域名的信誉和随机性 |
| `link_content` | 链接主机是不是仿冒、DGA，或把发件域嵌进去 |
| `landing_page_scan` | 点开之后的落地页 |
| `anomaly_detect` | 这封信相对平时是不是异常 |
| `aitm_detect` | 登录中间人，反向代理偷会话 |
| `rmm_detect` | 远程控制工具的诱导 |
| `prompt_injection_scan` | 藏在邮件里的提示词注入 |
| `toad_detect` | 回拨诈骗：让人打电话、交验证码 |
| `semantic_scan` | 语义意图。模型默认只做影子记录，规则仍会跑 |
| `domain_verify` | 发件域本身是否站得住 |
| `identity_anomaly` | 第一次联系、身份漂移、租户域名 |
| `transaction_correlation` | 和前后业务邮件是否对得上 |
| `yara_scan` | YARA 规则 |

这 23 项默认就会参加这次检测。另外 5 项在列表里，但要前置模块或外部组件才出结果：

| 模块 | 什么时候才跑 |
| --- | --- |
| `url_sandbox_scan` | 落地页模块先跑过 |
| `process_sandbox_scan` | 落地页模块先跑过 |
| `av_eml_scan` | 配了 ClamAV，查整封邮件 |
| `av_attach_scan` | 配了 ClamAV，查附件 |
| `sandbox_scan` | 附件模块先跑过，并且配了 CAPEv2 |

没配杀毒和沙箱时，判定摘要里的分母常见是 25。29 是编译期的完整列表，含 `verdict` 和这些可选项。

`verdict` 用 `clustered_ds_v2` 融合。同一来源的重复证据只算一次，最后给出等级，并留下是哪一项检查看到的。

## 判定之后

结果写入 PostgreSQL。API 和 WebSocket 把新判定推到 React 控制台。需要通知时，SOAR 走邮件或企业微信。

Inline 的处置和等级绑在一起。覆盖完整的安全和低危会转发。中危起隔离。严重拒收，不转给下游。引擎当时给不出判定，默认返回临时失败，不放行。具体响应码在 [版本发布](/zh/docs/releases)。

## 外发数据安全

这不是上面 29 项里的威胁检测。它看的是信里有没有不该发出去的敏感数据，例如证件号、银行卡号这一类。

代码在 `vigilyx-engine` 的 `data_security`，由 `vigilyx-mta` 在处置时执行。只有这封信已经被判成可以转发、而且方向是外发，才会做这次检查。默认开启。命中级别默认从 3 起，动作默认是隔离。也可以改成拒发，或放行并告警。

旁路看不到投递前的拦截机会，所以这一路只能审计已经能检查到的邮件，不能代替 Inline 把信扣下来。它也不改写上面的威胁等级。

## 代码落在哪

| Crate | 角色 |
| --- | --- |
| `vigilyx-core` | 邮件、等级、处置这些共用类型 |
| `vigilyx-parser` | SMTP 与 MIME |
| `vigilyx-sniffer` | 旁路抓包 |
| `vigilyx-engine` | 模块、融合、DLP、时序 |
| `vigilyx-mta` | SMTP 代理和内嵌引擎 |
| `vigilyx-db` | PostgreSQL 与 Redis |
| `vigilyx-api` | REST、登录、WebSocket |
| `vigilyx-soar` | 告警 |

前端是 React。Python 只做可选的 NLP，不在主链上。

## 相关页面

- [概览](/zh/docs/)
- [快速开始](/zh/docs/quick-start)
- [部署说明](/zh/docs/deployment)
- [版本发布](/zh/docs/releases)
