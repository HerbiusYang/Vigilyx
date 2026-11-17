# 邮件中危复核与数据安全中文显示修复

部署环境：36.33.98.77；验收时间：2026-11-16 05:39 UTC。

## 邮件风险

- 计分模式下语义模型达到阈值，模块风险改为 0.40 / Medium。推理阈值仍为 0.90。
- `link_content:recipient_in_url` 模块风险改为 0.40 / Medium。可信目标和退订、偏好元数据的原有排除条件保留。
- 两项分别通过具名约束要求综合风险至少 0.40；同时命中不叠加保底分数。仅标签、未计分的严格证据项、零分或零置信结果不能触发该约束。
- 复核约束不把模型分数解释为恶意概率，也不改写原始 BPA。语义模块分数调整会正常影响其证据质量。
- Migration 135 已完成，两项持久化策略 `minimum_risk` 均为 0.40。应用原有初始化流程会刷新 canonical seed；管理员定制保存在 overrides / pipeline，真实数据库测试验证其保留和重复初始化。

| 会话 | 新判定 ID | 两项模块 | 综合风险 | 模型分数 |
| --- | --- | --- | --- | --- |
| afdb320b-9887-41e5-bfb8-de360c4cb7d3 | 5c84574c-5e95-4106-bdfa-6917e4db5314 | Medium | 0.40 | 0.9009723858678796 |
| 182fa657-2b34-40ad-b194-84836063be85 | 1df2edfd-83bb-429a-bfe7-a6f9aebe5f07 | Medium | 0.40 | 0.9254375766132468 |

两跳均保留 `inspection_coverage=limited` 和 `inspection_coverage_incomplete`。原始 BPA 为 Bel=0.10868、Dis=0、Unc=0.89132。生效约束为 `semantic_intent_review_minimum` 和 `recipient_targeting_review_minimum`，各下限 0.40。

## 数据安全中文显示

- 发布已有事件类型及检测项翻译，避免截图中的未翻译 key。
- 列表摘要、详情摘要、证据描述和证据位置统一经过显示层本地化；兼容已持久化的邮件、草稿、文件上传、覆盖不完整、批量传输和频次异常模板。
- 字段名称包含旧版检测器输出的英文别名。中文、英文切换按当前语言重新显示，无需重采或修改历史事件。
- 原始证据片段、文件名、IP、用户及 URL 保持为数据；未知描述保留原文，避免猜测事件含义。
- 公开 HTTPS 页面及新数据安全脚本返回 200；脚本与远程构建产物逐字节一致，已包含中文事件标签、摘要、字段证据及位置模板。
- 数据安全资源：`/assets/page-data-security-DY5a0CSo.js`，SHA-256：`a301a6c38b837c3fe8746eb02f0fbe8190a34dbe363c985a9038294c68134d61`。
- 浏览器自动化连接不可用，未完成浏览器视觉验收；完成了组件/本地化测试、公开入口及线上静态资源核验。

## 验证与部署

- 远程 workspace Clippy 通过，零警告。
- 远程 workspace 测试：4,156 通过，0 失败，10 个原有测试忽略；36 个测试套件完成。
- 真实临时 PostgreSQL：`medium_review_policy_refresh_preserves_admin_configuration` 通过；临时容器已删除。
- 远程前端：32 个文件、319 项测试通过；TypeScript 和 Vite 构建通过。
- API 和 Engine 使用 `release-fast` 构建。部署依赖协调、数据库迁移、API readiness、容器健康及消息流未消费积压检查通过；邮件与 HTTP Stream lag 均为 0。
- Sniffer 镜像未更新，服务已恢复运行。

运行镜像：

- API：`sha256:aa5d2734cda8eb3a8b9102e8daf0d190c6e5e7893e1c356aa867370324cb651d`
- Engine：`sha256:3259020b52fbdfe63000f4a9784a9905a58ea4fec790b609b0de2f192df3042c`
- Sniffer：`sha256:371764cc26a20dbf605dd985f4a5f26109fcb2cf29086c7a48e8a38ab19ab8ca`

部署前镜像保留为 `vigilyx-api:rollback-before-medium-review-20261116` 与 `vigilyx-engine:rollback-before-medium-review-20261116`。
