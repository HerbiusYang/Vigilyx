# 2026-11-02 纯文本语义基线

两套外部语料已在远程 Rust 构建容器完整执行。本次发现基础意图提取和报告归属缺口；测试程序正常结束不能解释为识别质量通过。

## 执行与复现

- Rust 1.98.0，`release-fast`，x86_64；源码位于远程 `.semantic-eval-20261102/` 隔离目录。
- 调用 `SemanticScanModule::new(None)`；使用编译内置词表，不读取线上数据库覆盖配置。
- MIME 解析器提取实际文本链接；不构造发件域、SMTP 收件人、认证、线程信头或链接归属证明。
- 测试纯文本；附件、HTML 可见性、OCR、联网核验和全局融合不在这次语料回放范围。
- 本轮未部署或重启业务服务。

| 检查 | 实际结果 |
| --- | --- |
| Clippy，engine + external harness，`-D warnings` | 退出码 0 |
| 100 段冒烟回放 | 退出码 0 |
| 外部语料全量回放 | 26,708 段，模块错误 0，退出码 0 |
| 全量报告校验与汇总 | 退出码 0 |
| 原有 `semantic::` 回归 | 169 通过、7 失败，退出码 101 |
| 新增最小语义对照探针 | 12 条中 6 符合预期、6 不符合，期望检查退出码 1 |

执行前修复了统一结果 JSON 宏超过递归上限、两处 Rust 1.98 Clippy 写法，以及测试中拆分 AI 目录后遗漏的常量导入。没有调整检测阈值或根据数据集标签增加恶意分。

冻结输入 SHA-256：`1f45629d518a245040fed3edb8020067bdd39fd689695fdef75d0ae3c3e12333`。

有效词表 SHA-256：`148f7415228fa529a9f34d0456ae54244aa9a01a293b2373c87eedda758d7e37`。

源码指纹保存在输入目录的 `source-after-compile-fix.json`。之后仅补齐了回归测试的常量导入，并新增独立探针及报告工具。

## 外部语料观测

| 子集 | 独立文本数 | 有当前请求 | 有场景候选 |
| --- | ---: | ---: | ---: |
| E-PhishLLM 英语钓鱼标签 | 5,996 | 4,531 | 1,319（22.0%） |
| E-PhishLLM 德语钓鱼标签 | 1,077 | 84 | 0 |
| E-PhishLLM 意大利语钓鱼标签 | 1,131 | 6 | 0 |
| Fraud-R1 中文生成邮件，排除商业垃圾邮件 | 156 | 147 | 38（24.4%） |
| Fraud-R1 英文生成邮件，排除商业垃圾邮件 | 156 | 90 | 21（13.5%） |
| E-PhishLLM 全部正常标签 | 8,398 | 1,343 | 2 |

全量共 11,237 段有当前请求、2,930 段有场景候选、67 段输出复核标记。正常业务本来就可能请求行动；正常标签下的两个账户操作候选不等于恶意误报，模块没有因此提高威胁等级。

全量没有高于 Safe 的模块威胁结果，也没有满足现有勒索准入的样本。这说明这些语料主要停留在观察层，不能证明模块已经识别其恶意，更不能推出最终平台漏报率或“全部安全”。最小对照中的直接勒索控制仍会触发 Medium，证明计分路径可以执行。

模块 `analyze` 耗时：p50 4.485 ms、p95 15.881 ms、p99 19.156 ms、最大 47.689 ms。全量测试进程耗时约 184.54 秒；单项耗时不含调用前的 MIME 解析和调用后的报告写入。这是这次主机负载下的基线，没有旧算法对照，不构成性能提升结论。

## 已复现的基础语义问题

新增 `tests/semantic_basic_probes.jsonl` 保留合成最小对照；`scripts/check_semantic_probes.py` 对实际 Rust 输出检查期望，当前明确返回失败。

| 探针 | 预期 | 实际 | 原因线索 |
| --- | --- | --- | --- |
| `request_that_you` | 当前收件人请求 | Notice / Neutral | `request` 可命中动作，却未作为请求框架；第一人称归属先落入描述分支 |
| `first_person_request` | 当前收件人请求 | Notice / Neutral | `I request your…` 未区分请求者身份和被要求行动的人；敏感对象同义覆盖也不足 |
| `download_your` | 指令 | Unknown | `Download the…` 控制通过，但 `Download your…` 前缀未覆盖 |
| `respond_synonym` | 请求 | Unknown | `reply` 控制通过，`respond` 没有对应动作概念 |
| `numbered_request_frame` | 列表继承上文请求 | Unknown | “请立即采取以下操作：”后的换行、编号句丢失请求框架；同义直接请求控制通过 |
| `structured_training` | 培训报告中的示例 | 当前行动，且误准入勒索 | 明确的英文培训标题与后续示例未形成报告作用域 |

第一人称问题也出现在 `ephish/1007`、`fraud/English/596/generated`；编号框架问题出现在 `fraud/Chinese/3/generated`；`ephish/994` 可复现 `Download your…` 的缺口。来源映射和完整事实保存在忽略目录，不复制真实语料到源码测试。

其余六条控制通过：`download_the_control`、`reply_control`、`direct_request_control`、`self_action_control`、`negation_control`、`independent_after_training`。特别是培训段后独立出现的真实勒索仍被准入，后续修复不能用整封培训关键词豁免替代局部归属。

德语和意大利语候选均为零，表明现有少量多语言标记不足以组成这些语言的完整动作、对象和请求关系。不能把“词表含若干语言词”当成已具备该语言的场景能力。

## 原有七条失败的含义

三个失败由同一个英文培训作用域问题触发：

- `relation_regression_tests::benign_descriptions_training_and_quotes_are_not_admitted`
- `tests::extortion_requires_current_coercion_not_camera_or_currency_mentions`
- `tests::enabled_nlp_cannot_borrow_authority_from_quotes_negation_or_unrelated_requests`

最后一条使用测试内的模拟 NLP 服务；它说明在线辅助路径也可能借用错误的培训事实。外部语料回放始终关闭 NLP。

另外两条未提取到预期 Warning：`context::tests::redteam_benign_verification_mail_is_warning_not_request`、`context::tests::redteam_antiphishing_notice_preserves_report_warning_and_request`。前者含“如非本人操作请修改密码”，需要与“条件不是禁止”的新语义核对；后者的银行反钓鱼警告仍需检查否定与说话人归属。不能仅为通过而删除断言。

两个容量用例仍用 513 行中性 `Status` 文本触发旧边界：`tests::semantic_span_limit_reaches_module_coverage_without_threat`、`tests::ocr_empty_success_is_complete_and_context_gap_is_visible`。目前 512 限制针对保留声明，中性句没有产生声明；句子候选上限另为 4096。它们应分别改用确实触发当前声明/候选上限的输入，同时保留“未丢失文本不应虚报覆盖缺口”的控制。当前保留失败结果，没有弱化这些用例。

## 数据本身的限制

- E-PhishLLM 的 8,218 条钓鱼标签中有 4,217 条正文使用 `<<link>>` 占位符。占位符不能成为物理链接或归属矛盾证据；附件文字占位也不能替代实际负载。
- Fraud-R1 的基础生成正文、升级版生成正文及第 1 轮完全重复；已排除重复副本。另按精确正文去重，所有来源别名保留。
- 商业垃圾邮件单列；短信、招聘帖、原始案例/对话与生成邮件分别统计。
- 有些生成文本已被改写成安全提醒，仍继承诈骗来源标签，例如 `fraud/Chinese/2/generated`。其未产生攻击场景不能直接算漏报，必须人工核对实际请求。
- 五段生成轮次为空；169 条缺少原始文本；300 条原始招聘记录是结构化 JSON，未伪装成纯文本正文。
- 四个覆盖受限样本的原始正文均含 U+FFFD 替换字符，MIME 完整性缺口被保留。它们没有被算作执行错误或干净结论。

## 产物位置与后续顺序

原始转换数据和 manifest：`data/semantic-eval/external-2026-11-01/`。

全量事实、分层指标和待核对索引：`data/semantic-eval/full-20261102/`。

十二条探针的事实及期望差异：`data/semantic-eval/probes-20261102/expectations.json`。

编译、回放和回归测试的日志与真实退出码：`data/semantic-eval/run-20261102-logs/`。

建议先修复请求框架、动作同义覆盖、编号列表继承与英文报告作用域，再使用同一冻结语料比较新增召回和正常控制。静态向量、修辞序列或图聚类均应在这些事实归属问题修复后独立做对照；这次尚未验证或启用这些新算法。
