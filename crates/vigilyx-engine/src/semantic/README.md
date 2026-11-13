# Rust 语义引擎

本目录集中维护本地确定性语义算法、可选 CPU ONNX 意图模型及其引擎适配。对外入口由 `mod.rs` 导出，调用方使用 `crate::semantic`。共享类型继续使用 `vigilyx-core`，公共正文工具继续复用现有实现。

## 代码职责

| 文件 | 职责 |
| --- | --- |
| `scan.rs` | 调度本地分析与可选 AI、OCR，保留现有计分入口 |
| `intent_model.rs` | 引擎进程内 CPU ONNX bge/e5 集成推理，支持影子与显式计分模式 |
| `intent_text.rs` | 与训练端一致的模型正文归一化及采样 |
| `context.rs` | 按已有词表提取语义声明，保留来源偏移、引用、反语境及实际观测到的链接 |
| `attribution.rs` | 根据已有声明线索解析言语行为、极性和施事、受事角色 |
| `guards.rs` | 局部词内排除、否定例外、动作去向和客户端回复头 |
| `constructions.rs` | 有界请求、处置式与完成态构式；由注册表中的构式策略控制 |
| `compiled.rs` | 与不可变词表快照绑定的派生数据缓存 |
| `data/` | 原有语义自有词表和场景策略的统一源码目录 |
| `source.rs`、`relations.rs` | 来源检查、位置索引和现有本地关系准入 |
| `solicitation.rs` | 登录秘密回传、可退核验转账及先缴费后释放本人资金的有界关系 |
| `workflow.rs` | 纯 CPU 的有界角色与工作流证明，输出支持节点、关系及未满足条件 |
| `workflow_collection.rs` | 同一句协调字段、后置表单目标与收集论元的局部绑定 |
| `projection.rs`、`text.rs` | 正文选择、投影、匹配与 UTF-8 边界 |
| `statistics.rs`、`language.rs`、`style.rs` | 统计、语言和文风观察 |
| `policy.rs` | 使用已有策略生成单声明及跨声明场景候选 |
| `ocr.rs` | 将独立 AI 服务的 OCR 结果转换为本地事实和场景观察 |
| `classifier.rs`、`model/` | 本地文本分类器：哈希线性模型推理、特征抽取与策略开关（默认影子模式） |
| `result.rs` | 最终统一组装事实、场景、计分和覆盖状态 |

## 与 AI 模块的边界

AI 服务连接、配置加载、正文采样、异步请求和模型结果检查由同级 `../ai/` 维护，入口为 `crate::ai`。`semantic/` 使用该接口，AI 模块不依赖 `semantic/` 的内部类型或实现。

本地规则路径保留有界声明的来源坐标检查、当前收件人请求及关系准入，并将合格关系是否出现在模型输入中的结果传给 AI 适配层。模型观察、辅助加分和覆盖状态由结果入口组装。本地规则不依赖 Python AI 服务；场景观察仍不等于恶意判定。ONNX 显式计分模式走独立的提前返回路径，替代本地规则及后续 Python NLP/OCR 分析，见下节。

## CPU ONNX 意图模型

- 设置 `SEMANTIC_INTENT_MODEL_DIR` 指向包含 `ensemble.json`、各成员 `model.onnx`、`tokenizer.json` 和 `classifier_config.json` 的模型包，并用 `ORT_DYLIB_PATH` 指定 ONNX Runtime 动态库。加载失败时记录警告并禁用该模型。
- 默认影子模式：与本地规则并行，结果写入 `semantic_intent_model`，不改变模块结果或最终处置；无需启用 Python AI。
- 有效的 `SEMANTIC_INTENT_SCORE_THRESHOLD` 显式开启计分模式，替代本地规则路径。达到阈值时输出待复核的 Low 模块分数 0.20，进入 verdict 融合；这不是最终等级或拦截保证。未达到阈值也不等价于已证明安全。
- `SEMANTIC_INTENT_THREADS` 默认 4；推理使用有界等待预算。运行失败、超时和缺少可分析正文应按覆盖/适用状态解读，不能当作完整检查通过。
- 当前 Compose 的模型环境变量和只读卷接在旁路 engine；不能据此假定 MTA 的内嵌引擎已加载同一模型。

模型打包、文本/推理一致性验证与权重使用边界见 [意图模型实验说明](../../../../scripts/semantic_intent_poc/README.md)。规则路径、旧哈希分类器、ONNX 模型和 Python NLP 的历史评测不可相互替代，也不代表当前线上质量。

## 数据来源

语义分析继续复用项目原有的数据路径：

```text
semantic/data/*.json + shared/schemas/engine_module_data_seed.json
    → vigilyx_db::security::embedded_module_data_seed()（统一合成默认种子）
    → 持久化种子合并与管理员覆盖配置
    → ModuleDataRegistry
    → CompiledSemanticData（不可变快照与派生缓存）
    → 事实提取、场景策略及关系准入
    → 统一结果输出
```

原有语义自有数据已从共享种子移入 `data/`，分为 `context.json`、`scenarios.json`、`relations.json` 和 `scan.json`。迁移保留原有数据，后续中文词条在原列表内追加，并同步扩展适用的场景条件；原有词条顺序与场景 ID 保留，没有缩减已有场景。每条数据只保留一个源码定义。

语义数据仍经过统一注册表加载，数据库初始化、编译内置默认值及热更新共用同一个合成种子；持久化配置和管理员覆盖的合并规则保持不变。共享域名等其他模块数据继续放在共享种子中。场景样本保留在原测试目录。

场景候选由现有 `semantic_scenario_policy_v1` 与 `semantic_cross_claim_candidate_policy_v1` 评估，继续写入 `semantic_scenarios`。正文、备用正文、主题和 OCR 保留各自的来源信息。场景候选本身不代表恶意，现有勒索关系等命名准入继续承担其原有计分职责。

缓存随词表快照替换；进行中的分析继续使用原快照。关系检索按位置缩小候选范围，但保留原始声明顺序和最终的来源、跨度、段落及语义资格检查。

`semantic_fact_coverage` 表示本地声明提取的覆盖状态；`semantic_coverage_limited` 和原因列表包含整个模块的缺口，例如后续 AI/OCR 请求失败。后续 I/O 失败不会改写已完成的本地事实覆盖状态。

归属加固的适用边界见下文“2026-10-26 归属与边界修复”，历史验证结果见 [评测报告](EVALUATION_RESULTS_2026-11-02.md)。`action_destination` 区分被请求行动的人和信息/资金的去向，事实 schema 为 4；旧 JSON 缺少该字段时按 `unknown` 读取。存在物理链接的反驳冲突保留为 `Countered` 场景并输出 `semantic_review_required`，该标记尚未接入自动处置。

## 2026-10-26 归属与边界修复

以下行为已改变，均有对应回归测试（`attribution_regression_tests.rs`、`relation_regression_tests.rs` 及各文件内测试）：

- **引用和线程**：
  - 单独的转发分隔线（如 "-----Original Message-----"）后 3 行内必须出现发件人头，才会打开转发范围。
  - HTML 的 blockquote、`<q>`、gmail_quote 容器，前 3 行或容器开头附近必须有回复署名或邮件头，才算引用。
  - 信头没有 In-Reply-To/References、主题也没有 Re:/Fw:/回复/转发 前缀时：引用和转发内容保留原状态，但按原创内容判定语气，并带 `semantic_unverified_thread_v1` 标记。这类内容不会被其他检测器涂掉，会参与勒索准入，并输出 `semantic_unverified_thread_actions`、触发 `semantic_review_required`。
  - 纯文本 `>` 行与冻结用例一致，在线程已验证时仍按引用处理。
- **内联引号**：引号不能跨行；超过 4096 字节不算引用；同一行引号前 32 字节内必须有说话或示例框架词（`inline_quote_frames`）。
- **否定**：否定词只作用于其后 48 字节内、中间没有冒号或破折号的动作。否定后紧跟催促类动词（`urgency_negated_verbs`，如"请勿忽略"、"don't hesitate"）时改判为指令。出现在"否则 / or"之后的否定视为后果。
- **报告**：报告子句以冒号结尾时，覆盖同句后续所有子句；否则只覆盖没有自身请求标记的子句。报告标记和请求在同一子句、中间没有冒号或引号时，按当前请求处理，并带 `semantic_unframed_report_request_v1`。
- **主语**：请求或指令标记后 12 字节内紧跟收件人代词、且中间没有动作词时（如"要求您"、"ask you"），视为指向收件人，第一人称或第三方主语不再豁免。
- **构式**：通过新字段 `stage_b_enabled` 启用。已持久化的种子保留旧的 `enabled` 值，新字段经增量回填生效；设为 false 可关闭。
- **边界**：
  - 纯标点句不计数。
  - 超长句按 4096 字节分块检查，不再截断。
  - 句子候选超过 4096 条时保留首尾各一半。
  - 声明满 512 条时，按优先级淘汰较早的低价值声明。
  - URL 在 ASCII 字符和中文的交界处结束。
- **性能**：
  - 每行只归一化一次。
  - 子句切分改为一次收集动作位置，不再逐个连接词扫描后缀。
  - 主体、主题、备用正文共用模块入口的截止时间（`extract_semantic_context_until`），OCR 本地解析上限 1 秒。
  - 同一会话的重复抽取经内容摘要缓存复用。
- **勒索准入**：
  - 关系最多可跨 3 段，包络 8192 字节。
  - 支持名词式付款行。
  - 支持"主题为威胁、正文为付款和后果"的跨来源组合。
  - 因果键按归一化文本计算，plain 和 HTML 合并为一条。
- **结果**：只要有未被反驳的场景、需复核项或覆盖缺口，Safe 结果就输出不表态的 BPA（置信度 0），不再写"语义正常"。非 Safe 结果在覆盖受限时置信度降为 0.50。
- **统计**：阈值按长度归一，未经校准，见 `statistics.rs` 注释。`nonsensical_spam` 不再作为 notice banner 压分的 NLP 佐证。
- **策略诊断**：观察类策略缺失只写 `semantic_policy_diagnostics`，不再导致隔离。计分词表缺失仍记为覆盖缺口。

## 中文及混写关系优化（2026-11）

金额中的千位逗号、全角数字和小数不会切断付款动作。列表前缀只用于语气归属，原文偏移不变；纯文本段落按空行分隔，HTML仍保留投影容器边界。列表继承不跨空行。

秘密回传要求当前收件人动作、秘密对象与发件人去向同时成立。OTP 设备能力、密码策略、正文已提供的固定通知码及已关闭功能不充当登录秘密回传证据。核验转账要求当前付款、大额或全部余额、核验目的及针对本次款项的退款承诺。预付费关系要求付款与释放收件人自身资金的依赖；跨段拼接必须有同一费用的明确指代，并受段数和字节上限约束。不同付款机制共享同一动作因果键，不能重复投票。

报告补语、否定、已完成动作与可信线程边界保留局部作用域。附件请求到物理链接的继续绑定须重新核对来源及中间声明，不跨报告、反语境或引用借用目标。未经线程佐证的引用格式不能提供豁免。

四份语义 JSON 同时参与 DB 内置种子的构建依赖；验证时应核对有效注册表与源码，而不能只检查文件已上传。已有数据库管理员覆盖仍优先生效，源码策略更新不等价于线上已启用。

静态工作流推理不调用模型或网络。它使用同一套来源、语气、否定和引用归属，将动作与资金所有者、受益人、已有秘密及表单目的连接起来。遗产类关系需要第三方遗产、虚构亲属角色、收件人收益和当前配合构成完整证明；普通继承、慈善委托及遗产词汇不单独计分。远程金融秘密表单需要已有取款 PIN、身份/其他秘密和同一认证收集流程，区别于新设 PIN、商品支付与实体 ATM。

词法层复用缓存的多模式匹配索引。启用的工作流所需名词概念从同一个策略快照并入对象识别，防止“SMS code into this form”等无独立动作的字段先被丢弃；原始注册表不被改写，禁用工作流不派生其词法项。重叠 PIN 名词按最长概念跨度统一处理修饰词，跨类型概念仍可保留，不按词命中数加分。

`semantic_workflow_diagnostics`保存工作流的已观察节点、关系与缺失条件；`semantic_scoring_decision`明确区分请求提取、场景观察和实际计分准入。新增证明沿用现有最大值合并和因果去重，不按同一邮件中出现了多少个关键词累加风险。CPU 截止时间及来源包络仍适用。

## 本地文本分类器（2026-11，默认影子模式）

规则路径只在关系证明完整时计分，在 E-PhishLLM 与 Fraud-R1 上的恶意检出率约 0.5%。`classifier.rs` 在规则之外提供一个本地统计分类器，权重编译进引擎，纯 CPU、无网络，受模块 CPU 截止时间约束。

- **模型**：FTRL-Proximal 逻辑回归，特征按 FNV-1a 哈希到 2^22 维，按族做 L2 归一。三族特征：非 CJK 文本的词、词组和字符 n-gram（`lexical`），现有语义词表分组的命中及当前收件人请求内的分组组合（`concept`），声明角色、请求数和场景候选（`structure`）。CJK 占比 ≥0.3 的文本路由到只用 `concept`、`structure` 的第二个模型。少于 30 个文本单位、有效特征少于 3 个或特征贡献不为正时不触发。
- **输出**：触发时最多给出“Low + 需复核”，类别 `semantic_text_classifier`，不进入 v1/v2 融合（`evidence_clusters.rs`、`clustered_ds_v2.rs` 已排除）。概率、阈值、路由和前 8 个正向特征写入 `semantic_text_classifier`。
- **开关**：`scan.json` 的 `semantic_text_classifier_policy_v1`。`mode=shadow` 只记录结果（details 中 `shadow: true`），不改变威胁等级、类别和复核标记；`mode=review` 才计分；不写 `mode` 视为 `review`，与旧配置兼容。源码默认 `enabled=true, mode=shadow`。已有数据库覆盖仍优先生效。
- **训练数据**：两个研究数据集按种子分组切分（Fraud-R1 同一 record id 的各轮、中英文译文在同一侧），中文按组进入训练（切分 v3）。两个数据集缺少通知类正常邮件，也没有中文正常邮件，所以加入 `scripts/generate_semantic_synthetic_benign.py` 生成的合成正常通知与往来邮件（只生成正常邮件；一种通知类型整体落在同一侧，开发集和测试集里的类型未参与训练）。仓库红队语料只做评测，不参与训练。

### 2026-11-06 评测（`review` 模式回放，模型 `semantic_text_classifier_v2_syn1`）

留出测试集只在最终回放时读取一次。“检出”指模块判定高于 Safe：

| 子集 | 检出 | 误报 |
|---|---:|---:|
| 全部恶意 | 3,236/3,375（95.9%） | — |
| E-PhishLLM 正常邮件 | — | 15/1,643（0.91%） |
| E-PhishLLM 英/德/意 | 97.5% / 96.7% / 94.2% | — |
| Fraud-R1 英文 / 中文 | 99.2% / 90.9% | — |
| 合成正常邮件（未见过的类型）英 / 中 | — | 9.9% / 9.5% |
| 红队语料（评测用） | 761/1,926（39.5%） | 482/1,772（27.2%） |

同一批测试样本只靠规则时检出 18 条、误报 0 条。商业垃圾邮件 136 条中有 120 条被标记，它不属于正负任何一类。红队正常邮件中，机构通知的标记率 37.0%，商务往来 15.9%，私人邮件 0%；英文路由 122 条中有 115 条被标记。红队上的 AUC 中文约 0.66、英文约 0.51。

耗时对照：同一程序、同一批 6,039 条测试文本，单线程逐条计时，分类器关闭与开启交替各两轮（Xeon E7-4820 v4 2.0 GHz）。开启后单条 p50 4.9 ms、p99 24.9 ms，关闭时分别为 4.0 ms 和 23.8 ms；同一条文本开、关耗时差值的中位数约 0.9 ms。单核吞吐约 133 条/秒（关闭时约 156 条/秒）。大邮件压力基准（300 KB HTML、512 KiB 纯文本）开、关结果差别在波动范围内。

**局限**：

- 模型在两个数据集内部有效，换到通知类正常邮件时误报明显上升；未见过的合成通知类型误报约 10%，红队正常邮件约 27%，英文路由几乎没有泛化能力。
- 13 组训练变体之间做选择时参考过红队结果，红队语料对当前模型已不是完全独立的旁证。
- 尚未在真实流量上验证。

因此默认只开影子模式，在真实流量上统计 `semantic_text_classifier.fired` 与人工复核结论后，再决定是否切换到 `review`。

### 重新训练与评测

所有步骤都在远程构建容器中运行，数据只放在远程实验目录：

```bash
python3 -I scripts/generate_semantic_synthetic_benign.py --output <dir>/synthetic-benign-v1 --per-language 3000
python3 -I scripts/prepare_semantic_classifier_split.py --corpus <frozen corpus> --output <dir>/split \
  --chinese grouped --synthetic <dir>/synthetic-benign-v1
# 训练：VIGILYX_CLASSIFIER_TRAIN/DEV/OUTPUT 必填；ALLOW_CHINESE=1；EVAL 只评测；VARIANTS 为 JSON 变体列表
cargo test --profile release-fast -p vigilyx-engine --test semantic_classifier_train -- --ignored --nocapture
# 回放与指标（被测副本需临时设为 mode=review）
cargo test --profile release-fast -p vigilyx-engine --test semantic_external_harness -- --ignored --nocapture
python3 -I scripts/evaluate_semantic_classifier.py --cases <split>/test.jsonl --results <replay>/results.jsonl --output <metrics.json>
```

训练程序每个变体输出 `text_classifier_v1.json` 和 `training_report.json`；将选定模型复制到 `model/text_classifier_v1.json` 即随引擎发布。模型 `hash_bits`、词表来源列表须与特征抽取一致，否则加载失败并按未训练处理。

## 验证命令

2026-11-02 已在远程隔离目录执行 Clippy、两套外部语料全量回放及 `semantic::` 回归；回归存在失败，具体结果与问题见 [评测报告](EVALUATION_RESULTS_2026-11-02.md)。本轮未部署。后续可在持久化构建容器中执行：

```bash
ssh root@36.33.98.77 'docker exec vigilyx-rust-builder cargo test -p vigilyx-engine --lib semantic:: -- --test-threads=1'
ssh root@36.33.98.77 'docker exec vigilyx-rust-builder cargo test -p vigilyx-engine --lib ai:: -- --test-threads=1'
ssh root@36.33.98.77 'docker exec vigilyx-rust-builder cargo clippy -p vigilyx-engine --all-targets -- -D warnings'
ssh root@36.33.98.77 'docker exec vigilyx-rust-builder cargo test -p vigilyx-engine --lib pipeline::verdict -- --test-threads=4'
ssh root@36.33.98.77 'docker exec vigilyx-rust-builder cargo test -p vigilyx-engine --lib modules::content_scan -- --test-threads=4'
```

评测与性能基线的运行方式见 [EVALUATION.md](EVALUATION.md)。

上面的完整命令集合没有全部执行，不能据此声称 AI、全局融合或生产部署已经验收。外部语料回放的观察指标也不代表最终平台识别率。
