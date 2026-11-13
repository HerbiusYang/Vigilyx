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

## 本地文本分类器

`classifier.rs` 使用编译内置的哈希线性模型，按文本路由到词法、概念与结构特征。训练脚本可使用合成正常通知补充研究语料中的类型缺口；这不能证明真实流量上的泛化能力。

`scan.json` 中 `semantic_text_classifier_policy_v1` 的源码默认值为 `enabled=true, mode=shadow`，只记录观察结果；`mode=review` 可输出待复核信号。已有数据库覆盖配置优先生效。历史实验数字不作为当前部署的验收结果。

## 验证

在配置好的远程构建主机执行项目的 Clippy、workspace 测试及 Rustdoc 检查。需要模型包、外部语料或实验环境的忽略测试须另行准备输入并显式运行；普通 workspace 测试通过不能代替这些验证。
