# 语义模块评测与性能基线

语料评测与性能基线标记为 `#[ignore]`，不进入常规 workspace 测试，需要在远程构建容器里显式运行。2026-11-02 外部语料及基础回归的实际结果见 [评测报告](EVALUATION_RESULTS_2026-11-02.md)；性能对照仍需单独执行。

## 语料评测

`tests/semantic_eval_harness.rs` 读取仓库已有的标注语料，不新编写攻击文本：

- `tests/redteam_cases/labels.json`
- `tests/redteam_cases/synth/labels.jsonl`

只评测标签为 malicious 或 benign 的用例，逐封送入 `SemanticScanModule::new(None)`，即不启用 NLP。

```bash
ssh root@36.33.98.77 'docker exec vigilyx-rust-builder cargo test -p vigilyx-engine --test semantic_eval_harness -- --ignored --nocapture'
# 只跑前 n 封
ssh root@36.33.98.77 'docker exec -e VIGILYX_SEMANTIC_EVAL_LIMIT=500 vigilyx-rust-builder cargo test -p vigilyx-engine --test semantic_eval_harness -- --ignored --nocapture'
```

输出按标签和家族列出以下比例：

| 列 | 含义 |
| --- | --- |
| signal | 出现未被反驳的场景、需复核项或勒索类别 |
| scenario | 出现未被反驳的语义场景 |
| review | `semantic_review_required` 为 true |
| sextort | 准入 `sextortion` 类别 |
| unsafe | 模块威胁等级高于 Safe |
| gibber | 出现 `nonsensical_spam` 统计类别 |

malicious 行是语义层召回，benign 行是语义层误报，另外单独输出每万封正常邮件的信号数。

这些数字只说明语义层贡献的事实，不代表最终判定准确率。最终判定还要经过全局融合，并依赖链接、发件人身份等其他模块。

合成语料的写法和真实流量分布不同；对外声明检测效果之前，应补充真实流量的独立 holdout 集。

## 性能基线

`tests/semantic_perf_bench.rs` 使用中性业务填充文本，测量以下五种输入：

- 一句 4 KB 的连续逗号
- 512 个句号后接一条请求
- 300 KB 单行 HTML
- 512 KiB 短行纯文本
- 一封普通的 5 KB 中文邮件

每种输入记录模块端到端耗时和单次抽取耗时的 p50、p95、p99 和最大值。每次运行都新建会话，避免命中抽取缓存。断言只检查模块 p99 低于 3000 ms 的模块超时。

```bash
ssh root@36.33.98.77 'docker exec vigilyx-rust-builder cargo test -p vigilyx-engine --profile release-fast --test semantic_perf_bench -- --ignored --nocapture'
# 调整重复次数
ssh root@36.33.98.77 'docker exec -e VIGILYX_SEMANTIC_BENCH_RUNS=50 vigilyx-rust-builder cargo test -p vigilyx-engine --profile release-fast --test semantic_perf_bench -- --ignored --nocapture'
```

如需对比修复前后，应在同一构建 profile 和同一主机负载下，分别对旧提交和新提交运行，并记录两次运行的环境。

## 外部 JSON 语料：E-PhishLLM 与 Fraud-R1

`scripts/prepare_semantic_corpora.py` 将用户提供的两个压缩包转为同一个 JSONL，原始文本和来源标签保持不变。产物放在被 Git 排除的 `data/semantic-eval/`。此步骤只转换数据，不执行检测。

```bash
python3 scripts/prepare_semantic_corpora.py \
  --ephish /path/to/E-PhishLLM.zip --fraud /path/to/Fraud-R1.zip \
  --output data/semantic-eval/external-2026-11-01
```

导入器验证并排除 `phishing_only`、`no_spam` 的重复副本，以及 Fraud-R1 升级版重复的生成正文和第 1 轮。相同 Subject + Body 仅执行一次，保留全部来源映射。缺失、空文本和结构化原始招聘记录单列；不把 JSON 对象冒充邮件正文。多轮各自独立执行，不模拟跨邮件记忆。

`tests/semantic_external_harness.rs` 显式运行 `SemanticScanModule::new(None)`，使用真实 MIME 解析器提取文本中的链接。只提供数据集中实际存在的 subject/body，不编造 SMTP 收件人、发件域、认证结果或线程信头。当前入口明确测试纯文本路径；不覆盖 HTML 可见性、附件、OCR 和联网链接核验。

源码和语料同步到远程隔离目录后，在构建容器内执行（下列路径仅为示例）：

```bash
docker exec \
  -e VIGILYX_SEMANTIC_EXTERNAL_INPUT=/app/data/semantic-eval/external-2026-11-01/cases.jsonl \
  -e VIGILYX_SEMANTIC_EXTERNAL_OUTPUT=/app/data/semantic-eval/run-2026-11-01 \
  vigilyx-rust-builder cargo test -p vigilyx-engine --profile release-fast \
  --test semantic_external_harness -- --ignored --nocapture
```

输出目录必须不存在，防止覆盖前次实验。`VIGILYX_SEMANTIC_EXTERNAL_LIMIT` 可用于冒烟运行；输出会标记 `limited_run`，不能当全量结果。报告逐条写入并定期刷新，出错记录保留；没有完整 summary 或真实进程退出码不能判定通过。

远程运行完成后汇总：

```bash
python3 scripts/summarize_semantic_corpus.py \
  --corpus data/semantic-eval/external-2026-11-01 \
  --report data/semantic-eval/run-2026-11-01
```

结果按数据集、语言、邮件/短信/招聘帖、原始/生成/轮次、标签和类别分别统计。`results.jsonl` 保存逐条事实、归属、场景、覆盖原因、威胁等级和耗时；`issue_candidates.jsonl` 提供待人工核对的样本索引。

“正常标签下出现请求场景”仅表示需要检查，正常业务也会请求行动。模块威胁、观察场景、复核项、覆盖缺口分别计数，不合成一个误报率。Fraud-R1 的诈骗标签也不能证明其中每句都是当前收件人请求；生成文本可能带安全说明或案例包装。此入口用来定位基础语义问题，不能直接证明最终平台检出率。

## 最小语义对照

`tests/semantic_basic_probes.jsonl` 保留从本轮问题中整理出的 12 条合成对照，字段 `expected_current_request` 表示是否应提取当前收件人行动，不表示邮件是否恶意。使用外部 JSON harness 回放该文件到一个新的输出目录，再在远程运行：

```bash
python3 scripts/check_semantic_probes.py \
  --cases crates/vigilyx-engine/tests/semantic_basic_probes.jsonl \
  --report data/semantic-eval/probes-20261102
```

检查器校验完整输入指纹、逐条比较语义期望，并在不符合时返回非零。它不把“Rust harness 正常结束”当作语义通过。2026-11-02 基线为 6 通过、6 失败，详情保存在 `expectations.json`。
