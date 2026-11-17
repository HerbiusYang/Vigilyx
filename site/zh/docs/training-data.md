---
title: 训练语料
description: Vigilyx 开源分享的邮件安全训练语料，包括当前数量、标签，以及分类器能看到的字段。
---

# 训练语料

[VIGILYX-Training-Data](https://github.com/HerbiusYang/VIGILYX-Training-Data) 是 Vigilyx 项目开源分享的训练语料，许可是 MIT。网关本身是 AGPL，语料单独放一个仓库，方便直接拿去训练和评估。里面是 JSON 邮件、本地查看器，以及一份指导智能体检索、改编和验收新记录的 Skill。

记录根据公开活动、业务流程或已披露的风险机制改编，不是生产环境截获的原始邮件。收录在语料里，也不等于它已经符合最新检测规则。第三方原文和品牌仍保留各自权利，不会因为本项目使用 MIT 就自动变成 MIT。

## 当前文件

按当前 `data/corpus.json` 清点：

| | |
| --- | --- |
| 记录 | 5,438 |
| 恶意 | 4,537 |
| 正常 | 901 |
| 中文 | 5,199 |
| 英文 | 121 |
| 中英双语 | 118 |
| `source-adapted` | 5,064 |
| 历史 `synthetic` | 374 |

这是语料数量，不是模型成绩，也不是对每条来源的重新认证。仓库 README 在更新之前，数字可能仍停在更早的一次清点。

同一文件的领域分布：金融 3,459，职场 972，财会 578，购物 429。默认场景是中国大陆、自然中文和人民币。覆盖钓鱼、身份冒用、业务流程篡改（BPC）和商业邮件诈骗（BEC），并带正常对照。面向个人消费者的来信也在范围内，收件人不必是员工、采购或财务。

## 记录怎么拆

分类器能看到的内容，和答案、来源是分开的：

- `input` 是唯一的分类输入，包括当前邮件和已有往来。
- `target` 保存标签和证据，不作为模型输入。
- `provenance` 保存来源和改编说明，不作为模型输入。

`source-adapted` 表示正文由检索到的来源改编，并记录了改动。`synthetic` 是更早的生成批次。`redacted-source` 留给忠实脱敏后的原始通信。活动主办方、期次、奖品和资格不能编造。中奖、截止期限、链接、陌生品牌或新地址本身不决定恶意。证据不足的记录进入复核队列，不混进正式训练数组。

## 本地使用

需要 Python 3.9 或更新版本、桌面环境和 `tkinter`。不用再装 Python 包。

```bash
git clone https://github.com/HerbiusYang/VIGILYX-Training-Data.git
cd VIGILYX-Training-Data
python3 corpus_viewer.py
```

查看器打开 `data/corpus.json`，可以隐藏标签做盲读，也可以导出分类输入。检查结构、标签、证据引用和配对：

```bash
python3 realistic-email-threat-corpus/scripts/validate_records.py data/corpus.json --labels malicious,benign
```

校验通过不能证明来源网页真实、正文自然或标签正确。校验器不会打开邮件链接，也不会重新抓取来源。
