# 合成语料（LLM 逐封撰写）

生成方式：由大语言模型**逐封独立撰写**（每封邮件的场景、措辞、口吻、结构均不同），
`batch_*.py` 仅负责把已写好的字面内容落盘并记录标签，不做任何词汇插值或模板拼接。
每个 batch 文件本身就是全部样本的"源码"，可直接人工审阅与增删。

- 目录：`synth/mal_*.eml`（恶意）/ `synth/ham_*.eml`（良性）
- 标签：`synth/labels.jsonl`（逐封一条，含 label/family/language/techniques/batch）
- `engine_status` 均为 `not_evaluated`：本标签是人工/合成语料标注，不是引擎判定；当前红队语料只用于评测，不参与训练或阈值选择
- 红队 harness 默认不包含本目录；显式设置 `VIGILYX_REDTEAM_INCLUDE_SYNTH=1` 后可纳入合成语料，`VIGILYX_REDTEAM_CASES` 可进一步筛选
- 恶意样本覆盖历次红队验证过的全部攻击族，含当前 7 个开放向量的硬正样本；
  良性样本刻意包含金融词汇、本人验证码、内网 IP 链接、带横幅通讯等硬负样本
- 样本数与分类以当前 `labels.jsonl` 为准，不把历史 batch 进度当作验收数量。灰区文件名与二分类标签并非一一对应。

在远程仓库根目录查看标签分布：

```bash
python3 - <<'PYCOUNT'
import collections
import json
from pathlib import Path
path = Path("crates/vigilyx-engine/tests/redteam_cases/synth/labels.jsonl")
rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
print("records:", len(rows))
print("labels:", dict(collections.Counter(row.get("label", "unknown") for row in rows)))
PYCOUNT
```

- 覆盖定向话术（会议/猎头/期刊/闭门）、多阶段投递（阶段1纯信任邮件→阶段2线程载荷）、
  凭据新手法（设备码钓鱼、OAuth 同意钓鱼、反向代理扫码）、无宏载荷
  （ISO/LNK/RAR 符号链接/OneNote/HTML 走私/远程模板/HWP/固件伪装）、
  基础设施伪装（U+2011 连字符域、punycode、品牌子域拼接、Worker/短链中转）
- APT 特有标注：`expected=review` 用于单封不可判定、需事后关联或人工复核的样本
  （阶段1信任邮件、被劫持真线程、真站挂马、私域引流）

### 灰区系列（gray_*，batch 7 起）

- 每封带 `ambiguous: true` 与 `borderline`（一句话说明灰在哪）
- `expected` 新增第三种动作 `review`：理想结果是进隔离/人工复核，而非自动 block/deliver
  ——静态特征无法判定真假的样本（如供应商账户劫持、真假 CEO 同形）都标 review
- 含三组"同形对照对"：gray_0016/0031（假/真 CEO 垫付）、gray_0017/0032（假/真商标代理）、
  gray_0018/0033（假/真期刊 APC）——静态特征几乎一致、标签相反，专供语义模型与阈值评估
- 评测用法：`expected=review` 不并入恶意/良性二分类，应单独报告复核和覆盖结果；
  不把合成语料上的理想动作当作生产处置保证，也不使用本语料选择训练模型或阈值
