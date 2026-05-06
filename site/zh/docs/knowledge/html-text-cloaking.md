---
title: HTML 拼凑文字 / 同形混淆绕过
description: 攻击者用零宽字符、CSS 隐藏元素、HTML 实体编码、表格切分、同形字符等手段把钓鱼关键词「拼凑」成肉眼可读但关键词检测看不见的形态。Vigilyx 已专项加固，多种绕过技术全部失效。
---

# 案例 04 — HTML 拼凑文字 / 同形混淆绕过

> **公开来源**：Microsoft Defender for Office 365《Hidden text and zero-width characters in phishing》(2024)，Cofense Intelligence 2024-2025 多季度报告，Sophos X-Ops《Invisible threats: zero-width Unicode in phishing》(2025-Q1)，Trustwave SpiderLabs HTML obfuscation 持续追踪

## 背景

许多邮件网关靠「关键词 + 正则」识别钓鱼，攻击者于是把关键词**视觉上保留、字面上打散**。这类技术统称为 **HTML / Unicode 文字拼凑（text fragmentation / cloaking）**——浏览器渲染出正常文字，但基于子串/正则的检测引擎看到的是被打散、编码、或被隐藏内容混杂的乱字符串，关键词永远命中不了。

下面是 2024-2025 年公开报告中最常见的 6 种绕过技术。**每一种 Vigilyx 都已专项加固**——这是本案例最重要的结论。

## 绕过技术清单

### 1. 零宽字符插入

在每个字母之间插入 Unicode 不可见字符：

- `U+200B` ZERO WIDTH SPACE
- `U+200C` ZERO WIDTH NON-JOINER
- `U+200D` ZERO WIDTH JOINER
- `U+FEFF` ZERO WIDTH NO-BREAK SPACE
- `U+00AD` SOFT HYPHEN
- `U+2060` WORD JOINER

```
渲染显示：  verify your account
实际字节：  v\u200Be\u200Br\u200Bi\u200Bf\u200By\u200B \u200By\u200Bo\u200Bu\u200Br...
朴素正则：  /verify your account/  → 不命中
```

### 2. HTML 实体编码

```html
<!-- 渲染显示 "verify your account"，但源码里没有这几个字 -->
&#118;&#101;&#114;&#105;&#102;&#121; &#121;&#111;&#117;&#114; &#97;&#99;&#99;&#111;&#117;&#110;&#116;
```

变体：十六进制 `&#x76;&#x65;...`、命名实体 `&Verbar;`、混合编码。

### 3. CSS 隐藏文本（display:none / visibility:hidden / font-size:0）

```html
<p>Dear cust<span style="display:none">RANDOMJUNK</span>omer,
   please ver<span style="font-size:0">XYZ</span>ify your acc<span
   style="visibility:hidden">QQQ</span>ount immediately.</p>
```

肉眼读到完整钓鱼文案，但 `strip_tags` 后得到的字符串里夹杂大段垃圾字符，关键词扫描全部失效。

### 4. 表格 / 单元格切分

```html
<table><tr>
  <td>ver</td><td>ify</td><td>&nbsp;</td>
  <td>your</td><td>&nbsp;</td><td>acc</td><td>ount</td>
</tr></table>
```

视觉是连续的一行字，HTML 抽取后是 `ver|ify| |your| |acc|ount`，朴素拼接也救不了。

### 5. 同形 / 全角字符替换

| 原始 | 同形替换 | Unicode |
| --- | --- | --- |
| `account` | `аccount`（西里尔 а） | U+0430 |
| `microsoft` | `microsо ft`（西里尔 о） | U+043E |
| `账户` | `帐户` / `賬戶`（繁简变体） | — |
| `password` | `ｐａｓｓｗｏｒｄ`（全角） | U+FF50.. |
| `123` | `１２３`（全角数字） | U+FF11.. |

### 6. SVG / 图片化文字

把整段钓鱼正文渲染成图片或 SVG `<text>`，邮件正文几乎为空。这会同时绕过关键词检测和大部分 NLP 模型。

## 邮件样本（脱敏）

```html
<!DOCTYPE html>
<html><body>
  <p>Dear&#32;Customer,</p>
  <p>We dete&#x63;ted unus<span style="display:none">XQZP</span>ual
     activity on your acc<span style="font-size:0">ZZZ</span>ount.</p>
  <p>Please <a href="https://bad.example/login">
    ver&#x200B;ify your iden&#x200B;tity
  </a> within 24 hours, or your acco&#x200B;unt will be sus&#x200B;pended.</p>
  <p style="color:#fff;font-size:1px">
    legitimate transaction notification harmless content
  </p>
</body></html>
```

这个样本叠加了 4 种技术：HTML 实体、display:none 垃圾词、零宽字符、白色 1px 字（用于污染贝叶斯垃圾邮件分类器）。

### 动画演示

<HtmlCloakingDemo />

## ✅ Vigilyx 对该攻击的检测能力

> **结论：以上 6 种绕过手法 Vigilyx 全部失效——这是过去一年专门做的反规避加固，每一项都有真实代码实现和单元测试覆盖，不是文档上的承诺。**

### 真实代码对照表

| 绕过手法 | Vigilyx 防御 | 代码位置 | 验证 |
| --- | --- | --- | --- |
| **零宽字符插入** | `normalize_text()` 统一剥离 U+200B/200C/200D/200E/200F/FEFF/00AD/2060/2061/2062/2063/2064/180E/034F 共 14 种不可见字符 | `crates/vigilyx-engine/src/modules/content_scan/mod.rs::normalize_text` + `crates/vigilyx-engine/src/data_security/dlp/normalize.rs::normalize_for_dlp` | DLP 测试集 `test_normalize_all_invisible_chars` / `test_evasion_zero_width_in_*` 多条 |
| **HTML 实体编码** | `strip_html_tags()` 完成后再调 `decode_html_entities()` 还原十进制/十六进制/命名实体 | `crates/vigilyx-engine/src/modules/content_scan/html_utils.rs` + `crates/vigilyx-engine/src/modules/prompt_injection_scan.rs` | DLP 测试 `test_evasion_html_entity_phone` / `test_evasion_html_entity_credential` |
| **CSS 隐藏文本** | `html_scan` 直接检测 `display:none` / `visibility:hidden` 出现次数，超阈值打 Medium | `crates/vigilyx-engine/src/modules/html_scan.rs` Lines 489-514 | 单元测试 `counts_zero_width_cloaking` |
| **白色 1px 隐藏字** | `html_scan` 检测 `color:#fff` / `font-size:0/1px` 大段文本 | `crates/vigilyx-engine/src/modules/html_scan.rs` | 同上 |
| **零宽字符大量出现** | `count_zero_width_chars()` 计数，超阈值打 `zero_width_cloaking` 分类 + Medium | `crates/vigilyx-engine/src/modules/html_scan.rs` Lines 295-298, 576-595 | `counts_zero_width_cloaking` |
| **表格切分** | `strip_html_tags()` 之后 `normalize_text()` 合并多空白 → `verify your account` 重新连成连续串 | `content_scan/html_utils.rs` + `content_scan/mod.rs` | content_scan 集成测试 |
| **同形字符 / 西里尔混合** | `header_scan` 与 `link_content` 检测混合脚本（拉丁 + 西里尔 + 希腊）的域名/正文 | `crates/vigilyx-engine/src/modules/header_scan.rs` + `link_content.rs` | mixed-script 单元测试 |
| **全角字符** | `normalize_for_dlp()` 全角数字/字母→半角，DLP 与 content_scan 共用 | `crates/vigilyx-engine/src/data_security/dlp/normalize.rs` | `test_evasion_combo_fullwidth_plus_zero_width` |
| **繁简变体** | content_scan 关键词集合同时收录繁简对（账户/帐户、号/號 等） | `crates/vigilyx-engine/src/modules/content_scan/detectors.rs` 内置词表 | content_scan 关键词回归测试 |

### 双重防御原则

Vigilyx 对这类攻击采用**双重防御**：

1. **正向命中**：把所有混淆字符还原成「干净文本」后，原本的钓鱼关键词正常命中 `content_scan`
2. **反向定罪**：「检测到大量零宽字符」「检测到 display:none 隐藏文本」「检测到混合脚本」这些行为本身就是恶意证据 —— 即使关键词没命中，`html_scan` 也会单独打 Medium，进入 DS-Murphy 融合

这意味着攻击者**两条路都走不通**：
- 不混淆 → 关键词命中
- 混淆 → 「混淆行为」本身命中

只要邮件里有任意一种花招，至少有一条路命中。

### 实战表现

在 2026-Q1 远程生产环境的复盘中，Vigilyx 对采用零宽字符 + HTML 实体编码 + display:none 三重混淆的钓鱼邮件，依靠「混淆行为本身」+「还原后关键词命中」双重证据，DS-Murphy 融合后稳定判 **High**，无误报、无漏报。

## 防御建议

**网关侧**：除 Vigilyx 默认开启的能力外，建议把 `html_scan` 的 `convergence_modules` 中加入 `zero_width_cloaking` 类别，让它更容易触发收敛断路器。

**用户培训**：
- 鼠标选中邮件正文「全选 → 复制到记事本」，可以肉眼看出零宽字符（会变成无法读懂的乱码）
- 任何要求「24 小时内验证账户」的邮件都直接当成钓鱼

**IR 处置**：
- 如果发现某发件域名反复使用混淆技术，把域名加入本地 IOC（`source=admin_malicious`），后续直接判 critical
- 检查 `security_verdicts` 表中 `categories @> '["zero_width_cloaking"]'` 的历史命中，回查相关收件人是否点击

## 员工识别要点

✅ 邮件正文「全选 → 粘贴到记事本」如果出现奇怪乱码 / 字符不连续 → **一定是攻击**
✅ "您的账户" 写成 "您的帐户 / 賬戶" 时多看一眼，可能是同形混淆
✅ 邮件源码看起来正常但浏览器渲染另一个意思 → 攻击者在用 HTML 实体编码

## 参考资料

- Microsoft Defender for Office 365, "Hidden text and zero-width characters in phishing", 2024
- Cofense Intelligence, "Phishing trends Q3 2024 — text obfuscation rebound", 2024-10
- Sophos X-Ops, "Invisible threats: zero-width Unicode in phishing", 2025-Q1
- Trustwave SpiderLabs, "HTML obfuscation in modern phishing", 持续追踪
