<template>
  <div class="kg">
    <a
      v-for="c in cards"
      :key="c.slug"
      :href="hrefFor(c.slug)"
      class="kg__card"
      :data-severity="c.severity"
    >
      <div class="kg__card-head">
        <span class="kg__num">{{ c.num }}</span>
        <span class="kg__sev" :data-sev="c.severity">{{ sevLabel(c.severity) }}</span>
      </div>
      <h3 class="kg__title">{{ titleOf(c) }}</h3>
      <p class="kg__sub">{{ subOf(c) }}</p>

      <div class="kg__meta">
        <span class="kg__tag" v-for="t in c.tags" :key="t">{{ tagLabel(t) }}</span>
      </div>

      <div class="kg__footer">
        <span class="kg__source">{{ c.source }}</span>
        <span class="kg__year">{{ c.year }}</span>
        <span class="kg__cta">
          {{ isZh ? "查看案例" : "Open case" }}
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6" /></svg>
        </span>
      </div>
    </a>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { useData, withBase } from "vitepress";

interface Card {
  num: string;
  slug: string;
  title: { zh: string; en: string };
  sub: { zh: string; en: string };
  tags: string[];
  source: string;
  year: string;
  severity: "high" | "critical" | "medium";
}

const { lang } = useData();
const isZh = computed(() => (lang.value || "").toLowerCase().startsWith("zh"));

const tagDict: Record<string, { zh: string; en: string }> = {
  social: { zh: "社工", en: "Social eng" },
  lolbin: { zh: "LOLBin", en: "LOLBin" },
  oauth: { zh: "OAuth", en: "OAuth" },
  mfa: { zh: "MFA 绕过", en: "MFA bypass" },
  qr: { zh: "二维码", en: "QR code" },
  obfusc: { zh: "混淆", en: "Obfuscation" },
  smuggling: { zh: "HTML 走私", en: "HTML smuggling" },
  loader: { zh: "加载器", en: "Loader" },
  aitm: { zh: "AiTM 代理", en: "AiTM proxy" },
  bec: { zh: "BEC", en: "BEC" },
  ato: { zh: "账户接管", en: "Account takeover" },
  invoice: { zh: "发票欺诈", en: "Invoice fraud" },
  zerowidth: { zh: "零宽字符", en: "Zero-width" },
  homoglyph: { zh: "同形字", en: "Homoglyph" },
  toad: { zh: "电话钓鱼", en: "Callback" },
  rmm: { zh: "RMM 接管", en: "RMM takeover" },
  voice: { zh: "语音社工", en: "Voice social eng" },
};

const cards: Card[] = [
  {
    num: "01",
    slug: "clickfix",
    title: { zh: "ClickFix / Fake CAPTCHA 投递载荷", en: "ClickFix / Fake CAPTCHA payload delivery" },
    sub: {
      zh: "假 CAPTCHA 诱导用户复制粘贴 PowerShell，绕过附件扫描。",
      en: "Fake CAPTCHA tricks the user into pasting PowerShell, bypassing attachment scans.",
    },
    tags: ["social", "lolbin"],
    source: "Proofpoint · CISA · Microsoft",
    year: "2024–2025",
    severity: "high",
  },
  {
    num: "02",
    slug: "device-code-phishing",
    title: { zh: "Storm-2372 Device Code 钓鱼", en: "Storm-2372 device-code phishing" },
    sub: {
      zh: "滥用 Microsoft OAuth 设备码授权流，受害者在合法登录页授权攻击者。",
      en: "Abuses Microsoft OAuth device-code flow — victim authorizes the attacker on the real login page.",
    },
    tags: ["oauth", "mfa"],
    source: "Microsoft Threat Intelligence",
    year: "2025-02",
    severity: "critical",
  },
  {
    num: "03",
    slug: "quishing",
    title: { zh: "Quishing / QR 码钓鱼", en: "Quishing / QR-code phishing" },
    sub: {
      zh: "二维码图片承载钓鱼 URL，绕过传统链接检测。",
      en: "QR images carry the phishing URL, bypassing classic link detection.",
    },
    tags: ["qr", "obfusc"],
    source: "Cisco Talos · Sophos",
    year: "2024–2025",
    severity: "high",
  },
  {
    num: "04",
    slug: "html-text-cloaking",
    title: { zh: "HTML 拼凑文字 / 同形混淆绕过", en: "HTML text cloaking & homoglyph evasion" },
    sub: {
      zh: "零宽字符 + HTML 实体 + display:none 让关键词扫描全失。",
      en: "Zero-width chars + HTML entities + display:none make every keyword regex miss.",
    },
    tags: ["zerowidth", "homoglyph", "obfusc"],
    source: "Microsoft · Cofense · Sophos",
    year: "2024–2025",
    severity: "high",
  },
  {
    num: "05",
    slug: "html-smuggling",
    title: { zh: "HTML 走私投递勒索软件加载器", en: "HTML smuggling for ransomware loaders" },
    sub: {
      zh: "HTML 附件用 JavaScript Blob 在浏览器内还原可执行文件。",
      en: "HTML attachments rebuild the binary inside the browser via JavaScript Blob URLs.",
    },
    tags: ["smuggling", "loader"],
    source: "Microsoft · Mandiant · HP Wolf",
    year: "2024–2025",
    severity: "critical",
  },
  {
    num: "06",
    slug: "aitm-phishing",
    title: { zh: "Tycoon 2FA / EvilProxy AiTM 钓鱼", en: "Tycoon 2FA / EvilProxy AiTM phishing" },
    sub: {
      zh: "中间人代理实时窃取 session cookie，MFA 形同虚设。",
      en: "Man-in-the-middle proxy steals session cookies in real time — MFA bypassed.",
    },
    tags: ["aitm", "mfa"],
    source: "Proofpoint · Mandiant · Sekoia",
    year: "2024–2025",
    severity: "critical",
  },
  {
    num: "07",
    slug: "vendor-email-compromise",
    title: { zh: "VEC 供应商账户接管 BEC", en: "VEC vendor account takeover (BEC)" },
    sub: {
      zh: "用真实供应商邮箱发起的发票欺诈，DMARC/SPF 全部通过。",
      en: "Invoice fraud sent from a real vendor mailbox — DMARC/SPF all pass.",
    },
    tags: ["bec", "ato", "invoice"],
    source: "FBI IC3 · Abnormal Security",
    year: "2024–2025",
    severity: "high",
  },
  {
    num: "08",
    slug: "toad-callback-phishing",
    title: { zh: "TOAD 电话钓鱼", en: "TOAD callback phishing" },
    sub: {
      zh: "纯文本邮件诱骗受害者拨打假客服热线，话术诱导安装 RMM 或念出 OAuth 设备码。",
      en: "Plain-text email lures the victim to call a fake hotline; agent then walks them into RMM install or OAuth device code.",
    },
    tags: ["toad", "voice", "rmm", "social"],
    source: "Proofpoint · Cisco Talos · CISA",
    year: "2024–2025",
    severity: "high",
  },
];

function hrefFor(slug: string): string {
  // VitePress withBase prepends /Vigilyx/. Locale prefix is added by
  // checking the current language: zh keeps /zh/docs/knowledge/<slug>,
  // en uses /docs/knowledge/<slug>.
  const path = isZh.value
    ? `/zh/docs/knowledge/${slug}`
    : `/docs/knowledge/${slug}`;
  return withBase(path);
}

function titleOf(c: Card): string {
  return isZh.value ? c.title.zh : c.title.en;
}
function subOf(c: Card): string {
  return isZh.value ? c.sub.zh : c.sub.en;
}
function tagLabel(t: string): string {
  const x = tagDict[t];
  if (!x) return t;
  return isZh.value ? x.zh : x.en;
}
function sevLabel(s: Card["severity"]): string {
  if (isZh.value) {
    return s === "critical" ? "严重" : s === "high" ? "高危" : "中危";
  }
  return s === "critical" ? "Critical" : s === "high" ? "High" : "Medium";
}
</script>

<style scoped>
.kg {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 1rem;
  margin: 1.25rem 0 2.4rem;
}
.kg__card {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 0.72rem;
  min-height: 230px;
  padding: 1.05rem 1.05rem 0.95rem;
  border-radius: 16px;
  border: 1px solid color-mix(in srgb, var(--vig-accent) 14%, var(--vig-border));
  background:
    linear-gradient(145deg, rgba(20, 184, 166, 0.075), transparent 42%),
    color-mix(in srgb, var(--vig-bg-1) 88%, transparent);
  text-decoration: none !important;
  color: var(--vig-text) !important;
  box-shadow: 0 1px 0 rgba(255, 255, 255, 0.03) inset;
  transition:
    transform 0.18s ease,
    border-color 0.18s ease,
    box-shadow 0.18s ease,
    background 0.18s ease;
  overflow: hidden;
}
.dark .kg__card {
  background:
    linear-gradient(145deg, rgba(20, 184, 166, 0.09), transparent 42%),
    color-mix(in srgb, var(--vig-bg-1) 86%, transparent);
  border-color: rgba(148, 163, 184, 0.13);
}
.kg__card::before {
  content: "";
  position: absolute;
  inset: 0 0 auto;
  height: 3px;
  pointer-events: none;
  background: linear-gradient(90deg, var(--vig-accent), transparent);
  opacity: 0.62;
}
.kg__card::after {
  content: "";
  position: absolute;
  right: -32px;
  bottom: -44px;
  width: 140px;
  height: 140px;
  border-radius: 999px;
  background: radial-gradient(circle, rgba(20, 184, 166, 0.09), transparent 62%);
  pointer-events: none;
}
.kg__card:hover {
  transform: translateY(-2px);
  border-color: color-mix(in srgb, var(--vig-accent) 55%, var(--vig-border));
  box-shadow:
    0 14px 34px -22px rgba(0, 0, 0, 0.72),
    0 0 0 1px color-mix(in srgb, var(--vig-accent) 18%, transparent);
}
.kg__card[data-severity="critical"]:hover {
  border-color: rgba(239, 68, 68, 0.55);
  box-shadow:
    0 12px 32px -12px rgba(2, 6, 23, 0.55),
    0 0 0 1px rgba(239, 68, 68, 0.22);
}

.kg__card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.kg__num {
  font-family: var(--vp-font-family-mono);
  font-size: 0.76rem;
  font-weight: 800;
  letter-spacing: 0.1em;
  padding: 0.18rem 0.5rem;
  border-radius: 8px;
  background: rgba(20, 184, 166, 0.1);
  color: var(--vig-accent);
  border: 1px solid rgba(20, 184, 166, 0.22);
}
.dark .kg__num {
  color: var(--vig-accent-soft);
  background: rgba(20, 184, 166, 0.13);
  border-color: rgba(20, 184, 166, 0.26);
}
.kg__sev {
  font-size: 0.66rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 0.2rem 0.55rem;
  border-radius: 999px;
}
.kg__sev[data-sev="critical"] {
  background: linear-gradient(135deg, #ef4444, #b91c1c);
  color: #fff;
  box-shadow: 0 0 12px rgba(239, 68, 68, 0.35);
}
.kg__sev[data-sev="high"] {
  background: rgba(249, 115, 22, 0.18);
  color: #c2410c;
  border: 1px solid rgba(249, 115, 22, 0.4);
}
.dark .kg__sev[data-sev="high"] {
  color: #fdba74;
  background: rgba(249, 115, 22, 0.22);
}
.kg__sev[data-sev="medium"] {
  background: rgba(234, 179, 8, 0.15);
  color: #a16207;
  border: 1px solid rgba(234, 179, 8, 0.4);
}
.dark .kg__sev[data-sev="medium"] {
  color: #fde68a;
}

.kg__title {
  margin: 0;
  font-size: 1rem;
  font-weight: 700;
  line-height: 1.4;
  color: var(--vig-text);
}
.kg__sub {
  margin: 0;
  font-size: 0.9rem;
  line-height: 1.58;
  color: var(--vig-text-soft);
}

.kg__meta {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  margin-top: 0.2rem;
}
.kg__tag {
  font-size: 0.7rem;
  font-weight: 600;
  padding: 0.16rem 0.48rem;
  border-radius: 999px;
  background: rgba(148, 163, 184, 0.08);
  color: var(--vig-text-muted);
  border: 1px solid rgba(148, 163, 184, 0.12);
  font-family: var(--vp-font-family-mono);
}
.dark .kg__tag {
  background: rgba(148, 163, 184, 0.1);
  border-color: rgba(148, 163, 184, 0.18);
}

.kg__footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  margin-top: auto;
  padding-top: 0.7rem;
  border-top: 1px solid rgba(148, 163, 184, 0.12);
  font-size: 0.74rem;
  color: var(--vig-text-muted);
}
.kg__source {
  flex: 1;
  min-width: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.kg__year {
  font-family: var(--vp-font-family-mono);
  font-weight: 600;
}
.kg__cta {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  font-weight: 600;
  color: var(--vig-accent);
  font-size: 0.78rem;
  white-space: nowrap;
  transition: gap 0.2s ease;
}
.dark .kg__cta {
  color: var(--vig-accent-soft);
}
.kg__card:hover .kg__cta {
  gap: 0.55rem;
}

@media (min-width: 1280px) {
  .kg {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 720px) {
  .kg {
    grid-template-columns: 1fr;
  }
}
</style>
