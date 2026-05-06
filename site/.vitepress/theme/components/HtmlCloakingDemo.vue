<template>
  <div class="cloak-demo" :class="{ 'cloak-demo--revealed': revealed }">
    <header class="cloak-demo__header">
      <div class="cloak-demo__title">
        <span class="cloak-demo__badge">
          <span class="cloak-demo__badge-dot"></span>
          {{ t.badge }}
        </span>
        <h4>{{ t.title }}</h4>
      </div>
      <div class="cloak-demo__controls">
        <button
          type="button"
          class="cloak-demo__btn cloak-demo__btn--primary"
          @click="toggle"
        >
          <span v-if="revealed">{{ t.reset }}</span>
          <span v-else>{{ t.reveal }}</span>
        </button>
        <button
          type="button"
          class="cloak-demo__btn"
          @click="step"
          :disabled="revealed && currentStage >= stages.length"
        >
          {{ t.step }}
        </button>
      </div>
    </header>

    <div class="cloak-demo__progress" role="progressbar" :aria-valuenow="currentStage" :aria-valuemax="stages.length">
      <div
        v-for="(stage, i) in stages"
        :key="i"
        class="cloak-demo__phase"
        :class="{
          'cloak-demo__phase--done': currentStage > i,
          'cloak-demo__phase--active': currentStage === i + 1,
        }"
      >
        <span class="cloak-demo__phase-num">{{ i + 1 }}</span>
        <span class="cloak-demo__phase-label">{{ stageLabel(stage) }}</span>
      </div>
    </div>

    <div class="cloak-demo__split">
      <!-- LEFT: raw HTML source -->
      <section class="cloak-demo__pane cloak-demo__pane--code">
        <div class="cloak-demo__pane-head">
          <span class="cloak-demo__dot cloak-demo__dot--red"></span>
          <span class="cloak-demo__dot cloak-demo__dot--yellow"></span>
          <span class="cloak-demo__dot cloak-demo__dot--green"></span>
          <span class="cloak-demo__pane-title">{{ t.codePane }}</span>
        </div>
        <pre class="cloak-demo__code"><code v-html="renderedCode"></code></pre>
      </section>

      <!-- RIGHT: browser render preview -->
      <section class="cloak-demo__pane cloak-demo__pane--render">
        <div class="cloak-demo__pane-head">
          <span class="cloak-demo__url-bar">
            <span class="cloak-demo__lock">🔒</span>
            <span class="cloak-demo__url-text">mail.example.com / message #2483</span>
          </span>
          <span class="cloak-demo__pane-title">{{ t.renderPane }}</span>
        </div>
        <div class="cloak-demo__render" v-html="renderedPreview"></div>
      </section>
    </div>

    <footer class="cloak-demo__footer">
      <transition name="cloak-fade">
        <div v-if="currentNarration" :key="currentStage" class="cloak-demo__narration">
          <span class="cloak-demo__narration-tag" :data-actor="currentNarration.actor">
            {{ actorLabel(currentNarration.actor) }}
          </span>
          <span class="cloak-demo__narration-text">{{ narrationText(currentNarration) }}</span>
        </div>
      </transition>
    </footer>
  </div>
</template>

<script setup lang="ts">
/**
 * HtmlCloakingDemo — split-pane "magic reveal" animation for the
 * HTML text cloaking case study.
 *
 * Left pane: raw HTML source. As stages advance, hidden Unicode
 * characters and obfuscation tricks light up with warning highlights
 * — the "magic reveal" you'd see in a heist movie when ink turns
 * visible under UV light.
 *
 * Right pane: faithful browser render of the same HTML. This stays
 * unchanged through stages 1-4 (because that's the whole point of
 * cloaking — humans can't tell), then in stage 5+ Vigilyx's
 * normalisation produces the cleaned-up text on the right too.
 */
import { computed, ref } from "vue";
import { useData } from "vitepress";

interface Stage {
  id: string;
  /** label shown on the progress bar */
  label: { zh: string; en: string };
  /** narration line shown in the footer */
  narration: { zh: string; en: string };
  /** which "actor" colours the narration tag */
  actor: "attacker" | "victim" | "system" | "vigilyx";
}

const { lang } = useData();
const isZh = computed(() => (lang.value || "").toLowerCase().startsWith("zh"));

const stages: Stage[] = [
  {
    id: "raw",
    label: { zh: "原始邮件", en: "Raw email" },
    narration: {
      zh: "受害者收到一封 HR 通知邮件。看起来人畜无害——这正是攻击者要的效果。",
      en: "The victim receives an HR notice. Looks completely benign — exactly what the attacker wants.",
    },
    actor: "victim",
  },
  {
    id: "zero-width",
    label: { zh: "零宽字符", en: "Zero-width chars" },
    narration: {
      zh: "看到那些闪烁的红块了吗？U+200B 零宽空格被插在每个字母之间。肉眼完全看不见，但 /verify your account/ 这种正则永远命中不了。",
      en: "See the flickering red blocks? U+200B zero-width spaces sit between every letter — invisible to humans, but a /verify your account/ regex will never match.",
    },
    actor: "attacker",
  },
  {
    id: "entities",
    label: { zh: "HTML 实体", en: "HTML entities" },
    narration: {
      zh: "&#118;&#101;&#114;&#105;&#102;&#121; 在浏览器里渲染成 “verify”。源码里压根没有这几个字母，关键词扫描全失。",
      en: "&#118;&#101;&#114;&#105;&#102;&#121; renders as “verify” in the browser. The literal letters never appear in the source — keyword scanners are blind.",
    },
    actor: "attacker",
  },
  {
    id: "css-hidden",
    label: { zh: "CSS 隐藏", en: "CSS hidden" },
    narration: {
      zh: "display:none 与 1px 白字段：人类读到完整钓鱼正文，strip_tags 后却得到一堆垃圾词，反而拉高“正常邮件”概率。",
      en: "display:none and 1px white text: humans read coherent phishing prose, but strip_tags yields a junk-laden bag of words that fools naive Bayesian classifiers.",
    },
    actor: "attacker",
  },
  {
    id: "naive",
    label: { zh: "传统网关", en: "Traditional GW" },
    narration: {
      zh: "传统网关：strip_tags + 简单正则 → 关键词全失，邮件被判“正常”，直接放行。",
      en: "Traditional gateway: strip_tags + naive regex → every keyword misses, the mail is judged clean and delivered.",
    },
    actor: "system",
  },
  {
    id: "vigilyx",
    label: { zh: "Vigilyx 还原", en: "Vigilyx normalises" },
    narration: {
      zh: "Vigilyx normalize_text 剥离 14 种零宽字符，decode_html_entities 还原实体，html_scan 标记 display:none 与 1px 白字。还原后钓鱼关键词全部命中，同时混淆行为本身已经是独立证据。",
      en: "Vigilyx normalize_text strips 14 zero-width characters, decode_html_entities expands entities, html_scan flags display:none and 1px white text. Keywords match after normalisation — and the obfuscation itself is independent evidence.",
    },
    actor: "vigilyx",
  },
];

const currentStage = ref(0);
const revealed = computed(() => currentStage.value > 0);

const currentNarration = computed(() =>
  currentStage.value > 0 ? stages[currentStage.value - 1] : null
);

const t = computed(() =>
  isZh.value
    ? {
        badge: "实时演示",
        title: "HTML 文字拼凑：肉眼正常 vs. 源码鬼魅",
        reveal: "▶ 显形",
        reset: "↻ 重置",
        step: "→ 下一步",
        codePane: "源码",
        renderPane: "浏览器渲染",
        attacker: "攻击者",
        victim: "受害者",
        system: "传统网关",
        vigilyx: "Vigilyx",
      }
    : {
        badge: "Live demo",
        title: "HTML text cloaking — what the eye sees vs. what the parser sees",
        reveal: "▶ Reveal",
        reset: "↻ Reset",
        step: "→ Next",
        codePane: "Source",
        renderPane: "Browser render",
        attacker: "Attacker",
        victim: "Victim",
        system: "Traditional GW",
        vigilyx: "Vigilyx",
      }
);

function stageLabel(s: Stage): string {
  return isZh.value ? s.label.zh : s.label.en;
}
function narrationText(s: Stage): string {
  return isZh.value ? s.narration.zh : s.narration.en;
}
function actorLabel(actor: Stage["actor"]): string {
  return t.value[actor];
}

function step() {
  if (currentStage.value < stages.length) {
    currentStage.value += 1;
  }
}

function toggle() {
  if (revealed.value) {
    currentStage.value = 0;
  } else {
    currentStage.value = stages.length;
  }
}

/* ---------------------------------------------------------------- *
 *  LEFT PANE: raw HTML with reveal-aware highlighting
 * ---------------------------------------------------------------- */

// Tokens we want to "light up" stage by stage. We render the HTML by
// hand (rather than reusing a syntax highlighter) because we need
// per-token spans we can class-toggle.

// stage 2 — zero-width chars rendered as visible warning chips
const ZW_CHIP = `<span class="tok tok-zw" title="U+200B ZERO WIDTH SPACE">U+200B</span>`;

// helper to wrap entity bytes so they animate
function ent(numeric: string, ch: string): string {
  return `<span class="tok tok-ent" data-render="${ch}">&amp;#${numeric};</span>`;
}

// helper for css-hidden span
function hidden(content: string): string {
  return `<span class="tok tok-hidden">&lt;span style=&quot;display:none&quot;&gt;${content}&lt;/span&gt;</span>`;
}

const renderedCode = computed(() => {
  const stage = currentStage.value;
  // Build the source markup with stage-aware reveal classes.
  const cls = (...names: string[]) => names.join(" ");
  return [
    `<span class="${cls("ln")}">&lt;!DOCTYPE html&gt;</span>`,
    `<span class="${cls("ln")}">&lt;html&gt;&lt;body style=&quot;font-family:sans-serif&quot;&gt;</span>`,
    `<span class="${cls("ln")}">  &lt;p&gt;Dear Customer,&lt;/p&gt;</span>`,
    `<span class="${cls("ln")}">  &lt;p&gt;We detected unusual activity on your`,
    `    <span class="reveal-zw" data-on="${stage >= 2}">acc${ZW_CHIP}o${ZW_CHIP}u${ZW_CHIP}n${ZW_CHIP}t</span>.&lt;/p&gt;</span>`,
    `<span class="${cls("ln")}">  &lt;p&gt;Please &lt;a href=&quot;https://bad.example/login&quot;&gt;</span>`,
    `<span class="${cls("ln")}">    <span class="reveal-ent" data-on="${stage >= 3}">${ent("118", "v")}${ent("101", "e")}${ent("114", "r")}${ent("105", "i")}${ent("102", "f")}${ent("121", "y")}</span> your`,
    `    <span class="reveal-zw" data-on="${stage >= 2}">iden${ZW_CHIP}tity</span>&lt;/a&gt;</span>`,
    `<span class="${cls("ln")}">  within 24 hours, or your`,
    `    <span class="reveal-zw" data-on="${stage >= 2}">acc${ZW_CHIP}ount</span> will be`,
    `    <span class="reveal-zw" data-on="${stage >= 2}">sus${ZW_CHIP}pended</span>.&lt;/p&gt;</span>`,
    `<span class="${cls("ln")}">  <span class="reveal-hidden" data-on="${stage >= 4}">${hidden("RANDOMJUNK")}</span></span>`,
    `<span class="${cls("ln")}">  <span class="reveal-hidden" data-on="${stage >= 4}">&lt;p style=&quot;color:#fff;font-size:1px&quot;&gt;legitimate transaction notification harmless content&lt;/p&gt;</span></span>`,
    `<span class="${cls("ln")}">&lt;/body&gt;&lt;/html&gt;</span>`,
  ].join("\n");
});

/* ---------------------------------------------------------------- *
 *  RIGHT PANE: rendered preview
 * ---------------------------------------------------------------- */

const renderedPreview = computed(() => {
  const stage = currentStage.value;
  if (stage <= 4) {
    // Stages 0-4: what a normal user sees in their email client.
    return `
      <p>Dear Customer,</p>
      <p>We detected unusual activity on your account.</p>
      <p>Please <a href="#" class="cloak-demo__link">verify your identity</a>
         within 24 hours, or your account will be suspended.</p>
      <p style="margin-top:1.2em;color:var(--vp-c-text-3);font-size:0.78rem">
        — HR Compliance Team
      </p>
    `;
  }
  if (stage === 5) {
    // Stage 5: traditional gateway sees a junk-laden bag of words after strip_tags
    return `
      <div class="cloak-demo__verdict cloak-demo__verdict--bad">
        <div class="cloak-demo__verdict-head">${isZh.value ? "传统网关看到的（strip_tags 后）" : "What a traditional gateway sees (after strip_tags)"}</div>
        <code class="cloak-demo__verdict-body">
Dear Customer, We detected unusual activity on your acc(U+200B)ou(U+200B)nt. Please &amp;#118;&amp;#101;&amp;#114;&amp;#105;&amp;#102;&amp;#121; your iden(U+200B)tity ... RANDOMJUNK legitimate transaction notification harmless content
        </code>
        <div class="cloak-demo__verdict-tag cloak-demo__verdict-tag--bad">
          ${isZh.value ? "判定：CLEAN ✗（误判，邮件已投递）" : "Verdict: CLEAN ✗ (mis-classified, mail delivered)"}
        </div>
      </div>
    `;
  }
  // Stage 6: Vigilyx normalises and matches
  return `
    <div class="cloak-demo__verdict cloak-demo__verdict--good">
      <div class="cloak-demo__verdict-head">${isZh.value ? "Vigilyx 规范化后看到的" : "What Vigilyx sees after normalisation"}</div>
      <code class="cloak-demo__verdict-body">
Dear Customer, We detected unusual activity on your <mark>account</mark>. Please <mark>verify</mark> your <mark>identity</mark> within 24 hours, or your <mark>account</mark> will be <mark>suspended</mark>.
      </code>
      <div class="cloak-demo__signals">
        <span class="cloak-demo__sig">${isZh.value ? "命中：account_security_phishing" : "match: account_security_phishing"}</span>
        <span class="cloak-demo__sig">${isZh.value ? "证据：zero_width_cloaking" : "evidence: zero_width_cloaking"}</span>
        <span class="cloak-demo__sig">${isZh.value ? "证据：css_hidden_text" : "evidence: css_hidden_text"}</span>
      </div>
      <div class="cloak-demo__verdict-tag cloak-demo__verdict-tag--good">
        ${isZh.value ? "Vigilyx 判定：HIGH — 邮件进入隔离区 ✓" : "Vigilyx verdict: HIGH — mail quarantined ✓"}
      </div>
    </div>
  `;
});
</script>

<style scoped>
.cloak-demo {
  margin: 1.5rem 0;
  border: 1px solid var(--vp-c-divider);
  border-radius: 16px;
  overflow: hidden;
  background: linear-gradient(
    180deg,
    rgba(15, 23, 42, 0.04) 0%,
    rgba(15, 23, 42, 0.01) 100%
  );
  font-size: 0.92rem;
}
.dark .cloak-demo {
  background: linear-gradient(
    180deg,
    rgba(2, 6, 23, 0.85) 0%,
    rgba(2, 6, 23, 0.6) 100%
  );
  border-color: rgba(148, 163, 184, 0.15);
}

/* ----- header ----- */

.cloak-demo__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.85rem 1.1rem;
  border-bottom: 1px solid var(--vp-c-divider);
  flex-wrap: wrap;
  background: rgba(15, 23, 42, 0.04);
}
.dark .cloak-demo__header {
  background: rgba(2, 6, 23, 0.5);
  border-bottom-color: rgba(148, 163, 184, 0.12);
}

.cloak-demo__title {
  display: flex;
  align-items: center;
  gap: 0.7rem;
  min-width: 0;
}
.cloak-demo__title h4 {
  margin: 0;
  font-size: 1rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
  line-height: 1.4;
}

.cloak-demo__badge {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 0.7rem;
  font-weight: 600;
  padding: 0.25rem 0.6rem;
  border-radius: 999px;
  background: linear-gradient(135deg, #ef4444, #b91c1c);
  color: #fff;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  white-space: nowrap;
  box-shadow: 0 0 12px rgba(239, 68, 68, 0.35);
}
.cloak-demo__badge-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #fff;
  animation: cloak-pulse-dot 1.4s ease-in-out infinite;
}
@keyframes cloak-pulse-dot {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.4; transform: scale(0.7); }
}

.cloak-demo__controls {
  display: flex;
  gap: 0.4rem;
  flex-wrap: wrap;
}
.cloak-demo__btn {
  font: inherit;
  font-size: 0.82rem;
  font-weight: 500;
  padding: 0.4rem 0.9rem;
  border-radius: 8px;
  border: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-1);
  cursor: pointer;
  transition: background 0.15s, border-color 0.15s, transform 0.15s;
  white-space: nowrap;
}
.cloak-demo__btn:hover:not(:disabled) {
  background: var(--vp-c-bg-mute);
  border-color: var(--vp-c-brand-1);
  transform: translateY(-1px);
}
.cloak-demo__btn:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}
.cloak-demo__btn--primary {
  background: linear-gradient(135deg, #f97316, #ef4444);
  color: #fff;
  border-color: transparent;
  box-shadow: 0 4px 14px rgba(239, 68, 68, 0.25);
}
.cloak-demo__btn--primary:hover:not(:disabled) {
  background: linear-gradient(135deg, #ea580c, #dc2626);
  border-color: transparent;
}

/* ----- progress phases ----- */

.cloak-demo__progress {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 4px;
  padding: 0.7rem 1.1rem 0.5rem;
}
.cloak-demo__phase {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.4rem 0.5rem;
  border-radius: 7px;
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
  font-size: 0.72rem;
  color: var(--vp-c-text-2);
  transition: all 0.35s ease;
  min-width: 0;
}
.cloak-demo__phase--done {
  background: rgba(34, 197, 94, 0.08);
  border-color: rgba(34, 197, 94, 0.3);
  color: var(--vp-c-text-1);
}
.cloak-demo__phase--active {
  background: linear-gradient(135deg, rgba(249, 115, 22, 0.15), rgba(239, 68, 68, 0.12));
  border-color: #f97316;
  color: var(--vp-c-text-1);
  box-shadow: 0 0 0 3px rgba(249, 115, 22, 0.18);
  animation: cloak-phase-pulse 1.2s ease-in-out infinite;
}
@keyframes cloak-phase-pulse {
  0%, 100% { box-shadow: 0 0 0 3px rgba(249, 115, 22, 0.18); }
  50% { box-shadow: 0 0 0 6px rgba(249, 115, 22, 0.06); }
}
.cloak-demo__phase-num {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: var(--vp-c-bg-mute);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 0.65rem;
  font-weight: 700;
  flex-shrink: 0;
}
.cloak-demo__phase--done .cloak-demo__phase-num {
  background: #22c55e;
  color: #fff;
}
.cloak-demo__phase--active .cloak-demo__phase-num {
  background: linear-gradient(135deg, #f97316, #ef4444);
  color: #fff;
}
.cloak-demo__phase-label {
  font-weight: 500;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* ----- split panes ----- */

.cloak-demo__split {
  display: grid;
  grid-template-columns: 1.15fr 0.85fr;
  gap: 1px;
  background: var(--vp-c-divider);
  min-height: 380px;
}
.dark .cloak-demo__split {
  background: rgba(148, 163, 184, 0.12);
}

.cloak-demo__pane {
  display: flex;
  flex-direction: column;
  background: var(--vp-c-bg);
  min-width: 0;
}
.cloak-demo__pane--code {
  background: #0f172a;
}
.dark .cloak-demo__pane--code {
  background: #020617;
}
.cloak-demo__pane--render {
  background: #ffffff;
}
.dark .cloak-demo__pane--render {
  background: #f8fafc;
}

.cloak-demo__pane-head {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.45rem 0.7rem;
  background: rgba(15, 23, 42, 0.6);
  border-bottom: 1px solid rgba(148, 163, 184, 0.15);
  font-size: 0.7rem;
  color: rgba(226, 232, 240, 0.85);
  flex-shrink: 0;
}
.cloak-demo__pane--render .cloak-demo__pane-head {
  background: #f1f5f9;
  border-bottom-color: #e2e8f0;
  color: #64748b;
}
.dark .cloak-demo__pane--render .cloak-demo__pane-head {
  background: #e2e8f0;
  color: #475569;
}

.cloak-demo__dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}
.cloak-demo__dot--red { background: #ef4444; }
.cloak-demo__dot--yellow { background: #eab308; }
.cloak-demo__dot--green { background: #22c55e; }

.cloak-demo__pane-title {
  margin-left: auto;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  font-size: 0.66rem;
  opacity: 0.75;
}

.cloak-demo__url-bar {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.25rem 0.7rem;
  border-radius: 999px;
  background: #fff;
  color: #0f172a;
  font-size: 0.72rem;
  font-weight: 500;
  border: 1px solid #e2e8f0;
}
.dark .cloak-demo__url-bar {
  background: #cbd5e1;
  border-color: #94a3b8;
}
.cloak-demo__lock { font-size: 0.7rem; }
.cloak-demo__url-text { font-family: var(--vp-font-family-mono); font-size: 0.7rem; }

/* ----- code (left) ----- */

.cloak-demo__code {
  flex: 1;
  margin: 0;
  padding: 0.7rem 0.8rem;
  background: transparent !important;
  font-family: var(--vp-font-family-mono);
  font-size: 0.72rem;
  line-height: 1.65;
  color: #cbd5e1;
  overflow: auto;
  white-space: pre;
  word-break: normal;
}
.cloak-demo__code :deep(.ln) {
  display: block;
}
.cloak-demo__code :deep(.tok) {
  display: inline;
  border-radius: 3px;
  padding: 0 0.15em;
  transition: all 0.4s ease;
}

/* zero-width chip — bright red flicker when revealed */
.cloak-demo__code :deep(.tok-zw) {
  display: inline-block;
  background: #1f2937;
  color: #1f2937;
  border: 1px dashed #1f2937;
  font-size: 0.62rem;
  font-weight: 700;
  padding: 0 0.3em;
  margin: 0 1px;
  vertical-align: middle;
  letter-spacing: 0.05em;
  user-select: none;
}
.cloak-demo__code :deep(.reveal-zw[data-on="true"] .tok-zw) {
  background: rgba(239, 68, 68, 0.85);
  color: #fff;
  border-color: #fca5a5;
  box-shadow: 0 0 8px rgba(239, 68, 68, 0.6);
  animation: cloak-flicker 1.6s ease-in-out infinite;
}
@keyframes cloak-flicker {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.55; box-shadow: 0 0 14px rgba(239, 68, 68, 0.9); }
}
.cloak-demo__code :deep(.reveal-zw[data-on="true"]) {
  background: rgba(239, 68, 68, 0.08);
}

/* HTML entity tokens — wash with amber when revealed */
.cloak-demo__code :deep(.tok-ent) {
  color: #94a3b8;
}
.cloak-demo__code :deep(.reveal-ent[data-on="true"] .tok-ent) {
  background: rgba(251, 191, 36, 0.22);
  color: #fde68a;
  border-bottom: 1px dashed #fbbf24;
  position: relative;
}
.cloak-demo__code :deep(.reveal-ent[data-on="true"] .tok-ent)::after {
  content: "→ " attr(data-render);
  margin-left: 0.3em;
  font-size: 0.66rem;
  font-weight: 700;
  color: #fbbf24;
}

/* CSS-hidden block — strike-through purple */
.cloak-demo__code :deep(.tok-hidden) {
  color: #64748b;
}
.cloak-demo__code :deep(.reveal-hidden[data-on="true"] .tok-hidden) {
  background: rgba(168, 85, 247, 0.18);
  color: #e9d5ff;
  text-decoration: line-through;
  text-decoration-color: rgba(168, 85, 247, 0.7);
  text-decoration-thickness: 2px;
  border-radius: 4px;
  padding: 0.05em 0.2em;
}

/* ----- render (right) ----- */

.cloak-demo__render {
  flex: 1;
  padding: 1.2rem 1.4rem;
  overflow: auto;
  color: #0f172a;
  background: #fff;
  font-family: -apple-system, "Segoe UI", sans-serif;
  font-size: 0.92rem;
  line-height: 1.65;
}
.dark .cloak-demo__render {
  color: #0f172a;
  background: #f8fafc;
}
.cloak-demo__render :deep(p) {
  margin: 0 0 0.8em;
}
.cloak-demo__render :deep(.cloak-demo__link) {
  color: #2563eb;
  text-decoration: underline;
}
.cloak-demo__render :deep(mark) {
  background: rgba(34, 197, 94, 0.25);
  color: #14532d;
  padding: 0 0.25em;
  border-radius: 3px;
  font-weight: 600;
}

/* verdict cards (stage 5 / 6) */
.cloak-demo__render :deep(.cloak-demo__verdict) {
  border-radius: 10px;
  padding: 1rem;
  border: 1px solid;
  animation: cloak-verdict-in 0.5s ease;
}
@keyframes cloak-verdict-in {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}
.cloak-demo__render :deep(.cloak-demo__verdict--bad) {
  background: rgba(239, 68, 68, 0.06);
  border-color: rgba(239, 68, 68, 0.4);
}
.cloak-demo__render :deep(.cloak-demo__verdict--good) {
  background: rgba(34, 197, 94, 0.07);
  border-color: rgba(34, 197, 94, 0.45);
}
.cloak-demo__render :deep(.cloak-demo__verdict-head) {
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: #475569;
  margin-bottom: 0.6rem;
}
.cloak-demo__render :deep(.cloak-demo__verdict-body) {
  display: block;
  font-family: var(--vp-font-family-mono);
  font-size: 0.74rem;
  background: rgba(15, 23, 42, 0.05);
  padding: 0.6rem 0.7rem;
  border-radius: 6px;
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.55;
  color: #1e293b;
}
.cloak-demo__render :deep(.cloak-demo__signals) {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin: 0.7rem 0;
}
.cloak-demo__render :deep(.cloak-demo__sig) {
  font-size: 0.7rem;
  font-weight: 600;
  padding: 0.2rem 0.55rem;
  border-radius: 4px;
  background: rgba(34, 197, 94, 0.12);
  color: #15803d;
  border: 1px solid rgba(34, 197, 94, 0.3);
  font-family: var(--vp-font-family-mono);
}
.cloak-demo__render :deep(.cloak-demo__verdict-tag) {
  margin-top: 0.7rem;
  display: inline-block;
  padding: 0.35rem 0.7rem;
  border-radius: 6px;
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.02em;
}
.cloak-demo__render :deep(.cloak-demo__verdict-tag--bad) {
  background: #ef4444;
  color: #fff;
}
.cloak-demo__render :deep(.cloak-demo__verdict-tag--good) {
  background: #22c55e;
  color: #fff;
}

/* ----- footer narration ----- */

.cloak-demo__footer {
  padding: 0.85rem 1.1rem;
  border-top: 1px solid var(--vp-c-divider);
  background: rgba(15, 23, 42, 0.03);
  min-height: 3.2rem;
  display: flex;
  align-items: center;
}
.dark .cloak-demo__footer {
  background: rgba(2, 6, 23, 0.5);
  border-top-color: rgba(148, 163, 184, 0.12);
}

.cloak-demo__narration {
  display: flex;
  align-items: flex-start;
  gap: 0.7rem;
  font-size: 0.88rem;
  line-height: 1.55;
  color: var(--vp-c-text-1);
}
.cloak-demo__narration-tag {
  flex-shrink: 0;
  font-size: 0.68rem;
  font-weight: 700;
  padding: 0.2rem 0.55rem;
  border-radius: 4px;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  white-space: nowrap;
}
.cloak-demo__narration-tag[data-actor="attacker"] {
  background: rgba(239, 68, 68, 0.18);
  color: #b91c1c;
  border: 1px solid rgba(239, 68, 68, 0.4);
}
.dark .cloak-demo__narration-tag[data-actor="attacker"] {
  color: #fca5a5;
  background: rgba(239, 68, 68, 0.22);
}
.cloak-demo__narration-tag[data-actor="victim"] {
  background: rgba(234, 179, 8, 0.16);
  color: #a16207;
  border: 1px solid rgba(234, 179, 8, 0.4);
}
.dark .cloak-demo__narration-tag[data-actor="victim"] {
  color: #fde68a;
  background: rgba(234, 179, 8, 0.2);
}
.cloak-demo__narration-tag[data-actor="system"] {
  background: rgba(100, 116, 139, 0.18);
  color: #475569;
  border: 1px solid rgba(100, 116, 139, 0.4);
}
.dark .cloak-demo__narration-tag[data-actor="system"] {
  color: #cbd5e1;
  background: rgba(100, 116, 139, 0.25);
}
.cloak-demo__narration-tag[data-actor="vigilyx"] {
  background: rgba(34, 197, 94, 0.18);
  color: #15803d;
  border: 1px solid rgba(34, 197, 94, 0.45);
}
.dark .cloak-demo__narration-tag[data-actor="vigilyx"] {
  color: #86efac;
  background: rgba(34, 197, 94, 0.22);
}

.cloak-demo__narration-text { flex: 1; }

/* ----- transitions ----- */

.cloak-fade-enter-active,
.cloak-fade-leave-active {
  transition: opacity 0.35s ease, transform 0.35s ease;
}
.cloak-fade-enter-from {
  opacity: 0;
  transform: translateY(4px);
}
.cloak-fade-leave-to {
  opacity: 0;
  transform: translateY(-4px);
}

/* ----- responsive ----- */

@media (max-width: 760px) {
  .cloak-demo__split {
    grid-template-columns: 1fr;
  }
  .cloak-demo__progress {
    grid-template-columns: repeat(3, 1fr);
  }
  .cloak-demo__phase-label {
    font-size: 0.66rem;
  }
  .cloak-demo__code {
    white-space: pre-wrap;
    word-break: break-word;
  }
}

@media (prefers-reduced-motion: reduce) {
  .cloak-demo__code :deep(.reveal-zw[data-on="true"] .tok-zw),
  .cloak-demo__phase--active,
  .cloak-demo__badge-dot {
    animation: none !important;
  }
}
</style>
