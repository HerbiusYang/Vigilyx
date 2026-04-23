<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import SharePanel from "./SharePanel.vue";
import HeroBackdrop from "./HeroBackdrop.vue";

const props = withDefaults(
  defineProps<{
    locale?: "en" | "zh";
  }>(),
  {
    locale: "en",
  }
);

type LandingCopy = {
  hero: {
    badge: string;
    stats: Array<{ value: string; label: string }>;
    terminal: {
      title: string;
      lines: Array<{ kind: "prompt" | "out" | "ok" | "warn" | "bad" | "muted"; text: string }>;
    };
    pipeline: {
      title: string;
      stages: Array<{ name: string; verdict: "safe" | "suspicious" | "malicious" | "clean" }>;
    };
  };
  strip: string[];
  deployment: {
    kicker: string;
    title: string;
    body: string;
    cards: Array<{
      label: string;
      title: string;
      body: string;
      points: string[];
      className: string;
    }>;
  };
  flow: {
    kicker: string;
    title: string;
    body: string;
    cards: Array<{
      step: string;
      title: string;
      body: string;
    }>;
  };
  product: {
    kicker: string;
    title: string;
    body: string;
    cards: Array<{
      value: string;
      label: string;
      body: string;
    }>;
  };
  ai: {
    kicker: string;
    title: string;
    body: string;
    cards: Array<{
      title: string;
      body: string;
    }>;
  };
  cta: {
    kicker: string;
    title: string;
    body: string;
    actions: Array<{
      text: string;
      href: string;
      primary?: boolean;
    }>;
  };
};

const landingCopy: Record<"en" | "zh", LandingCopy> = {
  en: {
    hero: {
      badge: "Open source · Rust core · Mirror + Inline",
      stats: [
        { value: "20+", label: "pipeline stages" },
        { value: "30+", label: "DLP patterns" },
        { value: "<8s", label: "inline verdict" },
        { value: "2", label: "deploy modes" },
      ],
      terminal: {
        title: "verdict.jsonl",
        lines: [
          { kind: "muted", text: "# live verdict stream — mirror mode" },
          { kind: "prompt", text: "vigilyx tail --stream verdicts" },
          { kind: "out", text: "[SMTP] mail-01 → alice@corp · subject: \"Invoice 2026-Q1\"" },
          { kind: "ok", text: "verdict: safe    score 0.08  modules 0/15  dlp ok" },
          { kind: "out", text: "[SMTP] mx-2 → bob@corp · subject: \"Account verification\"" },
          { kind: "warn", text: "verdict: medium  score 0.52  modules 4/15  nlp phishing=0.71" },
          { kind: "bad", text: "verdict: high    score 0.81  ioc=sender_ip content=urgency yara=phish_01" },
          { kind: "muted", text: "# action: quarantined · session replayable · explain trail saved" },
        ],
      },
      pipeline: {
        title: "Detection pipeline",
        stages: [
          { name: "Parse", verdict: "clean" },
          { name: "Header", verdict: "clean" },
          { name: "Content", verdict: "suspicious" },
          { name: "Link", verdict: "suspicious" },
          { name: "YARA", verdict: "malicious" },
          { name: "DLP", verdict: "clean" },
          { name: "Fuse", verdict: "malicious" },
        ],
      },
    },
    strip: [
      "Mirror monitoring",
      "Inline SMTP inspection",
      "DLP + YARA + SOAR",
      "Rust core, AI optional",
    ],
    deployment: {
      kicker: "Two deployment paths",
      title: "Start as an observer. Move to inline enforcement when the detections are ready.",
      body:
        "Vigilyx is built for teams that do not want to choose between visibility and control. The same codebase supports a passive email security analysis platform and an inline SMTP proxy with quarantine or rejection paths.",
      cards: [
        {
          label: "Mirror mode",
          title: "Deploy beside the mail system, not inside it",
          body:
            "Mirror traffic from the existing environment, reconstruct mail sessions, and review verdicts after delivery. This is the lower-friction path for forensics, tuning, and alerting.",
          points: [
            "No mail-flow cutover required",
            "Useful for SMTP, POP3, IMAP, and webmail observation",
            "Good fit for audit, replay, and false-positive control",
          ],
          className: "mode-card--mirror",
        },
        {
          label: "Inline MTA mode",
          title: "Become a decision point before final delivery",
          body:
            "Put Vigilyx in the SMTP path as a relay. Messages can be accepted, quarantined, or rejected inline while the detection model stays explainable and operationally tunable.",
          points: [
            "Inline accept, quarantine, and reject actions",
            "Fail-open behavior available for operational safety",
            "Designed for real gateway-style inspection workflows",
          ],
          className: "mode-card--inline",
        },
      ],
    },
    flow: {
      kicker: "Detection flow",
      title: "Structured to be tuned like an engineering system, not sold like a black box.",
      body:
        "The product surface is intentionally opinionated: collect enough signal, keep the fusion explainable, and make the response layer auditable. That makes it easier to reduce false positives without losing the trail.",
      cards: [
        {
          step: "01",
          title: "Collect and normalize",
          body:
            "SMTP, MIME, attachment, link, header, and webmail signals are normalized into a shape the detection engine can reason about across both passive and inline paths.",
        },
        {
          step: "02",
          title: "Fuse evidence",
          body:
            "Multiple analyzers contribute evidence into a verdict pipeline with clustered D-S fusion, module-level explanations, and clear threat scoring instead of opaque labels.",
        },
        {
          step: "03",
          title: "Respond and audit",
          body:
            "Trigger alerts, quarantine, rescan, rejection, and analyst workflows without losing the original session, verdict trail, or operational context.",
        },
      ],
    },
    product: {
      kicker: "Product shape",
      title: "More than a mailbox list with a risk badge.",
      body:
        "The current project already covers the pieces teams usually end up stitching together manually: parsers, verdict fusion, content controls, operational workflows, and a UI that can actually be used for review.",
      cards: [
        {
          value: "20",
          label: "default pipeline entries",
          body: "Detection stages for content, identity, link, attachment, YARA, DLP, and verdicting.",
        },
        {
          value: "30",
          label: "DLP patterns",
          body: "Data-security inspection paths for sensitive content and suspicious transfer behavior.",
        },
        {
          value: "2",
          label: "deployment modes",
          body: "Passive mirror monitoring for visibility and inline MTA inspection for enforcement.",
        },
        {
          value: "Rust",
          label: "core runtime",
          body: "Parsing, detection, API, sniffer, and MTA code paths stay in one performance-oriented stack.",
        },
      ],
    },
    ai: {
      kicker: "AI support",
      title: "Use AI as an extra lens, not as a single point of failure.",
      body:
        "Vigilyx can layer semantic and NLP analysis on top of deterministic detection, but the core pipeline still works when AI is disabled. That keeps operations stable while giving analysts another review lens when it is useful.",
      cards: [
        {
          title: "AI-assisted semantic review",
          body: "Use optional NLP analysis for phishing semantics, language intent, and suspicious persuasion patterns.",
        },
        {
          title: "Core pipeline still stands alone",
          body: "Parsing, link checks, YARA, DLP, identity analysis, and verdict fusion do not depend on any single AI model.",
        },
        {
          title: "Safer for production operations",
          body: "Turn AI on where it improves analyst productivity, not because the product would stop making decisions without it.",
        },
      ],
    },
    cta: {
      kicker: "Who should look at this",
      title: "Built for engineering-led security teams.",
      body:
        "Useful for SOC teams, mail-security engineers, DFIR workflows, and anyone building an internal email security gateway who wants to own the logic instead of renting a black box.",
      actions: [
        { text: "Read Quick Start", href: "/docs/quick-start", primary: true },
        { text: "See deployment modes", href: "/docs/deployment" },
        {
          text: "Browse GitHub",
          href: "https://github.com/HerbiusYang/Vigilyx",
        },
      ],
    },
  },
  zh: {
    hero: {
      badge: "开源 · Rust 核心 · 旁路 + Inline",
      stats: [
        { value: "20+", label: "检测模块" },
        { value: "30+", label: "DLP 规则" },
        { value: "<8s", label: "Inline 判定" },
        { value: "2", label: "部署模式" },
      ],
      terminal: {
        title: "verdict.jsonl",
        lines: [
          { kind: "muted", text: "# 实时 verdict 数据流 · 旁路镜像模式" },
          { kind: "prompt", text: "vigilyx tail --stream verdicts" },
          { kind: "out", text: "[SMTP] mail-01 → alice@corp · 主题：\"发票 2026-Q1\"" },
          { kind: "ok", text: "verdict: safe    score 0.08  modules 0/15  dlp ok" },
          { kind: "out", text: "[SMTP] mx-2 → bob@corp · 主题：\"账户验证提醒\"" },
          { kind: "warn", text: "verdict: medium  score 0.52  modules 4/15  nlp phishing=0.71" },
          { kind: "bad", text: "verdict: high    score 0.81  ioc=sender_ip content=urgency yara=phish_01" },
          { kind: "muted", text: "# action: 已隔离 · 会话可复盘 · 解释链已保存" },
        ],
      },
      pipeline: {
        title: "检测流水线",
        stages: [
          { name: "解析", verdict: "clean" },
          { name: "头部", verdict: "clean" },
          { name: "内容", verdict: "suspicious" },
          { name: "链接", verdict: "suspicious" },
          { name: "YARA", verdict: "malicious" },
          { name: "DLP", verdict: "clean" },
          { name: "融合", verdict: "malicious" },
        ],
      },
    },
    strip: [
      "旁路镜像监控",
      "Inline SMTP 检测",
      "DLP + YARA + SOAR",
      "Rust 核心，AI 可选",
    ],
    deployment: {
      kicker: "两种部署路径",
      title: "可以先做观察系统，再逐步变成真正的投递决策点。",
      body:
        "Vigilyx 的目标不是逼你在“可见性”和“可控性”之间二选一。同一套代码既能做旁路邮件安全分析平台，也能做支持隔离和拒收的 Inline SMTP 代理。",
      cards: [
        {
          label: "Mirror 模式",
          title: "部署在邮件系统旁边，而不是先动主链路",
          body:
            "从现有环境镜像流量，重组邮件会话，再在投递后做分析和复核。这条路径更适合取证、调参、告警和误报收敛。",
          points: [
            "不需要先切换邮件收发链路",
            "适合 SMTP、POP3、IMAP 与 Webmail 观察",
            "更适合审计、回放和规则迭代",
          ],
          className: "mode-card--mirror",
        },
        {
          label: "Inline MTA",
          title: "在最终投递前真正参与决策",
          body:
            "把 Vigilyx 放在 SMTP 路径里作为中继。邮件可以被接受、隔离或拒收，同时判定过程依旧保持可解释、可运营和可调优。",
          points: [
            "支持 Inline accept、quarantine、reject",
            "可配置 fail-open，兼顾生产稳定性",
            "适合做真正的网关型检测链路",
          ],
          className: "mode-card--inline",
        },
      ],
    },
    flow: {
      kicker: "检测流程",
      title: "按工程系统去打磨，而不是按“命中一个模型就下结论”的黑盒思路。",
      body:
        "产品形态是有明确取向的：先收足信号，再做可解释的融合，最后把响应和审计链路补完整。这样才方便在压误报时不把取证能力一起牺牲掉。",
      cards: [
        {
          step: "01",
          title: "收集与归一化",
          body:
            "SMTP、MIME、附件、链接、头部与 Webmail 行为都会被拉平到统一的数据形态，供旁路与 Inline 两条路径复用。",
        },
        {
          step: "02",
          title: "证据融合与判定",
          body:
            "多个检测模块贡献证据，通过 clustered D-S fusion 和模块级解释产出更清晰的 threat score，而不是单个黑盒标签。",
        },
        {
          step: "03",
          title: "响应与审计",
          body:
            "告警、隔离、重扫、拒收与分析师处置都保留在同一条审计链上，不会因为做了自动化就丢掉上下文。",
        },
      ],
    },
    product: {
      kicker: "产品形态",
      title: "不是一个只有列表页和风险标签的“邮件控制台”。",
      body:
        "当前项目已经覆盖了很多团队通常需要自己拼起来的部分：解析器、证据融合、内容控制、处置流以及一套能实际用于分析的前端界面。",
      cards: [
        {
          value: "20",
          label: "默认 pipeline entries",
          body: "覆盖内容、身份、链接、附件、YARA、DLP 与 verdict 的检测链路。",
        },
        {
          value: "30",
          label: "DLP patterns",
          body: "覆盖敏感内容识别与可疑传输行为的数据安全检测路径。",
        },
        {
          value: "2",
          label: "deployment modes",
          body: "既能做旁路可视化分析，也能做 Inline MTA 决策。",
        },
        {
          value: "Rust",
          label: "core runtime",
          body: "抓包、解析、检测、API 与 MTA 逻辑都维持在同一套高性能栈里。",
        },
      ],
    },
    ai: {
      kicker: "AI 支持",
      title: "AI 是额外视角，不是单点依赖。",
      body:
        "Vigilyx 可以在确定性检测链上叠加语义和 NLP 分析，但就算关闭 AI，核心检测流水线仍然可以独立工作。这更适合真实生产环境。",
      cards: [
        {
          title: "AI 辅助语义分析",
          body: "可选接入 NLP 检测，用于钓鱼语义、说服话术和可疑意图分析。",
        },
        {
          title: "核心系统不依赖 AI",
          body: "解析、链接检测、YARA、DLP、身份异常和 verdict fusion 不依赖任何单一模型。",
        },
        {
          title: "更适合生产运维",
          body: "只有当 AI 真正提升分析效率时才启用，而不是“不开 AI 就没法工作”。",
        },
      ],
    },
    cta: {
      kicker: "适合谁看",
      title: "更适合工程驱动的安全团队。",
      body:
        "适用于 SOC、邮件安全工程、DFIR 场景，以及任何想自己掌控邮件安全网关逻辑而不是租用黑盒系统的团队。",
      actions: [
        { text: "查看快速开始", href: "/zh/docs/quick-start", primary: true },
        { text: "了解部署方式", href: "/zh/docs/deployment" },
        {
          text: "查看 GitHub",
          href: "https://github.com/HerbiusYang/Vigilyx",
        },
      ],
    },
  },
};

const copy = computed(() => landingCopy[props.locale]);

function isExternalLink(href: string): boolean {
  return href.startsWith("http://") || href.startsWith("https://");
}

// One-shot scroll-in reveal via IntersectionObserver.
// Disabled: created a jarring "block-by-block" feel on slower machines.
// Entrance animations on hero elements (term-line, pipeline-stage) are enough.
const rootRef = ref<HTMLElement | null>(null);

onMounted(() => {
  // No-op: reveal removed for smoother scrolling.
});

onBeforeUnmount(() => {
  // No-op.
});
</script>

<template>
  <div ref="rootRef" class="home-landing">
    <!-- HERO VISUAL: backdrop + terminal + pipeline -->
    <section class="hero-visual">
      <HeroBackdrop />
      <div class="hero-visual__inner">
        <div class="hero-visual__badge">
          <span class="hero-visual__dot"></span>
          {{ copy.hero.badge }}
        </div>

        <div class="hero-visual__grid">
          <!-- Terminal card -->
          <div class="hero-terminal" role="img" :aria-label="copy.hero.terminal.title">
            <div class="hero-terminal__bar">
              <span class="hero-terminal__dots">
                <i></i><i></i><i></i>
              </span>
              <span class="hero-terminal__title">{{ copy.hero.terminal.title }}</span>
              <span class="hero-terminal__live">● live</span>
            </div>
            <pre class="hero-terminal__body"><code><span
              v-for="(line, idx) in copy.hero.terminal.lines"
              :key="idx"
              :class="['term-line', `term-line--${line.kind}`]"
              :style="{ animationDelay: `${idx * 90}ms` }"
            ><template v-if="line.kind === 'prompt'"><span class="term-caret">$</span> </template>{{ line.text }}</span></code></pre>
          </div>

          <!-- Pipeline card -->
          <div class="hero-pipeline">
            <div class="hero-pipeline__title">{{ copy.hero.pipeline.title }}</div>
            <ol class="hero-pipeline__list">
              <li
                v-for="(stage, idx) in copy.hero.pipeline.stages"
                :key="stage.name"
                :class="['pipeline-stage', `pipeline-stage--${stage.verdict}`]"
                :style="{ animationDelay: `${idx * 110}ms` }"
              >
                <span class="pipeline-stage__index">{{ String(idx + 1).padStart(2, "0") }}</span>
                <span class="pipeline-stage__name">{{ stage.name }}</span>
                <span class="pipeline-stage__pulse"></span>
              </li>
            </ol>
            <div class="hero-pipeline__stats">
              <div v-for="stat in copy.hero.stats" :key="stat.label" class="hero-stat">
                <strong>{{ stat.value }}</strong>
                <span>{{ stat.label }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <div class="home-strip">
      <span v-for="item in copy.strip" :key="item">{{ item }}</span>
    </div>

    <section class="home-section">
      <div class="home-section-heading">
        <p class="home-kicker">{{ copy.deployment.kicker }}</p>
        <h2>{{ copy.deployment.title }}</h2>
        <p>{{ copy.deployment.body }}</p>
      </div>

      <div class="home-dual-grid">
        <article
          v-for="card in copy.deployment.cards"
          :key="card.label"
          :class="['home-surface', 'mode-card', card.className]"
        >
          <p class="mode-label">{{ card.label }}</p>
          <h3>{{ card.title }}</h3>
          <p>{{ card.body }}</p>
          <ul>
            <li v-for="point in card.points" :key="point">{{ point }}</li>
          </ul>
        </article>
      </div>
    </section>

    <section class="home-section">
      <div class="home-section-heading">
        <p class="home-kicker">{{ copy.flow.kicker }}</p>
        <h2>{{ copy.flow.title }}</h2>
        <p>{{ copy.flow.body }}</p>
      </div>

      <div class="home-stack-grid">
        <article
          v-for="card in copy.flow.cards"
          :key="card.step"
          class="home-surface stack-card"
        >
          <span class="stack-step">{{ card.step }}</span>
          <h3>{{ card.title }}</h3>
          <p>{{ card.body }}</p>
        </article>
      </div>
    </section>

    <section class="home-section">
      <div class="home-section-heading">
        <p class="home-kicker">{{ copy.product.kicker }}</p>
        <h2>{{ copy.product.title }}</h2>
        <p>{{ copy.product.body }}</p>
      </div>

      <div class="home-metric-grid">
        <article
          v-for="card in copy.product.cards"
          :key="card.label"
          class="home-surface metric-card"
        >
          <strong>{{ card.value }}</strong>
          <span>{{ card.label }}</span>
          <p>{{ card.body }}</p>
        </article>
      </div>
    </section>

    <section class="home-section">
      <div class="home-section-heading">
        <p class="home-kicker">{{ copy.ai.kicker }}</p>
        <h2>{{ copy.ai.title }}</h2>
        <p>{{ copy.ai.body }}</p>
      </div>

      <div class="home-ai-grid">
        <article
          v-for="card in copy.ai.cards"
          :key="card.title"
          class="home-surface ai-card"
        >
          <h3>{{ card.title }}</h3>
          <p>{{ card.body }}</p>
        </article>
      </div>
    </section>

    <section class="home-section home-cta">
      <div>
        <p class="home-kicker">{{ copy.cta.kicker }}</p>
        <h2>{{ copy.cta.title }}</h2>
        <p>{{ copy.cta.body }}</p>
      </div>
      <div class="home-cta-actions">
        <a
          v-for="action in copy.cta.actions"
          :key="action.text"
          :class="['home-cta-link', action.primary ? 'home-cta-link--primary' : '']"
          :href="action.href"
          :target="isExternalLink(action.href) ? '_blank' : undefined"
          :rel="isExternalLink(action.href) ? 'noreferrer' : undefined"
        >
          {{ action.text }}
        </a>
      </div>
    </section>

    <SharePanel mode="home" />
  </div>
</template>
