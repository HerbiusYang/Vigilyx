<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, shallowRef, watch } from "vue";
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
      icon: "pipeline" | "shield" | "deploy" | "rust";
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
  highlights: {
    kicker: string;
    title: string;
    body: string;
    cards: Array<{
      tag: string;
      title: string;
      body: string;
      why: string;
      source: string;
    }>;
  };
  anatomy: {
    kicker: string;
    title: string;
    body: string;
    selectorLabel: string;
    captureLabel: string;
    verdictLabel: string;
    actionLabelPrefix: string;
    hoverHint: string;
    layerNames: [string, string, string, string, string];
    emails: Array<{
      id: string;
      name: string;
      headline: string;
      lines: Array<{
        label: string;
        content: string;
        tag: string;
        why: string;
      }>;
      verdict: {
        level: string;
        score: string;
        action: string;
        className: "verdict-safe" | "verdict-low" | "verdict-medium" | "verdict-high" | "verdict-critical";
      };
    }>;
  };
  cta: {
    title: string;
    body: string;
    terminal: {
      title: string;
      commands: Array<{ kind: "comment" | "prompt" | "hint"; text: string }>;
      copyLabel: string;
      copiedLabel: string;
      copyPayload: string;
    };
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
        { value: "Clustered D-S", label: "evidence fusion" },
        { value: "5-state HMM", label: "BEC phase tracking" },
        { value: "Hawkes", label: "self-exciting time series" },
      ],
      terminal: {
        title: "verdict.jsonl",
        lines: [
          { kind: "muted", text: "# illustrative verdicts — mirror mode" },
          { kind: "prompt", text: "# console/API output illustration" },
          { kind: "out", text: "[SMTP] mail-01 → alice@corp · subject: \"Invoice 2026-Q1\"" },
          { kind: "ok", text: "verdict: safe    score 0.08  modules 0/15  dlp ok" },
          { kind: "out", text: "[SMTP] mx-2 → bob@corp · subject: \"Account verification\"" },
          { kind: "warn", text: "verdict: medium  score 0.52  modules 4/15  nlp phishing=0.71" },
          { kind: "bad", text: "verdict: high    score 0.81  ioc=sender_ip content=urgency yara=phish_01" },
          { kind: "muted", text: "# action: alert/audit · mirror mode cannot quarantine" },
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
    deployment: {
      kicker: "Two independent deployment shapes",
      title: "Pick the deployment that fits the environment. Not a migration path.",
      body:
        "Mirror and MTA are two separate deployment shapes for two different operating models, not two phases of the same rollout. They share the same detection stack, but they are installed, operated, and evaluated independently. Run the one that matches how much of the mail path you can own.",
      cards: [
        {
          label: "Mirror deployment",
          title: "Passive analysis next to the mail system",
          body:
            "Vigilyx receives mirrored traffic and reconstructs inspectable SMTP and configured HTTP/Webmail content. POP3/IMAP currently provide metadata and coverage signals. Encrypted or incomplete payloads remain coverage gaps; mirror mode alerts and audits after delivery.",
          points: [
            "Zero-touch — no change to MX records or SMTP routing",
            "Verdicts are advisory: alert, audit, replay, tune",
            "Best fit when the mail path cannot be reshaped, or for forensics and rule iteration",
          ],
          className: "mode-card--mirror",
        },
        {
          label: "MTA deployment",
          title: "Inline SMTP proxy that enforces before delivery",
          body:
            "Vigilyx relays SMTP through an embedded engine. Policy can relay, quarantine, reject, or return a temporary failure. The default inline timeout is 8 seconds; fail-open is optional and outbound DLP still applies to relay candidates.",
          points: [
            "Enforcing — mail actually does not reach users until Vigilyx decides",
            "Accept / quarantine / reject, with fail-open safety valve",
            "Best fit when the mail path can be reshaped and real blocking is required",
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
            "SMTP, MIME, attachment, link, header, and webmail signals are normalized into a single shape the detection engine can reason about — whether they arrive from a mirror capture or from the inline MTA proxy.",
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
          value: "29",
          label: "default pipeline entries",
          body: "Configured entries include verdict and conditional integrations; SMTP outbound DLP is a separate policy path.",
          icon: "pipeline",
        },
        {
          value: "DLP",
          label: "pattern families",
          body: "Data-security inspection paths for sensitive content and suspicious transfer behavior.",
          icon: "shield",
        },
        {
          value: "2",
          label: "deployment modes",
          body: "Two independent shapes — mirror deployment for passive visibility, MTA deployment for inline enforcement. Pick one per environment.",
          icon: "deploy",
        },
        {
          value: "Rust",
          label: "core runtime",
          body: "Parsing, detection, API, sniffer, and MTA code paths stay in one performance-oriented stack.",
          icon: "rust",
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
          body: "Local rules can run beside an optional CPU ONNX intent model in shadow mode. Explicit scored mode replaces the local semantic path. Python NLP/OCR and external LLM review are separate optional integrations.",
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
    highlights: {
      kicker: "Under the hood",
      title: "Four implementation paths you can inspect.",
      body:
        "Explore the source for evidence fusion, temporal diagnostics, AitM indicators, and HTML pixel analysis. Available evidence depends on capture coverage and runtime configuration.",
      cards: [
        {
          tag: "Evidence fusion",
          title: "Clustered D-S fusion with causal-source deduplication",
          body:
            "The default ds_murphy configuration dispatches to clustered_ds_v1: evidence clusters support scenario scaling and diagnostics, while stable causal keys deduplicate repeated source views. Each unique source is fused once. Copula correction belongs to the explicitly selected legacy_ds_murphy strategy.",
          why: "Preserves evidence provenance and limits repeated votes from the same causal source; cluster summaries are diagnostic.",
          source: "crates/vigilyx-engine/src/pipeline/verdict/clustered_ds_v1.rs",
        },
        {
          tag: "Temporal layer",
          title: "Full temporal layer on top of single-email verdicts",
          body:
            "CUSUM for shift detection, dual-speed EWMA for baseline drift, a marked Hawkes self-excitation process for attack-campaign tempo, a 5-state HMM that infers BEC / ATO phases (recon → trust-build → execute → exfil), plus a directed communication graph. Most mail-security products judge each email in isolation — this one doesn't.",
          why: "Provides cross-message diagnostics for analyst review; inferred phases are not proof of an attack.",
          source: "crates/vigilyx-engine/src/temporal/",
        },
        {
          tag: "AitM phishing",
          title: "Reverse-proxy MFA-bypass kit fingerprinting",
          body:
            "Analyzes AitM-related clues such as hosted-platform URLs, OAuth redirect mismatches, MFA/CAPTCHA language, and mixed-script brand domains. A hosting platform or CAPTCHA alone does not establish a phishing toolkit.",
          why: "Adds contextual clues for reviewing reverse-proxy phishing alongside other evidence.",
          source: "crates/vigilyx-engine/src/modules/aitm_detect.rs",
        },
        {
          tag: "HTML pixel art",
          title: "HTML pixel art & table-cell QR detection",
          body:
            "Attackers \"draw\" QR codes with <table> bgcolor cells, or assemble phishing text from floated <div>s with background-color — specifically to bypass OCR and sandbox image scanning. Vigilyx reconstructs the bitmap from DOM structure and decodes with rqrr. Unicode block-character ASCII-art QR codes in body text are decoded through the same pipeline.",
          why: "Complements image scanning with DOM-derived graphical evidence.",
          source: "crates/vigilyx-engine/src/modules/html_pixel_art.rs",
        },
      ],
    },
    anatomy: {
      kicker: "Layer by layer",
      title: "Open one email. Watch every layer flag it.",
      body:
        "These fictional scenarios illustrate analysis concepts. Fields, scores, and histories are illustrative, not captured output or benchmark results. Mail threat verdicts and HTTP data-security incidents use separate paths; final actions depend on mode and policy.",
      selectorLabel: "Scenario",
      captureLabel: "captured",
      verdictLabel: "Illustrative result",
      actionLabelPrefix: "Action",
      hoverHint: "Hover any line to see why Vigilyx flagged it.",
      layerNames: ["Sniffer", "Parser", "Engine", "Fusion", "Temporal"],
      emails: [
        {
          id: "bec",
          name: "BEC wire fraud",
          headline: "From: ceo@acme-corp.com  ·  Subject: [URGENT] Wire transfer — vendor change  ·  Tue 14:03",
          lines: [
            {
              label: "L1 · pcap",
              content: "SMTP 203.0.113.44 → mx.acme-corp.com",
              tag: "NEW SENDER IP",
              why: "Sender IP has zero history in the directed communication graph; first-seen inbound path from this /24.",
            },
            {
              label: "L2 · headers",
              content: "SPF=softfail  DKIM=none  DMARC=fail  Reply-To: ceo.acme@proton.me",
              tag: "REPLY-TO MISMATCH",
              why: "Reply-To domain does not match From. Classic look-alike: free-mail reply, corporate display name.",
            },
            {
              label: "L3 · content",
              content: "subject=\"[URGENT] Wire transfer\"  urgency_financial_combo=0.78",
              tag: "URGENCY + $",
              why: "content_scan flags the urgency_financial_combo rule — urgency keyword + amount mention + deadline within 24h.",
            },
            {
              label: "L4 · identity",
              content: "display_name=\"CEO John Doe\"  first_comm_window=true",
              tag: "IDENTITY ANOMALY",
              why: "identity_anomaly: sender domain has never corresponded with this mailbox. First-contact wire-transfer asks are BEC gold.",
            },
            {
              label: "L5 · temporal",
              content: "HMM phase: EXECUTE  ·  CUSUM drift +3.2σ against baseline",
              tag: "HMM EXECUTE",
              why: "5-state HMM transitioned recon → trust-build → EXECUTE over the past 8 days. CUSUM confirms baseline drift.",
            },
          ],
          verdict: {
            level: "HIGH",
            score: "0.81",
            action: "MTA: policy quarantine; mirror: alert and audit",
            className: "verdict-high",
          },
        },
        {
          id: "aitm",
          name: "AitM MFA bypass",
          headline: "From: no-reply@m1crosoft-auth.workers.dev  ·  Subject: Unusual sign-in — verify now  ·  Mon 09:41",
          lines: [
            {
              label: "L1 · pcap",
              content: "HTTPS 104.21.48.11  ·  SNI=m1crosoft-auth.workers.dev",
              tag: "CLOUDFLARE DGA",
              why: "A hosted-platform URL is a contextual clue; it does not establish domain age or identify a toolkit.",
            },
            {
              label: "L2 · link_scan",
              content: "href=\"…/oauth2/authorize?redirect_uri=https://evil-proxy.xyz/callback\"",
              tag: "OAUTH MISMATCH",
              why: "redirect_uri does not match any Microsoft official callback. AitM proxy signature, not a typo'd link.",
            },
            {
              label: "L3 · brand",
              content: "display_text=\"Microsоft\" (Cyrillic о in brand name)",
              tag: "HOMOGRAPH",
              why: "Latin/Cyrillic mixed script. Renders identical, fails exact-match brand guard — classic homograph impersonation.",
            },
            {
              label: "L4 · aitm_detect",
              content: "MFA/CAPTCHA context + URL observations",
              tag: "TYCOON2FA",
              why: "MFA/CAPTCHA and URL clues need independent corroboration; they do not prove toolkit identity.",
            },
            {
              label: "L5 · fusion",
              content: "clustered_ds_v1 · repeated causal source views deduplicated",
              tag: "CLUSTERED D-S",
              why: "The default path deduplicates stable causal keys before fusion; cluster summaries do not cast extra votes.",
            },
          ],
          verdict: {
            level: "CRITICAL",
            score: "0.94",
            action: "MTA: policy rejection; mirror: alert and audit",
            className: "verdict-critical",
          },
        },
        {
          id: "exfil",
          name: "Webmail data exfil",
          headline: "HTTP POST /webmail/compose.jsp · sensitive self-send illustration",
          lines: [
            {
              label: "L1 · pcap",
              content: "HTTP mirror · configured Webmail host · multipart/form-data",
              tag: "HTTP CAPTURE",
              why: "HTTP capture requires configured Webmail targets and inspectable traffic.",
            },
            {
              label: "L2 · webmail",
              content: "reassembled body extracted from compose.jsp action payload",
              tag: "WEBMAIL RECON",
              why: "Coremail field extraction and bounded multipart/file inspection provide HTTP data-security inputs.",
            },
            {
              label: "L3 · dlp",
              content: "PII hits: 11× id_card, 4× bank_account, 2× phone",
              tag: "DLP PII",
              why: "DLP engine matches 17 sensitive tokens after Unicode normalization (zero-width chars stripped).",
            },
            {
              label: "L4 · recipient",
              content: "from=user@corp · to=user@corp · sensitive content",
              tag: "SELF-SEND",
              why: "Self-send analysis compares sender and recipient; sensitive-data findings require analyst review.",
            },
            {
              label: "L5 · coverage",
              content: "bounded scan · explicit incomplete-inspection reasons",
              tag: "DLP COVERAGE",
              why: "Size and time limits bound DLP inspection. An incomplete scan is not a clean result.",
            },
          ],
          verdict: {
            level: "HIGH",
            score: "0.82",
            action: "Record HTTP DLP incident for review; mirror cannot block",
            className: "verdict-high",
          },
        },
      ],
    },
    cta: {
      title: "Built for engineering-led security teams. Just clone it.",
      body:
        "Configure a remote build host, initialize it, review runtime settings, then deploy mirror or MTA mode. AGPL-3.0, with no network license requirement. HTTPS requires a TLS entry point.",
      terminal: {
        title: "deploy.sh",
        commands: [
          { kind: "comment", text: "# 1. Clone the repo" },
          { kind: "prompt", text: "git clone https://github.com/HerbiusYang/Vigilyx.git" },
          { kind: "prompt", text: "cd Vigilyx" },
          { kind: "comment", text: "# 2. Configure the remote host" },
          { kind: "prompt", text: "cp deploy.conf.example deploy.conf && chmod 600 deploy.conf" },
          { kind: "prompt", text: "$EDITOR deploy.conf" },
          { kind: "prompt", text: "./deploy.sh --init" },
          { kind: "comment", text: "# 3. Review remote deploy/docker/.env, then deploy" },
          { kind: "prompt", text: "./deploy.sh" },
          { kind: "hint", text: "→ HTTP: remote 127.0.0.1:8088 via SSH tunnel; HTTPS: configured host :443" },
        ],
        copyLabel: "Copy",
        copiedLabel: "Copied",
        copyPayload:
          "git clone https://github.com/HerbiusYang/Vigilyx.git\ncd Vigilyx\ncp deploy.conf.example deploy.conf\nchmod 600 deploy.conf\n$EDITOR deploy.conf\n./deploy.sh --init\n# Review remote deploy/docker/.env before continuing\n./deploy.sh",
      },
      actions: [
        { text: "Read Quick Start", href: "/docs/quick-start", primary: true },
        { text: "See deployment modes", href: "/docs/deployment" },
        {
          text: "Star on GitHub",
          href: "https://github.com/HerbiusYang/Vigilyx",
        },
      ],
    },
  },
  zh: {
    hero: {
      badge: "开源 · Rust 核心 · 旁路 + Inline",
      stats: [
        { value: "Clustered D-S", label: "证据融合" },
        { value: "5 状态 HMM", label: "BEC 阶段推断" },
        { value: "Hawkes", label: "自激时序建模" },
      ],
      terminal: {
        title: "verdict.jsonl",
        lines: [
          { kind: "muted", text: "# 判定示意 · 旁路镜像模式" },
          { kind: "prompt", text: "# 控制台/API 输出示意" },
          { kind: "out", text: "[SMTP] mail-01 → alice@corp · 主题：\"发票 2026-Q1\"" },
          { kind: "ok", text: "verdict: safe    score 0.08  modules 0/15  dlp ok" },
          { kind: "out", text: "[SMTP] mx-2 → bob@corp · 主题：\"账户验证提醒\"" },
          { kind: "warn", text: "verdict: medium  score 0.52  modules 4/15  nlp phishing=0.71" },
          { kind: "bad", text: "verdict: high    score 0.81  ioc=sender_ip content=urgency yara=phish_01" },
          { kind: "muted", text: "# 处置：告警与审计 · 旁路不能隔离" },
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
    deployment: {
      kicker: "两种独立的部署形态",
      title: "按场景选一种来用，不是升级路径。",
      body:
        "旁路镜像和 MTA 代理是两种独立的部署形态，服务于两种不同的运营模型，而不是同一次部署的两个阶段。它们共用同一套检测栈，但安装、运维和评估都互不相关。能接管多少邮件路径，就选对应的那一种。",
      cards: [
        {
          label: "旁路镜像部署",
          title: "部署在邮件系统旁边做被动分析",
          body:
            "Vigilyx 从镜像口 / SPAN 口接收流量，重建可检查的 SMTP 及已配置的 HTTP/Webmail 内容。POP3/IMAP 当前只提供元数据和覆盖信号；加密或不完整载荷保留覆盖缺口，旁路只做事后告警与审计。",
          points: [
            "零侵入——不需要改 MX、不需要调整 SMTP 路由",
            "判定是事后参考：告警、审计、复盘、调参",
            "适合不能动邮件路径的环境，或者做取证与规则迭代",
          ],
          className: "mode-card--mirror",
        },
        {
          label: "MTA 代理部署",
          title: "作为 Inline SMTP 代理在投递前做决策",
          body:
            "Vigilyx 通过内嵌引擎检查 SMTP 中继邮件，按策略转发、隔离、拒收或返回临时失败。默认 inline 超时为 8 秒，可配置 fail-open；待中继邮件仍受出站 DLP 约束。",
          points: [
            "真正的拦截——邮件在 Vigilyx 决策之前不会到达用户",
            "支持 accept / quarantine / reject，并配 fail-open 作为安全阀",
            "适合可以改造邮件路径、且需要真正阻断的场景",
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
            "SMTP、MIME、附件、链接、头部与 Webmail 行为都会被拉平到统一的数据形态供检测引擎使用——无论这份流量来自旁路镜像抓包，还是来自 Inline MTA 代理。",
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
          value: "29",
          label: "默认 pipeline entries",
          body: "含 verdict 与条件集成的配置条目；SMTP 出站 DLP 是独立策略路径。",
          icon: "pipeline",
        },
        {
          value: "DLP",
          label: "敏感数据模式族",
          body: "覆盖敏感内容识别与可疑传输行为的数据安全检测路径。",
          icon: "shield",
        },
        {
          value: "2",
          label: "deployment modes",
          body: "两种独立形态——旁路镜像做被动可见性，MTA 代理做 Inline 拦截。每个环境选一种。",
          icon: "deploy",
        },
        {
          value: "Rust",
          label: "core runtime",
          body: "抓包、解析、检测、API 与 MTA 逻辑都维持在同一套高性能栈里。",
          icon: "rust",
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
          body: "本地规则可与可选 CPU ONNX 意图模型影子诊断并行；显式计分模式会替代本地语义路径。Python NLP/OCR 与外部大模型复核是单独的可选集成。",
        },
        {
          title: "核心系统不依赖 AI",
          body: "解析、链接检测、YARA、DLP、身份异常和 verdict fusion 不依赖任何单一模型。",
        },
        {
          title: "更适合生产运维",
          body: "只有当 AI 真正提升分析效率时才启用，而不是「不开 AI 就没法工作」。",
        },
      ],
    },
    highlights: {
      kicker: "真正不一样的地方",
      title: "四条可以直接查看源码的实现路径。",
      body:
        "证据融合、时序诊断、AitM 线索和 HTML 像素分析均可查看源码；实际证据取决于采集覆盖和运行配置。",
      cards: [
        {
          tag: "证据融合",
          title: "按因果来源去重的 clustered D-S 融合",
          body:
            "默认 ds_murphy 配置映射到 clustered_ds_v1：证据簇用于场景缩放和诊断，稳定因果键用于去重同一来源的重复视图，每个唯一来源只融合一次。Copula 修正仅属于显式选择的 legacy_ds_murphy 策略。",
          why: "保留证据来源，限制同一因果来源重复投票；证据簇摘要只用于诊断。",
          source: "crates/vigilyx-engine/src/pipeline/verdict/clustered_ds_v1.rs",
        },
        {
          tag: "时序层",
          title: "在单邮件判定之上的完整时序层",
          body:
            "CUSUM 累计漂移检测、双速 EWMA 基线漂移、带 mark 的 Hawkes 自激过程建模攻击期节奏、5 状态 HMM 推断 BEC / ATO 阶段（侦察 → 建信 → 执行 → 收割），还叠了一张有向通信图。多数邮件安全产品按「单封邮件」孤立判定——这套不是。",
          why: "提供跨邮件诊断供分析师复核；推断阶段不等于已证实攻击。",
          source: "crates/vigilyx-engine/src/temporal/",
        },
        {
          tag: "AitM 钓鱼",
          title: "AitM 反向代理钓鱼检测",
          body:
            "分析托管平台 URL、OAuth 回调不一致、MFA/验证码话术及混合字符品牌域名等 AitM 线索。仅凭托管平台或 CAPTCHA 不能确认钓鱼工具包。",
          why: "为反向代理钓鱼复核补充上下文，并与其他证据共同判断。",
          source: "crates/vigilyx-engine/src/modules/aitm_detect.rs",
        },
        {
          tag: "HTML 像素艺术",
          title: "HTML 像素艺术与表格二维码检测",
          body:
            "攻击者用 <table> 的 bgcolor 单元格「画」二维码、用浮动 <div> 配 background-color 拼出钓鱼文字——就是为了绕开 OCR 和沙箱图片扫描。Vigilyx 从 DOM 结构重建位图并用 rqrr 解码。正文里用 Unicode 方块字符拼出来的 ASCII-art 二维码用同一套流程解出来。",
          why: "以 DOM 图形证据补充图片扫描。",
          source: "crates/vigilyx-engine/src/modules/html_pixel_art.rs",
        },
      ],
    },
    anatomy: {
      kicker: "逐层剖析",
      title: "打开一封邮件，看每一层是怎么识破它的。",
      body:
        "以下虚构场景仅用于解释分析概念；字段、分数和历史均为示意，并非抓包输出或实测结果。邮件威胁 verdict 与 HTTP 数据安全事件使用独立路径，最终动作取决于模式和策略。",
      selectorLabel: "场景",
      captureLabel: "已捕获",
      verdictLabel: "分析结果示意",
      actionLabelPrefix: "处置",
      hoverHint: "悬停任意一行可查看为什么被标记。",
      layerNames: ["抓包层", "解析层", "检测层", "融合层", "时序层"],
      emails: [
        {
          id: "bec",
          name: "BEC 电汇诈骗",
          headline: "From: ceo@acme-corp.com  ·  Subject: [紧急] 电汇 — 供应商账户变更  ·  周二 14:03",
          lines: [
            {
              label: "L1 · 抓包",
              content: "SMTP 203.0.113.44 → mx.acme-corp.com",
              tag: "新发件 IP",
              why: "发件 IP 在通信图里零历史；这个 /24 段第一次出现在入站路径上。",
            },
            {
              label: "L2 · 头部",
              content: "SPF=softfail  DKIM=none  DMARC=fail  Reply-To: ceo.acme@proton.me",
              tag: "Reply-To 不匹配",
              why: "Reply-To 域名和 From 对不上。典型的伪冒：企业显示名 + 免费邮箱回信地址。",
            },
            {
              label: "L3 · 内容",
              content: "subject=\"[紧急] 电汇\"  urgency_financial_combo=0.78",
              tag: "紧迫性 + 金额",
              why: "content_scan 命中 urgency_financial_combo 规则——紧迫关键词 + 金额陈述 + 24 小时内截止。",
            },
            {
              label: "L4 · 身份",
              content: "display_name=\"CEO John Doe\"  first_comm_window=true",
              tag: "身份异常",
              why: "identity_anomaly：这个发件域从未和该收件人通信过。首次接触 + 电汇请求 = 典型 BEC。",
            },
            {
              label: "L5 · 时序",
              content: "HMM 阶段: EXECUTE  ·  CUSUM 漂移 +3.2σ",
              tag: "HMM EXECUTE",
              why: "5 状态 HMM 在过去 8 天完成 侦察 → 建信任 → EXECUTE 的状态转移，CUSUM 确认基线漂移。",
            },
          ],
          verdict: {
            level: "HIGH",
            score: "0.81",
            action: "MTA 按策略隔离；旁路告警与审计",
            className: "verdict-high",
          },
        },
        {
          id: "aitm",
          name: "AitM MFA 绕过",
          headline: "From: no-reply@m1crosoft-auth.workers.dev  ·  Subject: 异常登录 — 立即验证  ·  周一 09:41",
          lines: [
            {
              label: "L1 · 抓包",
              content: "HTTPS 104.21.48.11  ·  SNI=m1crosoft-auth.workers.dev",
              tag: "CLOUDFLARE DGA",
              why: "托管平台 URL 是上下文线索，不能据此推断域名年龄或确认工具包。",
            },
            {
              label: "L2 · 链接扫描",
              content: "href=\"…/oauth2/authorize?redirect_uri=https://evil-proxy.xyz/callback\"",
              tag: "OAUTH 不一致",
              why: "redirect_uri 不在任何 Microsoft 官方回调白名单内。这是 AitM 代理的特征，不是拼写错误。",
            },
            {
              label: "L3 · 品牌",
              content: "display_text=\"Microsоft\"（品牌名含西里尔字母 о）",
              tag: "同形异义",
              why: "Latin/Cyrillic 混合字符脚本。肉眼看一致、却让严格匹配的品牌保护失效——典型同形异义伪装。",
            },
            {
              label: "L4 · AitM 检测",
              content: "MFA/CAPTCHA context + URL observations",
              tag: "TYCOON2FA",
              why: "MFA/验证码及 URL 线索需要独立佐证，不能单独确认工具包身份。",
            },
            {
              label: "L5 · 融合",
              content: "clustered_ds_v1 · 同因果来源视图已去重",
              tag: "CLUSTERED D-S",
              why: "默认路径先按稳定因果键去重再融合；证据簇摘要不额外投票。",
            },
          ],
          verdict: {
            level: "CRITICAL",
            score: "0.94",
            action: "MTA 按策略拒收；旁路告警与审计",
            className: "verdict-critical",
          },
        },
        {
          id: "exfil",
          name: "Webmail 数据外泄",
          headline: "HTTP POST /webmail/compose.jsp · 敏感内容自发送示意",
          lines: [
            {
              label: "L1 · 抓包",
              content: "HTTP 镜像 · 已配置 Webmail 主机 · multipart/form-data",
              tag: "HTTP 捕获",
              why: "HTTP 捕获依赖已配置的 Webmail 目标和可检查流量。",
            },
            {
              label: "L2 · Webmail",
              content: "从 compose.jsp 的 action payload 中重组出发件 body",
              tag: "WEBMAIL 还原",
              why: "Coremail 字段抽取与有界 multipart/文件检查为 HTTP 数据安全提供输入。",
            },
            {
              label: "L3 · DLP",
              content: "PII 命中：11× 身份证号、4× 银行账号、2× 手机号",
              tag: "DLP PII",
              why: "DLP 引擎在 Unicode 归一化（剥离零宽字符）之后命中 17 个敏感 token。",
            },
            {
              label: "L4 · 收件人",
              content: "from=user@corp · to=user@corp · sensitive content",
              tag: "自发送",
              why: "自发送分析比较发件人与收件人，敏感数据命中需要结合业务复核。",
            },
            {
              label: "L5 · 覆盖",
              content: "有界扫描 · 显式记录检查不完整原因",
              tag: "DLP 覆盖",
              why: "DLP 检查受大小和时间预算限制，不完整检查不能视为安全。",
            },
          ],
          verdict: {
            level: "HIGH",
            score: "0.82",
            action: "记录 HTTP DLP 事件供复核；旁路不能阻断",
            className: "verdict-high",
          },
        },
      ],
    },
    cta: {
      title: "给工程驱动的安全团队。直接 clone 就行。",
      body:
        "配置远程构建主机并初始化，检查运行参数后部署旁路或 MTA。AGPL-3.0，无需联网授权；HTTPS 需另行配置 TLS 入口。",
      terminal: {
        title: "deploy.sh",
        commands: [
          { kind: "comment", text: "# 1. 拉取仓库" },
          { kind: "prompt", text: "git clone https://github.com/HerbiusYang/Vigilyx.git" },
          { kind: "prompt", text: "cd Vigilyx" },
          { kind: "comment", text: "# 2. 配置远程主机" },
          { kind: "prompt", text: "cp deploy.conf.example deploy.conf && chmod 600 deploy.conf" },
          { kind: "prompt", text: "$EDITOR deploy.conf" },
          { kind: "prompt", text: "./deploy.sh --init" },
          { kind: "comment", text: "# 3. 检查远程 deploy/docker/.env，再部署" },
          { kind: "prompt", text: "./deploy.sh" },
          { kind: "hint", text: "→ HTTP: SSH 隧道访问远程 127.0.0.1:8088；HTTPS: 已配置的主机 :443" },
        ],
        copyLabel: "复制",
        copiedLabel: "已复制",
        copyPayload:
          "git clone https://github.com/HerbiusYang/Vigilyx.git\ncd Vigilyx\ncp deploy.conf.example deploy.conf\nchmod 600 deploy.conf\n$EDITOR deploy.conf\n./deploy.sh --init\n# 继续前检查远程 deploy/docker/.env\n./deploy.sh",
      },
      actions: [
        { text: "查看快速开始", href: "/zh/docs/quick-start", primary: true },
        { text: "了解部署方式", href: "/zh/docs/deployment" },
        {
          text: "GitHub 上 Star",
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

// Lightweight terminal tokenizer — pre-computed once per locale change.
// Produces typed token segments for fine-grained CSS coloring without
// requiring a heavyweight syntax highlighter bundle.
type TermToken = { t: "str" | "num" | "key" | "op" | "txt" | "path"; v: string };

function tokenizeTerm(text: string): TermToken[] {
  // Regex matches (in order): "quoted strings" | numbers | KEY= pattern |
  // path-like identifier (module names) | verdict/key words | plain text.
  const re =
    /("(?:[^"\\]|\\.)*")|(\b\d+(?:\.\d+)?\b)|(\b(?:verdict|score|modules|dlp|nlp|ioc|content|yara|action|subject|stream)\b)|([A-Za-z_][A-Za-z0-9_-]+=[A-Za-z0-9_.\-]+)|([A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+)|([#$·→•\[\]])/g;
  const out: TermToken[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push({ t: "txt", v: text.slice(last, m.index) });
    if (m[1]) out.push({ t: "str", v: m[1] });
    else if (m[2]) out.push({ t: "num", v: m[2] });
    else if (m[3]) out.push({ t: "key", v: m[3] });
    else if (m[4]) out.push({ t: "path", v: m[4] });
    else if (m[5]) out.push({ t: "str", v: m[5] });
    else if (m[6]) out.push({ t: "op", v: m[6] });
    last = re.lastIndex;
  }
  if (last < text.length) out.push({ t: "txt", v: text.slice(last) });
  return out;
}

// Dynamic verdict stream — seed lines stay pinned at top, new verdict
// events append at the bottom every ~1.6s, oldest excess trimmed so the
// buffer stays between [MIN_LINES, MAX_TERM_LINES]. Runs only when the
// terminal is in the viewport; respects prefers-reduced-motion.
type TermLine = { kind: "muted" | "prompt" | "out" | "ok" | "warn" | "bad"; text: string };
type TermLineView = TermLine & { key: string; tokens: TermToken[] };

const MAX_TERM_LINES = 14;
const TERM_INTERVAL_MS = 1600;
const TERM_ANCHOR = 2; // never trim the first 2 lines (comment + prompt)

const tokenizedTerminal = shallowRef<TermLineView[]>([]);
let termTimer: number | null = null;
let termObserver: IntersectionObserver | null = null;
let termFeedCursor = 0;
let termLineKeySeq = 0;

const TERM_FEED_POOL: Record<"en" | "zh", TermLine[][]> = {
  en: [
    [
      { kind: "out", text: "[SMTP] edge-03 → carol@corp · subject: \"Re: purchase order\"" },
      { kind: "ok", text: "verdict: safe    score 0.11  modules 0/15  dlp ok" },
    ],
    [
      { kind: "out", text: "[IMAP] webmail → dave@corp · subject: \"wire transfer update\"" },
      { kind: "warn", text: "verdict: low     score 0.28  modules 2/15  intel sender_domain=new" },
    ],
    [
      { kind: "out", text: "[SMTP] mx-4 → finance@corp · subject: \"Microsoft 365 security alert\"" },
      { kind: "bad", text: "verdict: critical score 0.92 modules 7/15  aitm=evilproxy oauth_abuse=1" },
    ],
    [
      { kind: "out", text: "[HTTP] webmail upload · user=eve@corp · file=\"Q4_report.xlsx\"" },
      { kind: "warn", text: "verdict: medium  score 0.48  modules 3/15  dlp=id_card hits=2" },
    ],
    [
      { kind: "out", text: "[SMTP] mail-02 → ops@corp · subject: \"invoice reminder #7821\"" },
      { kind: "ok", text: "verdict: safe    score 0.09  modules 0/15  dlp ok" },
    ],
    [
      { kind: "out", text: "[SMTP] mx-1 → hr@corp · subject: \"urgent: payroll change\"" },
      { kind: "bad", text: "verdict: high    score 0.78  modules 5/15  nlp bec=0.83 spoof=display_name" },
    ],
    [
      { kind: "out", text: "[SMTP] edge-02 → team@corp · subject: \"shared document\"" },
      { kind: "warn", text: "verdict: medium  score 0.41  modules 3/15  url=redirect_chain yara=phish_kit" },
    ],
  ],
  zh: [
    [
      { kind: "out", text: "[SMTP] edge-03 → carol@corp · 主题：\"Re: 采购订单\"" },
      { kind: "ok", text: "verdict: safe    score 0.11  modules 0/15  dlp ok" },
    ],
    [
      { kind: "out", text: "[IMAP] webmail → dave@corp · 主题：\"电汇信息更新\"" },
      { kind: "warn", text: "verdict: low     score 0.28  modules 2/15  intel sender_domain=new" },
    ],
    [
      { kind: "out", text: "[SMTP] mx-4 → finance@corp · 主题：\"Microsoft 365 安全警报\"" },
      { kind: "bad", text: "verdict: critical score 0.92 modules 7/15  aitm=evilproxy oauth_abuse=1" },
    ],
    [
      { kind: "out", text: "[HTTP] webmail 上传 · user=eve@corp · file=\"Q4_report.xlsx\"" },
      { kind: "warn", text: "verdict: medium  score 0.48  modules 3/15  dlp=id_card hits=2" },
    ],
    [
      { kind: "out", text: "[SMTP] mail-02 → ops@corp · 主题：\"发票提醒 #7821\"" },
      { kind: "ok", text: "verdict: safe    score 0.09  modules 0/15  dlp ok" },
    ],
    [
      { kind: "out", text: "[SMTP] mx-1 → hr@corp · 主题：\"紧急：薪资变更\"" },
      { kind: "bad", text: "verdict: high    score 0.78  modules 5/15  nlp bec=0.83 spoof=display_name" },
    ],
    [
      { kind: "out", text: "[SMTP] edge-02 → team@corp · 主题：\"共享文档\"" },
      { kind: "warn", text: "verdict: medium  score 0.41  modules 3/15  url=redirect_chain yara=phish_kit" },
    ],
  ],
};

function hydrateTermLine(line: TermLine): TermLineView {
  return {
    ...line,
    key: `${termLineKeySeq++}-${line.kind}-${line.text}`,
    tokens: tokenizeTerm(line.text),
  };
}

function seedStream() {
  termLineKeySeq = 0;
  tokenizedTerminal.value = copy.value.hero.terminal.lines.map(hydrateTermLine);
  termFeedCursor = 0;
}

function pushNextFeed() {
  const pool = TERM_FEED_POOL[props.locale] ?? TERM_FEED_POOL.en;
  if (!pool.length) return;
  const group = pool[termFeedCursor % pool.length];
  termFeedCursor += 1;
  const next = tokenizedTerminal.value.slice();
  for (const line of group) next.push(hydrateTermLine(line));
  while (next.length > MAX_TERM_LINES) next.splice(TERM_ANCHOR, 1);
  tokenizedTerminal.value = next;
}

seedStream();

watch(
  () => props.locale,
  () => {
    seedStream();
  },
);

// One-shot scroll-in reveal via IntersectionObserver.
// Disabled: created a jarring "block-by-block" feel on slower machines.
// Entrance animations on hero elements (term-line, pipeline-stage) are enough.
const rootRef = ref<HTMLElement | null>(null);

// -----------------------------------------------------------------------------
// Anatomy section: email dissection with scroll-driven reveal
// -----------------------------------------------------------------------------
const anatomyEmailIdx = ref(0);
const anatomyRevealedLines = ref<Set<number>>(new Set());
const anatomyVerdictRevealed = ref(false);
const anatomySectionArmed = ref(false);

const anatomyActiveEmail = computed(
  () => copy.value.anatomy.emails[anatomyEmailIdx.value],
);

function selectAnatomyEmail(idx: number) {
  if (idx === anatomyEmailIdx.value) return;
  anatomyEmailIdx.value = idx;
  // Reset reveal state so the new email plays its reveal sequence.
  anatomyRevealedLines.value = new Set();
  anatomyVerdictRevealed.value = false;
  // After Vue flushes new DOM, re-observe the new line/verdict elements.
  if (typeof window !== "undefined") {
    void nextTick(rewireAnatomyObservers);
  }
}

const anatomyRailLit = computed(() => {
  const n = anatomyRevealedLines.value.size;
  return [0, 1, 2, 3, 4].map((i) => i < n);
});

const anatomyRailProgress = computed(() => {
  const n = anatomyRevealedLines.value.size;
  return Math.min(1, n / 5);
});

let anatomyLineObserver: IntersectionObserver | null = null;
let anatomyVerdictObserver: IntersectionObserver | null = null;
let anatomySectionObserver: IntersectionObserver | null = null;

function rewireAnatomyObservers() {
  if (typeof window === "undefined") return;
  if (!("IntersectionObserver" in window)) return;

  anatomyLineObserver?.disconnect();
  anatomyVerdictObserver?.disconnect();
  const scope = rootRef.value ?? document;

  anatomyLineObserver = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        const idxAttr = (entry.target as HTMLElement).dataset.lineIdx;
        if (idxAttr == null) continue;
        const idx = Number(idxAttr);
        if (Number.isNaN(idx)) continue;
        const next = new Set(anatomyRevealedLines.value);
        next.add(idx);
        anatomyRevealedLines.value = next;
        anatomyLineObserver?.unobserve(entry.target);
      }
    },
    { threshold: 0.55, rootMargin: "0px 0px -10% 0px" },
  );

  anatomyVerdictObserver = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          anatomyVerdictRevealed.value = true;
          anatomyVerdictObserver?.disconnect();
          anatomyVerdictObserver = null;
        }
      }
    },
    { threshold: 0.4 },
  );

  scope
    .querySelectorAll<HTMLElement>(".anatomy-line")
    .forEach((el) => anatomyLineObserver!.observe(el));
  const verdictEl = scope.querySelector<HTMLElement>(".anatomy-paper__verdict");
  if (verdictEl) anatomyVerdictObserver?.observe(verdictEl);
}

// -----------------------------------------------------------------------------
// CTA terminal: copy-to-clipboard with ephemeral "copied" state.
// -----------------------------------------------------------------------------
const ctaCopied = ref(false);
let ctaCopyTimer: number | null = null;

async function copyCtaCommands() {
  const payload = copy.value.cta.terminal.copyPayload;
  try {
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(payload);
    } else if (typeof document !== "undefined") {
      // Fallback: hidden textarea + execCommand for older browsers / non-secure contexts.
      const ta = document.createElement("textarea");
      ta.value = payload;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
    ctaCopied.value = true;
    if (ctaCopyTimer !== null) clearTimeout(ctaCopyTimer);
    ctaCopyTimer = window.setTimeout(() => {
      ctaCopied.value = false;
      ctaCopyTimer = null;
    }, 1600);
  } catch {
    // Silently ignore clipboard failures — the user can still select the text manually.
  }
}

onMounted(() => {
  if (typeof window === "undefined") return;
  const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

  // Anatomy: for reduced-motion users, skip the scroll-reveal choreography
  // and show everything immediately so the content is still readable.
  if (reduce) {
    anatomySectionArmed.value = true;
    anatomyRevealedLines.value = new Set([0, 1, 2, 3, 4]);
    anatomyVerdictRevealed.value = true;
  } else if ("IntersectionObserver" in window) {
    // Arm the section when it enters the viewport — CSS uses .is-armed
    // as the gate for the reveal choreography.
    const scope = rootRef.value ?? document;
    const sectionEl = scope.querySelector<HTMLElement>(".home-anatomy-section");
    if (sectionEl) {
      anatomySectionObserver = new IntersectionObserver(
        (entries) => {
          for (const entry of entries) {
            if (entry.isIntersecting) {
              anatomySectionArmed.value = true;
              anatomySectionObserver?.disconnect();
              anatomySectionObserver = null;
            }
          }
        },
        { threshold: 0.1 },
      );
      anatomySectionObserver.observe(sectionEl);
    }
    // Per-line + verdict observers.
    rewireAnatomyObservers();
  } else {
    // Fallback for ancient browsers: just show everything.
    anatomySectionArmed.value = true;
    anatomyRevealedLines.value = new Set([0, 1, 2, 3, 4]);
    anatomyVerdictRevealed.value = true;
  }

  if (reduce) return;

  const termEl = (rootRef.value ?? document).querySelector<HTMLElement>(".hero-terminal");
  if (!termEl || !("IntersectionObserver" in window)) return;

  termObserver = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          if (termTimer === null) {
            termTimer = window.setInterval(pushNextFeed, TERM_INTERVAL_MS);
          }
        } else if (termTimer !== null) {
          clearInterval(termTimer);
          termTimer = null;
        }
      }
    },
    { threshold: 0.15 },
  );
  termObserver.observe(termEl);
});

onBeforeUnmount(() => {
  if (termTimer !== null) {
    clearInterval(termTimer);
    termTimer = null;
  }
  termObserver?.disconnect();
  termObserver = null;
  anatomyLineObserver?.disconnect();
  anatomyLineObserver = null;
  anatomyVerdictObserver?.disconnect();
  anatomyVerdictObserver = null;
  anatomySectionObserver?.disconnect();
  anatomySectionObserver = null;
  if (ctaCopyTimer !== null) {
    clearTimeout(ctaCopyTimer);
    ctaCopyTimer = null;
  }
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
              v-for="line in tokenizedTerminal"
              :key="line.key"
              :class="['term-line', `term-line--${line.kind}`]"
            ><template v-if="line.kind === 'prompt'"><span class="term-caret">$</span> </template><span
              v-for="(tok, ti) in line.tokens"
              :key="ti"
              :class="`tt tt--${tok.t}`"
            >{{ tok.v }}</span></span></code></pre>
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

    <!-- ANATOMY: live dissection of one captured email -->
    <section
      class="home-section home-anatomy-section"
      :class="{ 'is-armed': anatomySectionArmed }"
      :style="{ '--rail-progress': anatomyRailProgress }"
    >
      <div class="home-section-heading">
        <p class="home-kicker">{{ copy.anatomy.kicker }}</p>
        <h2>{{ copy.anatomy.title }}</h2>
        <p>{{ copy.anatomy.body }}</p>
      </div>

      <!-- Scenario selector tabs -->
      <div class="anatomy-selector" role="tablist" :aria-label="copy.anatomy.selectorLabel">
        <button
          v-for="(email, idx) in copy.anatomy.emails"
          :key="email.id"
          type="button"
          role="tab"
          :aria-selected="idx === anatomyEmailIdx"
          :class="['anatomy-selector__item', { 'is-active': idx === anatomyEmailIdx }]"
          @click="selectAnatomyEmail(idx)"
        >
          {{ email.name }}
        </button>
      </div>

      <!-- Email paper stage -->
      <div class="anatomy-stage">
        <article class="anatomy-paper" :key="anatomyActiveEmail.id">
          <header class="anatomy-paper__head">
            <span>{{ copy.anatomy.captureLabel }}</span>
            · {{ anatomyActiveEmail.headline }}
          </header>

          <div class="anatomy-paper__body">
            <div
              v-for="(line, idx) in anatomyActiveEmail.lines"
              :key="`${anatomyActiveEmail.id}-${idx}`"
              :class="['anatomy-line', { 'is-revealed': anatomyRevealedLines.has(idx) }]"
              :data-line-idx="idx"
            >
              <span class="anatomy-line__label">{{ line.label }}</span>
              <span class="anatomy-line__content">{{ line.content }}</span>
              <span class="anatomy-line__tag">{{ line.tag }}</span>
              <span class="anatomy-line__why">{{ line.why }}</span>
            </div>
          </div>

          <footer
            :class="[
              'anatomy-paper__verdict',
              anatomyActiveEmail.verdict.className,
              { 'is-revealed': anatomyVerdictRevealed },
            ]"
          >
            <span class="anatomy-paper__verdict-label">{{ copy.anatomy.verdictLabel }}</span>
            <span class="anatomy-paper__verdict-level">{{ anatomyActiveEmail.verdict.level }}</span>
            <span class="anatomy-paper__verdict-score">{{ anatomyActiveEmail.verdict.score }}</span>
            <span class="anatomy-paper__verdict-action">
              {{ copy.anatomy.actionLabelPrefix }} · {{ anatomyActiveEmail.verdict.action }}
            </span>
          </footer>
        </article>
      </div>

      <!-- L1-L5 rail -->
      <div class="anatomy-rail" aria-hidden="true">
        <div class="anatomy-rail__line"></div>
        <div
          v-for="(name, idx) in copy.anatomy.layerNames"
          :key="name"
          :class="['anatomy-rail__node', { 'is-lit': anatomyRailLit[idx] }]"
        >
          <span class="anatomy-rail__dot"></span>
          <span class="anatomy-rail__idx">L{{ idx + 1 }}</span>
          <span class="anatomy-rail__name">{{ name }}</span>
        </div>
      </div>

      <p class="anatomy-hint">{{ copy.anatomy.hoverHint }}</p>
    </section>

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
        <p class="home-kicker">{{ copy.highlights.kicker }}</p>
        <h2>{{ copy.highlights.title }}</h2>
        <p>{{ copy.highlights.body }}</p>
      </div>

      <div class="home-highlight-grid">
        <article
          v-for="(card, idx) in copy.highlights.cards"
          :key="card.title"
          class="home-surface highlight-card"
          :style="{ animationDelay: `${idx * 60}ms` }"
        >
          <span class="highlight-card__index">{{ String(idx + 1).padStart(2, "0") }}</span>
          <span class="highlight-card__tag">{{ card.tag }}</span>
          <h3>{{ card.title }}</h3>
          <code class="highlight-card__source">{{ card.source }}</code>
          <details class="highlight-card__details">
            <summary>
              <span class="highlight-card__summary-label">{{ props.locale === 'zh' ? '展开详情' : 'Read more' }}</span>
              <svg
                class="highlight-card__summary-chevron"
                viewBox="0 0 16 16"
                width="12"
                height="12"
                aria-hidden="true"
              >
                <path
                  d="M3 6l5 5 5-5"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="1.8"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
            </summary>
            <p class="highlight-card__body">{{ card.body }}</p>
            <p class="highlight-card__why">
              <strong>{{ props.locale === 'zh' ? '为什么关键：' : 'Why it matters:' }}</strong>
              {{ card.why }}
            </p>
          </details>
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
          <span class="metric-card__icon" aria-hidden="true">
            <!-- pipeline -->
            <svg v-if="card.icon === 'pipeline'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="5" cy="6" r="2" />
              <circle cx="5" cy="18" r="2" />
              <circle cx="19" cy="12" r="2" />
              <path d="M7 6h4a4 4 0 0 1 4 4v0a4 4 0 0 1-4 4H7" />
              <path d="M7 18h4a4 4 0 0 0 4-4" opacity=".55" />
            </svg>
            <!-- shield -->
            <svg v-else-if="card.icon === 'shield'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 3l8 3v6c0 4.5-3.2 8.5-8 10-4.8-1.5-8-5.5-8-10V6l8-3z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
            <!-- deploy -->
            <svg v-else-if="card.icon === 'deploy'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
              <rect x="3" y="4" width="18" height="6" rx="1.5" />
              <rect x="3" y="14" width="18" height="6" rx="1.5" />
              <path d="M7 7h.01M7 17h.01" />
            </svg>
            <!-- rust -->
            <svg v-else-if="card.icon === 'rust'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="8" />
              <path d="M8 8h5a2.5 2.5 0 0 1 0 5H8z" />
              <path d="M11 13l3 5" />
              <path d="M8 13v5" />
            </svg>
          </span>
          <strong>{{ card.value }}</strong>
          <span class="metric-card__label">{{ card.label }}</span>
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
      <!-- Aurora ambient layer: stardust particles + subtle gradient glow -->
      <div class="home-cta__aurora" aria-hidden="true">
        <span class="home-cta__aurora-blob home-cta__aurora-blob--a"></span>
        <span class="home-cta__aurora-blob home-cta__aurora-blob--b"></span>
        <span class="home-cta__aurora-grid"></span>
        <span class="home-cta__stardust">
          <i v-for="n in 18" :key="n" :style="`--i:${n}`"></i>
        </span>
      </div>

      <div class="home-cta__stage">
        <!-- LEFT: headline + body + 3 arrow links stacked vertically -->
        <div class="home-cta__left">
          <h2 class="home-cta__headline">{{ copy.cta.title }}</h2>
          <p class="home-cta__body">{{ copy.cta.body }}</p>

          <ul class="home-cta__links" role="list">
            <li
              v-for="action in copy.cta.actions"
              :key="action.text"
            >
              <a
                :class="['home-cta-arrow', action.primary ? 'home-cta-arrow--primary' : '']"
                :href="action.href"
                :target="isExternalLink(action.href) ? '_blank' : undefined"
                :rel="isExternalLink(action.href) ? 'noreferrer' : undefined"
              >
                <span class="home-cta-arrow__text">{{ action.text }}</span>
                <span class="home-cta-arrow__line" aria-hidden="true"></span>
                <svg
                  class="home-cta-arrow__icon"
                  viewBox="0 0 16 16"
                  width="14"
                  height="14"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="1.8"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  aria-hidden="true"
                >
                  <path d="M3 8h10M9 4l4 4-4 4" />
                </svg>
              </a>
            </li>
          </ul>
        </div>

        <!-- RIGHT: Aurora glass terminal (same family as SharePanel) -->
        <div class="cta-terminal" role="group" :aria-label="copy.cta.terminal.title">
          <div class="cta-terminal__bar">
            <span class="cta-terminal__dots">
              <i></i><i></i><i></i>
            </span>
            <span class="cta-terminal__title">{{ copy.cta.terminal.title }}</span>
            <button
              type="button"
              :class="['cta-terminal__copy', { 'is-copied': ctaCopied }]"
              @click="copyCtaCommands"
              :aria-label="ctaCopied ? copy.cta.terminal.copiedLabel : copy.cta.terminal.copyLabel"
            >
              <svg
                v-if="!ctaCopied"
                viewBox="0 0 16 16"
                width="13"
                height="13"
                fill="none"
                stroke="currentColor"
                stroke-width="1.6"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
              >
                <rect x="4.5" y="4.5" width="8" height="9" rx="1.2" />
                <path d="M3 10.5V3.5A1 1 0 0 1 4 2.5h7" />
              </svg>
              <svg
                v-else
                viewBox="0 0 16 16"
                width="13"
                height="13"
                fill="none"
                stroke="currentColor"
                stroke-width="1.8"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
              >
                <path d="M3.5 8.5l3 3 6-7" />
              </svg>
              <span>{{ ctaCopied ? copy.cta.terminal.copiedLabel : copy.cta.terminal.copyLabel }}</span>
            </button>
          </div>
          <pre class="cta-terminal__body"><code><span
            v-for="(cmd, i) in copy.cta.terminal.commands"
            :key="i"
            :class="['cta-term-line', `cta-term-line--${cmd.kind}`]"
          ><template v-if="cmd.kind === 'prompt'"><span class="cta-term-caret">$</span> </template>{{ cmd.text }}</span></code></pre>
        </div>
      </div>
    </section>

    <SharePanel mode="home" />
  </div>
</template>
