<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{ locale?: "en" | "zh" }>();

const copy = computed(() =>
  props.locale === "en"
    ? {
        mirror: "Mirror",
        mirrorNote: "See it after delivery",
        inline: "Inline",
        inlineNote: "Decide before delivery",
        mirrorSteps: [
          ["1", "Capture", "sniffer reads the wire"],
          ["2", "Rebuild", "SMTP session is reconstructed"],
          ["3", "Queue", "Redis Streams"],
        ],
        inlineSteps: [
          ["1", "Receive", "SMTP proxy accepts the mail"],
          ["2", "Parse", "same parser, no queue"],
        ],
        engine: "One detection engine",
        groups: ["Headers", "Identity", "Body", "HTML", "Semantics", "Links", "Landing page", "QR", "Files", "MIME", "YARA", "AiTM", "RMM", "Callback", "Prompt injection", "Domain"],
        fuse: "One explainable verdict",
        after: "Then",
        sinks: [
          ["Store", "PostgreSQL"],
          ["Push", "API / WebSocket"],
          ["Review", "Console"],
          ["Notify", "Alerts"],
        ],
        outs: [
          ["relay", "Relay", "only this leaves"],
          ["hold", "Quarantine", "from Medium"],
          ["stop", "Reject", "not forwarded"],
          ["wait", "Temp fail", "engine unavailable"],
        ],
        dlpTitle: "Outbound data security",
        dlpBody: "Not one of the 29 checks. It runs only on mail that would be relayed, and looks for sensitive data. On by default; a hit is quarantined.",
      }
    : {
        mirror: "旁路",
        mirrorNote: "投递之后看",
        inline: "Inline",
        inlineNote: "投递之前拦",
        mirrorSteps: [
          ["1", "抓包", "sniffer 从网卡取流量"],
          ["2", "重组", "拼回 SMTP 会话"],
          ["3", "队列", "Redis Streams"],
        ],
        inlineSteps: [
          ["1", "收信", "SMTP 代理自己接入"],
          ["2", "解析", "同一套 parser，不排队"],
        ],
        engine: "同一套检测引擎",
        groups: ["头部", "身份", "正文", "HTML", "语义", "链接", "落地页", "二维码", "附件", "MIME", "YARA", "登录中间人", "远控", "回拨", "提示词注入", "域名"],
        fuse: "一个说得清的判定",
        after: "然后",
        sinks: [
          ["存储", "PostgreSQL"],
          ["推送", "API / WebSocket"],
          ["复核", "控制台"],
          ["通知", "告警"],
        ],
        outs: [
          ["relay", "转发", "只有这一路离开"],
          ["hold", "隔离", "中危起"],
          ["stop", "拒收", "不转给下游"],
          ["wait", "临时失败", "引擎没给出判定"],
        ],
        dlpTitle: "外发数据安全",
        dlpBody: "不在 29 项里。只检查本来要转发的外发邮件，看有没有敏感数据。默认开启，命中后隔离。",
      },
);
</script>

<template>
  <figure class="arch">
    <div class="arch__board">
      <div class="arch__lanes">
        <section class="lane lane--mirror">
          <header>
            <span>{{ copy.mirror }}</span>
            <small>{{ copy.mirrorNote }}</small>
          </header>
          <ol>
            <li v-for="step in copy.mirrorSteps" :key="step[1]">
              <em>{{ step[0] }}</em>
              <div>
                <strong>{{ step[1] }}</strong>
                <span>{{ step[2] }}</span>
              </div>
            </li>
          </ol>
        </section>
        <section class="lane lane--inline">
          <header>
            <span>{{ copy.inline }}</span>
            <small>{{ copy.inlineNote }}</small>
          </header>
          <ol>
            <li v-for="step in copy.inlineSteps" :key="step[1]">
              <em>{{ step[0] }}</em>
              <div>
                <strong>{{ step[1] }}</strong>
                <span>{{ step[2] }}</span>
              </div>
            </li>
          </ol>
        </section>
      </div>

      <div class="arch__merge" aria-hidden="true"><span /></div>

      <section class="engine">
        <header>{{ copy.engine }}</header>
        <div class="engine__grid">
          <span v-for="name in copy.groups" :key="name">{{ name }}</span>
        </div>
        <div class="engine__fuse">{{ copy.fuse }}</div>
      </section>

      <p class="arch__then">{{ copy.after }}</p>

      <div class="sinks">
        <div v-for="item in copy.sinks" :key="item[0]">
          <strong>{{ item[0] }}</strong>
          <span>{{ item[1] }}</span>
        </div>
      </div>

      <div class="outs">
        <div v-for="item in copy.outs" :key="item[1]" :class="`out out--${item[0]}`">
          <strong>{{ item[1] }}</strong>
          <span>{{ item[2] }}</span>
        </div>
      </div>
      <aside class="dlp">
        <strong>{{ copy.dlpTitle }}</strong>
        <span>{{ copy.dlpBody }}</span>
      </aside>
    </div>
  </figure>
</template>

<style scoped>
.arch {
  margin: 1.4rem 0 1.8rem;
}
.arch__board {
  padding: 1.15rem;
  border: 1px solid var(--vig-border);
  border-radius: 20px;
  background:
    radial-gradient(70% 40% at 50% 0%, color-mix(in srgb, var(--vig-accent) 16%, transparent), transparent 70%),
    var(--vig-bg-1);
  box-shadow: 0 18px 40px -28px rgba(15, 23, 42, 0.45);
}
.arch__lanes {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.8rem;
}
.lane {
  padding: 0.9rem;
  border-radius: 16px;
  background: var(--vig-bg-0);
  border: 1px solid var(--vig-border);
}
.lane header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 0.6rem;
  margin-bottom: 0.7rem;
}
.lane header span {
  font-weight: 700;
  letter-spacing: 0.04em;
}
.lane header small {
  color: var(--vig-text-muted);
  font-size: 0.78rem;
}
.lane--mirror header span { color: #0f766e; }
.lane--inline header span { color: #0369a1; }
html.dark .lane--mirror header span { color: #5eead4; }
html.dark .lane--inline header span { color: #7dd3fc; }
.lane ol {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.45rem;
}
.lane li {
  display: flex;
  gap: 0.65rem;
  align-items: flex-start;
  padding: 0.55rem 0.65rem;
  border-radius: 12px;
  background: var(--vig-bg-2);
}
.lane em {
  flex: 0 0 auto;
  width: 1.35rem;
  height: 1.35rem;
  border-radius: 999px;
  display: grid;
  place-items: center;
  font-style: normal;
  font-size: 0.75rem;
  font-weight: 700;
  color: white;
  background: #0f766e;
}
.lane--inline em { background: #0369a1; }
.lane strong,
.sinks strong,
.out strong {
  display: block;
  font-size: 0.92rem;
}
.lane span,
.sinks span,
.out span,
.engine__grid span {
  color: var(--vig-text-soft);
  font-size: 0.8rem;
}
.arch__merge {
  display: flex;
  justify-content: center;
  height: 1.35rem;
}
.arch__merge span {
  width: 42%;
  border: 1.5px solid color-mix(in srgb, var(--vig-accent) 55%, transparent);
  border-top: 0;
  border-radius: 0 0 14px 14px;
}
.engine {
  margin-top: 0.15rem;
  padding: 0.95rem;
  border-radius: 16px;
  border: 1px solid color-mix(in srgb, var(--vig-accent) 35%, var(--vig-border));
  background: color-mix(in srgb, var(--vig-accent) 8%, var(--vig-bg-0));
}
.engine header {
  margin: 0 0 0.65rem;
  font-weight: 700;
}
.engine__grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 0.4rem;
}
.engine__grid span {
  padding: 0.45rem 0.5rem;
  text-align: center;
  border-radius: 10px;
  background: var(--vig-bg-1);
  border: 1px solid var(--vig-border);
}
.engine__fuse {
  margin-top: 0.65rem;
  padding: 0.6rem 0.75rem;
  text-align: center;
  font-weight: 700;
  border-radius: 12px;
  color: #042f2e;
  background: linear-gradient(180deg, #5eead4, #14b8a6);
}
html.dark .engine__fuse { color: #042f2e; }
.arch__then {
  margin: 0.85rem 0 0.45rem;
  text-align: center;
  font-size: 0.75rem;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--vig-text-muted);
}
.sinks,
.outs {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 0.45rem;
}
.sinks div,
.out {
  padding: 0.6rem 0.65rem;
  border-radius: 12px;
  background: var(--vig-bg-0);
  border: 1px solid var(--vig-border);
}
.outs { margin-top: 0.45rem; }
.out--relay { border-color: #14b8a6; }
.out--hold { border-color: #d97706; }
.out--stop { border-color: #e11d48; }
.out--wait { border-color: #64748b; }
.dlp {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
  margin-top: 0.7rem;
  padding: 0.75rem 0.85rem;
  border-radius: 12px;
  border: 1px dashed color-mix(in srgb, var(--vig-accent) 55%, var(--vig-border));
  background: color-mix(in srgb, var(--vig-accent) 7%, var(--vig-bg-0));
}
.dlp strong { font-size: 0.92rem; }
.dlp span { color: var(--vig-text-soft); font-size: 0.82rem; }
@media (max-width: 760px) {
  .arch__lanes,
  .engine__grid,
  .sinks,
  .outs {
    grid-template-columns: 1fr 1fr;
  }
}
</style>
