<template>
  <div class="toad" :class="{ 'toad--running': stage > 0 }">
    <header class="toad__head">
      <div class="toad__title">
        <span class="toad__badge">
          <span class="toad__badge-dot"></span>
          {{ t.live }}
        </span>
        <h4>{{ t.title }}</h4>
      </div>
      <div class="toad__ctrl">
        <button class="toad__btn toad__btn--primary" @click="toggle">
          {{ stage > 0 ? t.reset : t.play }}
        </button>
        <button class="toad__btn" @click="step" :disabled="stage >= scenes.length">
          {{ t.next }}
        </button>
      </div>
    </header>

    <!-- Three actor lanes -->
    <div class="toad__stage">
      <div
        v-for="(actor, i) in actors"
        :key="i"
        class="toad__lane"
        :data-role="actor.role"
        :class="{ 'toad__lane--active': activeRole === actor.role }"
      >
        <div class="toad__avatar" :data-role="actor.role">
          <span v-html="actor.icon"></span>
        </div>
        <div class="toad__lane-label">{{ labelOf(actor) }}</div>
      </div>

      <!-- Animated arrows / messages between lanes -->
      <transition-group name="toad-msg" tag="div" class="toad__messages">
        <div
          v-for="m in visibleMessages"
          :key="m.id"
          class="toad__message"
          :data-from="m.from"
          :data-to="m.to"
          :data-kind="m.kind"
        >
          <div class="toad__message-arrow">
            <span class="toad__message-line"></span>
            <span class="toad__message-arrowhead"></span>
          </div>
          <div class="toad__message-bubble" :data-kind="m.kind">
            <span class="toad__message-icon">{{ kindIcon(m.kind) }}</span>
            <span class="toad__message-text">{{ textOf(m) }}</span>
          </div>
        </div>
      </transition-group>
    </div>

    <!-- Phase progress -->
    <div class="toad__phases">
      <div
        v-for="(s, i) in scenes"
        :key="i"
        class="toad__phase"
        :class="{
          'toad__phase--done': stage > i,
          'toad__phase--active': stage === i + 1,
        }"
      >
        <span class="toad__phase-num">{{ i + 1 }}</span>
        <span class="toad__phase-text">{{ phaseLabel(s) }}</span>
      </div>
    </div>

    <!-- Narration -->
    <footer class="toad__footer">
      <transition name="toad-fade">
        <div v-if="currentScene" :key="stage" class="toad__narration">
          <span class="toad__nar-tag" :data-role="currentScene.actor">
            {{ roleLabel(currentScene.actor) }}
          </span>
          <span class="toad__nar-text">{{ narrationOf(currentScene) }}</span>
        </div>
      </transition>
    </footer>
  </div>
</template>

<script setup lang="ts">
/**
 * TOADTimeline — Telephone-Oriented Attack Delivery scenario.
 *
 * Three-lane stage:  Victim ── Attacker call center ── Microsoft / Bank
 * Animated message bubbles travel between lanes as the attack unfolds:
 *
 *   1. Email arrives at victim       (attacker → victim, kind=email)
 *   2. Victim dials toll-free number (victim → attacker, kind=phone)
 *   3. "Agent" socially engineers    (attacker ↔ victim, kind=voice)
 *   4. Agent has victim install RMM  (victim runs AnyDesk/ScreenConnect)
 *   5. Agent triggers MFA push       (attacker → real service, kind=oauth)
 *   6. Victim approves MFA           (victim → service, kind=approve)
 *   7. Vigilyx blocks at email stage (system, kind=verdict)
 */
import { computed, ref } from "vue";
import { useData } from "vitepress";

type Role = "attacker" | "victim" | "service" | "vigilyx";
type Kind = "email" | "phone" | "voice" | "rmm" | "oauth" | "approve" | "verdict";

interface Scene {
  id: string;
  actor: Role;
  /** narration shown at the bottom */
  narration: { zh: string; en: string };
  /** progress-bar label */
  label: { zh: string; en: string };
  /** message bubble emitted at this stage (optional) */
  message?: {
    from: Role;
    to: Role;
    kind: Kind;
    text: { zh: string; en: string };
  };
}

const { lang } = useData();
const isZh = computed(() => (lang.value || "").toLowerCase().startsWith("zh"));

const stage = ref(0);

const t = computed(() =>
  isZh.value
    ? {
        live: "实时演示",
        title: "TOAD 电话钓鱼：邮件 → 客服话术 → 远程接管",
        play: "▶ 播放",
        reset: "↻ 重置",
        next: "→ 下一步",
      }
    : {
        live: "Live demo",
        title: "TOAD callback phishing — email → fake support → remote takeover",
        play: "▶ Play",
        reset: "↻ Reset",
        next: "→ Next",
      }
);

const actors: Array<{
  role: Role;
  icon: string;
  label: { zh: string; en: string };
}> = [
  {
    role: "victim",
    icon: "👤",
    label: { zh: "受害者", en: "Victim" },
  },
  {
    role: "attacker",
    icon: "📞",
    label: { zh: "假客服热线", en: "Fake call centre" },
  },
  {
    role: "service",
    icon: "🏦",
    label: { zh: "真实银行 / Microsoft", en: "Real bank / Microsoft" },
  },
];

const scenes: Scene[] = [
  {
    id: "email-in",
    actor: "attacker",
    label: { zh: "投递", en: "Delivery" },
    narration: {
      zh: "Geek Squad / Norton 续费通知邮件投递到收件箱。无附件、无可疑链接，DMARC 通过 —— 网关把它当正常营销邮件放行。",
      en: "A Geek Squad / Norton renewal notice lands in the inbox. No attachment, no suspicious link, DMARC passes — the gateway treats it as ordinary marketing.",
    },
    message: {
      from: "attacker",
      to: "victim",
      kind: "email",
      text: { zh: "您的订阅将于 24 小时内自动续费 $499.99", en: "Your subscription will auto-renew for $499.99 within 24h" },
    },
  },
  {
    id: "dial",
    actor: "victim",
    label: { zh: "受害者拨打", en: "Victim dials" },
    narration: {
      zh: "受害者看到「金额错误立即拨打 1-855-XXX-XXXX 取消」字样，慌张地拨打了电话 —— 这是 TOAD 的核心：让用户主动联系攻击者。",
      en: "The victim sees “call 1-855-XXX-XXXX to cancel” and dials the number. This is the TOAD essence: lure the user to initiate the call.",
    },
    message: {
      from: "victim",
      to: "attacker",
      kind: "phone",
      text: { zh: "拨打 1-855-XXX-XXXX", en: "Dial 1-855-XXX-XXXX" },
    },
  },
  {
    id: "social-engineer",
    actor: "attacker",
    label: { zh: "话术诱导", en: "Social engineering" },
    narration: {
      zh: "「客服」要求受害者在浏览器输入 microsoft.com/devicelogin 并念出 9 位数字 —— 这其实是 OAuth 设备码授权，受害者在替攻击者登录自己的账户。",
      en: "The “agent” asks the victim to open microsoft.com/devicelogin and read the 9-digit code. That is the OAuth device-code flow — the victim is authorizing the attacker to access their own account.",
    },
    message: {
      from: "attacker",
      to: "victim",
      kind: "voice",
      text: { zh: "请念出您看到的 9 位授权码", en: "Please read the 9-digit code you see" },
    },
  },
  {
    id: "rmm-install",
    actor: "victim",
    label: { zh: "RMM 安装", en: "RMM install" },
    narration: {
      zh: "「为帮您退款」客服指导受害者安装 ScreenConnect / AnyDesk —— 攻击者获得屏幕共享和键鼠控制权，可以查看银行账户、发起转账、清空收件箱。",
      en: "“To process the refund”, the agent walks the victim through installing ScreenConnect / AnyDesk — granting screen + input control. The attacker can now view the bank account, initiate transfers, and wipe the inbox.",
    },
    message: {
      from: "victim",
      to: "attacker",
      kind: "rmm",
      text: { zh: "安装 ScreenConnect.ClientSetup.exe", en: "Install ScreenConnect.ClientSetup.exe" },
    },
  },
  {
    id: "mfa-push",
    actor: "attacker",
    label: { zh: "触发 MFA", en: "Trigger MFA" },
    narration: {
      zh: "攻击者在自己的设备上用偷来的设备码请求 token，触发受害者手机上的 MFA 推送通知。受害者以为是客服在「验证身份」，按下了「批准」。",
      en: "The attacker uses the stolen device code to request a token, which triggers an MFA push on the victim's phone. The victim, believing it is the agent “verifying identity”, taps Approve.",
    },
    message: {
      from: "attacker",
      to: "service",
      kind: "oauth",
      text: { zh: "POST /token (device_code=…)", en: "POST /token (device_code=…)" },
    },
  },
  {
    id: "approve",
    actor: "victim",
    label: { zh: "批准 MFA", en: "Approve MFA" },
    narration: {
      zh: "受害者批准了 MFA，攻击者立即获得长效 access_token + refresh_token。账户接管完成 —— 整个过程没有任何「恶意附件」或「钓鱼链接」被点击。",
      en: "The victim approves MFA. The attacker instantly receives a long-lived access_token + refresh_token. Account takeover is complete — no malicious attachment, no phishing link was ever clicked.",
    },
    message: {
      from: "victim",
      to: "service",
      kind: "approve",
      text: { zh: "✓ Approved", en: "✓ Approved" },
    },
  },
  {
    id: "vigilyx",
    actor: "vigilyx",
    label: { zh: "Vigilyx 拦截", en: "Vigilyx blocks" },
    narration: {
      zh: "Vigilyx toad_detect.rs 在邮件投递阶段就命中：callback_verb（“立即拨打”）+ phone_present（toll-free 1-855-）+ urgency_phrase（“24 小时内”）+ brand_impersonation（Norton / Geek Squad / 发件人域名不匹配）= High，邮件被隔离，电话从未被拨打。",
      en: "Vigilyx toad_detect.rs catches it at the delivery stage: callback_verb (“call now”) + phone_present (toll-free 1-855-) + urgency_phrase (“within 24h”) + brand_impersonation (Norton / Geek Squad mismatch) = High. The email is quarantined; the phone is never dialled.",
    },
    message: {
      from: "vigilyx" as Role,
      to: "victim",
      kind: "verdict",
      text: { zh: "Verdict: HIGH — quarantined", en: "Verdict: HIGH — quarantined" },
    },
  },
];

// active role for highlighting the lane in the current step
const currentScene = computed<Scene | null>(() =>
  stage.value > 0 ? scenes[stage.value - 1] : null
);
const activeRole = computed<Role | null>(() => currentScene.value?.actor ?? null);

// keep visible message trail showing last 3 message bubbles
const visibleMessages = computed(() => {
  const list: Array<{
    id: string;
    from: Role;
    to: Role;
    kind: Kind;
    text: { zh: string; en: string };
  }> = [];
  for (let i = 0; i < stage.value; i++) {
    const s = scenes[i];
    if (s.message) {
      list.push({ id: s.id, ...s.message });
    }
  }
  // Keep only the most recent 3 to avoid visual noise
  return list.slice(-3);
});

function step(): void {
  if (stage.value < scenes.length) stage.value += 1;
}
function toggle(): void {
  stage.value = stage.value === 0 ? scenes.length : 0;
}

function labelOf(a: { label: { zh: string; en: string } }): string {
  return isZh.value ? a.label.zh : a.label.en;
}
function narrationOf(s: Scene): string {
  return isZh.value ? s.narration.zh : s.narration.en;
}
function phaseLabel(s: Scene): string {
  return isZh.value ? s.label.zh : s.label.en;
}
function textOf(m: { text: { zh: string; en: string } }): string {
  return isZh.value ? m.text.zh : m.text.en;
}
function roleLabel(r: Role): string {
  if (isZh.value) {
    return { attacker: "攻击者", victim: "受害者", service: "服务商", vigilyx: "Vigilyx" }[r];
  }
  return { attacker: "Attacker", victim: "Victim", service: "Service", vigilyx: "Vigilyx" }[r];
}
function kindIcon(k: Kind): string {
  return {
    email: "✉",
    phone: "📞",
    voice: "🎙",
    rmm: "🖥",
    oauth: "🔑",
    approve: "✓",
    verdict: "🛡",
  }[k];
}
</script>

<style scoped>
.toad {
  margin: 1.5rem 0;
  border: 1px solid var(--vp-c-divider);
  border-radius: 16px;
  overflow: hidden;
  background: linear-gradient(
    180deg,
    rgba(15, 23, 42, 0.04) 0%,
    rgba(15, 23, 42, 0.01) 100%
  );
}
.dark .toad {
  background: linear-gradient(
    180deg,
    rgba(2, 6, 23, 0.85) 0%,
    rgba(2, 6, 23, 0.55) 100%
  );
  border-color: rgba(148, 163, 184, 0.15);
}

.toad__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.85rem 1.1rem;
  border-bottom: 1px solid var(--vp-c-divider);
  flex-wrap: wrap;
  background: rgba(15, 23, 42, 0.04);
}
.dark .toad__head {
  background: rgba(2, 6, 23, 0.5);
  border-bottom-color: rgba(148, 163, 184, 0.12);
}

.toad__title {
  display: flex;
  align-items: center;
  gap: 0.7rem;
  min-width: 0;
}
.toad__title h4 {
  margin: 0;
  font-size: 1rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
}
.toad__badge {
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
}
.toad__badge-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #fff;
  animation: toad-pulse 1.4s ease-in-out infinite;
}
@keyframes toad-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.4; transform: scale(0.7); }
}

.toad__ctrl {
  display: flex;
  gap: 0.4rem;
  flex-wrap: wrap;
}
.toad__btn {
  font: inherit;
  font-size: 0.82rem;
  font-weight: 500;
  padding: 0.4rem 0.9rem;
  border-radius: 8px;
  border: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-1);
  cursor: pointer;
  transition: all 0.15s ease;
}
.toad__btn:hover:not(:disabled) {
  background: var(--vp-c-bg-mute);
  border-color: var(--vp-c-brand-1);
}
.toad__btn:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}
.toad__btn--primary {
  background: linear-gradient(135deg, #f97316, #ef4444);
  color: #fff;
  border-color: transparent;
}

/* ---- Stage with three actor lanes ---- */
.toad__stage {
  position: relative;
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 0;
  padding: 1.6rem 1rem 1rem;
  background:
    radial-gradient(80% 60% at 50% 0%, rgba(20, 184, 166, 0.08), transparent 60%),
    transparent;
  min-height: 200px;
}

.toad__lane {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.55rem;
  position: relative;
  z-index: 2;
  padding: 0.8rem 0.6rem;
  border-radius: 12px;
  transition: all 0.3s ease;
}
.toad__lane--active {
  background: linear-gradient(180deg, rgba(20, 184, 166, 0.14), transparent 80%);
}
.toad__avatar {
  width: 52px;
  height: 52px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.6rem;
  background: var(--vp-c-bg-soft);
  border: 2px solid var(--vp-c-divider);
  position: relative;
  transition: all 0.3s ease;
}
.dark .toad__avatar {
  background: rgba(15, 23, 42, 0.7);
  border-color: rgba(148, 163, 184, 0.25);
}
.toad__avatar[data-role="attacker"] {
  background: linear-gradient(135deg, #fee2e2, #fecaca);
  border-color: #ef4444;
  color: #b91c1c;
}
.dark .toad__avatar[data-role="attacker"] {
  background: linear-gradient(135deg, rgba(239, 68, 68, 0.25), rgba(185, 28, 28, 0.18));
  border-color: rgba(239, 68, 68, 0.6);
}
.toad__avatar[data-role="victim"] {
  background: linear-gradient(135deg, #fef3c7, #fde68a);
  border-color: #d97706;
  color: #92400e;
}
.dark .toad__avatar[data-role="victim"] {
  background: linear-gradient(135deg, rgba(245, 158, 11, 0.25), rgba(217, 119, 6, 0.18));
  border-color: rgba(245, 158, 11, 0.6);
}
.toad__avatar[data-role="service"] {
  background: linear-gradient(135deg, #dbeafe, #bfdbfe);
  border-color: #2563eb;
  color: #1e40af;
}
.dark .toad__avatar[data-role="service"] {
  background: linear-gradient(135deg, rgba(37, 99, 235, 0.25), rgba(30, 64, 175, 0.18));
  border-color: rgba(96, 165, 250, 0.6);
}
.toad__lane--active .toad__avatar {
  transform: scale(1.08);
  box-shadow: 0 0 0 4px rgba(20, 184, 166, 0.18);
}
.toad__lane-label {
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
  text-align: center;
}

/* ---- Messages flowing between lanes ---- */
.toad__messages {
  position: absolute;
  inset: 1.6rem 1rem 1rem;
  pointer-events: none;
  z-index: 3;
}
.toad__message {
  position: absolute;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  width: 33.33%;
  pointer-events: none;
}
/* Position by stage index — each new message pushes earlier ones up */
.toad__message:nth-last-child(1) { top: 78px; }
.toad__message:nth-last-child(2) { top: 130px; opacity: 0.6; }
.toad__message:nth-last-child(3) { top: 175px; opacity: 0.3; }

.toad__message[data-from="attacker"][data-to="victim"] { left: 0; transform: translateX(50%); }
.toad__message[data-from="victim"][data-to="attacker"] { left: 33.33%; transform: translateX(-50%); }
.toad__message[data-from="attacker"][data-to="service"] { left: 33.33%; transform: translateX(50%); }
.toad__message[data-from="victim"][data-to="service"] { left: 33.33%; transform: translateX(50%); }
.toad__message[data-from="vigilyx"][data-to="victim"] { left: 0; transform: translateX(50%); }

.toad__message-bubble {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.4rem 0.7rem;
  border-radius: 10px;
  font-size: 0.78rem;
  font-weight: 500;
  background: rgba(15, 23, 42, 0.9);
  color: #f1f5f9;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.18);
  max-width: 240px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  border: 1px solid rgba(148, 163, 184, 0.25);
}
.dark .toad__message-bubble {
  background: rgba(15, 23, 42, 0.95);
}
.toad__message-bubble[data-kind="email"] { border-left: 3px solid #f59e0b; }
.toad__message-bubble[data-kind="phone"] { border-left: 3px solid #8b5cf6; }
.toad__message-bubble[data-kind="voice"] { border-left: 3px solid #ec4899; }
.toad__message-bubble[data-kind="rmm"]   { border-left: 3px solid #ef4444; background: rgba(239, 68, 68, 0.18); }
.toad__message-bubble[data-kind="oauth"] { border-left: 3px solid #38bdf8; }
.toad__message-bubble[data-kind="approve"]{ border-left: 3px solid #ef4444; }
.toad__message-bubble[data-kind="verdict"]{ background: linear-gradient(135deg, #14b8a6, #0d9488); color: #fff; border: none; }

.toad__message-icon { font-size: 0.95rem; }
.toad__message-text { font-family: var(--vp-font-family-mono); font-size: 0.74rem; }

/* ---- Phases ---- */
.toad__phases {
  display: grid;
  grid-template-columns: repeat(7, 1fr);
  gap: 4px;
  padding: 0.6rem 1.1rem 0.4rem;
}
.toad__phase {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.4rem 0.45rem;
  border-radius: 7px;
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
  font-size: 0.7rem;
  color: var(--vp-c-text-2);
  transition: all 0.3s ease;
  min-width: 0;
}
.toad__phase--done {
  background: rgba(34, 197, 94, 0.08);
  border-color: rgba(34, 197, 94, 0.3);
}
.toad__phase--active {
  background: linear-gradient(135deg, rgba(249, 115, 22, 0.18), rgba(239, 68, 68, 0.12));
  border-color: #f97316;
  box-shadow: 0 0 0 3px rgba(249, 115, 22, 0.15);
}
.toad__phase-num {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: var(--vp-c-bg-mute);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.65rem;
  font-weight: 700;
  flex-shrink: 0;
}
.toad__phase--done .toad__phase-num { background: #22c55e; color: #fff; }
.toad__phase--active .toad__phase-num {
  background: linear-gradient(135deg, #f97316, #ef4444);
  color: #fff;
}
.toad__phase-text {
  font-weight: 500;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* ---- Footer narration ---- */
.toad__footer {
  padding: 0.85rem 1.1rem 1rem;
  border-top: 1px solid var(--vp-c-divider);
  background: rgba(15, 23, 42, 0.03);
  min-height: 3.4rem;
  display: flex;
  align-items: center;
}
.dark .toad__footer {
  background: rgba(2, 6, 23, 0.5);
  border-top-color: rgba(148, 163, 184, 0.12);
}
.toad__narration {
  display: flex;
  gap: 0.65rem;
  align-items: flex-start;
  font-size: 0.86rem;
  line-height: 1.55;
  color: var(--vp-c-text-1);
}
.toad__nar-tag {
  flex-shrink: 0;
  font-size: 0.66rem;
  font-weight: 700;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  white-space: nowrap;
}
.toad__nar-tag[data-role="attacker"] {
  background: rgba(239, 68, 68, 0.18);
  color: #b91c1c;
  border: 1px solid rgba(239, 68, 68, 0.35);
}
.dark .toad__nar-tag[data-role="attacker"] { color: #fca5a5; }
.toad__nar-tag[data-role="victim"] {
  background: rgba(234, 179, 8, 0.16);
  color: #a16207;
  border: 1px solid rgba(234, 179, 8, 0.35);
}
.dark .toad__nar-tag[data-role="victim"] { color: #fde68a; }
.toad__nar-tag[data-role="service"] {
  background: rgba(37, 99, 235, 0.16);
  color: #1e40af;
  border: 1px solid rgba(37, 99, 235, 0.35);
}
.dark .toad__nar-tag[data-role="service"] { color: #93c5fd; }
.toad__nar-tag[data-role="vigilyx"] {
  background: rgba(20, 184, 166, 0.18);
  color: #0f766e;
  border: 1px solid rgba(20, 184, 166, 0.4);
}
.dark .toad__nar-tag[data-role="vigilyx"] { color: #5eead4; }

/* ---- Transitions ---- */
.toad-msg-enter-active,
.toad-msg-leave-active {
  transition: opacity 0.4s ease, transform 0.4s ease;
}
.toad-msg-enter-from {
  opacity: 0;
  transform: translateY(-12px) scale(0.85);
}
.toad-msg-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}
.toad-fade-enter-active,
.toad-fade-leave-active {
  transition: opacity 0.3s ease;
}
.toad-fade-enter-from,
.toad-fade-leave-to { opacity: 0; }

/* ---- Responsive ---- */
@media (max-width: 760px) {
  .toad__phases { grid-template-columns: repeat(4, 1fr); }
  .toad__message-bubble { max-width: 160px; font-size: 0.7rem; }
}
@media (prefers-reduced-motion: reduce) {
  .toad__badge-dot,
  .toad__phase--active { animation: none !important; }
}
</style>
