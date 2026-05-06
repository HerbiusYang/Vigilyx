<template>
  <div class="atksim" :class="{ 'atksim--playing': isPlaying }">
    <header class="atksim__header">
      <div class="atksim__title">
        <span class="atksim__badge">{{ t.badge }}</span>
        <h4>{{ title }}</h4>
      </div>
      <div class="atksim__controls">
        <button
          type="button"
          class="atksim__btn"
          @click="toggle"
          :aria-label="isPlaying ? t.pause : t.play"
        >
          <span v-if="isPlaying">⏸ {{ t.pause }}</span>
          <span v-else>▶ {{ t.play }}</span>
        </button>
        <button
          type="button"
          class="atksim__btn atksim__btn--ghost"
          @click="reset"
          :aria-label="t.replay"
        >
          ↻ {{ t.replay }}
        </button>
        <button
          type="button"
          class="atksim__btn atksim__btn--ghost"
          @click="next"
          :disabled="currentIndex >= steps.length - 1"
          :aria-label="t.step"
        >
          → {{ t.step }}
        </button>
      </div>
    </header>

    <div class="atksim__progress" role="progressbar" :aria-valuenow="currentIndex + 1" :aria-valuemax="steps.length">
      <div
        v-for="(_, i) in steps"
        :key="i"
        class="atksim__tick"
        :class="{
          'atksim__tick--done': i < currentIndex,
          'atksim__tick--active': i === currentIndex,
        }"
      ></div>
    </div>

    <ol class="atksim__stage">
      <li
        v-for="(step, i) in steps"
        :key="i"
        class="atksim__step"
        :class="{
          'atksim__step--active': i === currentIndex,
          'atksim__step--done': i < currentIndex,
          'atksim__step--pending': i > currentIndex,
        }"
      >
        <div class="atksim__step-marker">
          <span class="atksim__step-num">{{ i + 1 }}</span>
          <span v-if="step.actor" class="atksim__step-actor" :data-actor="step.actor">{{ actorLabel(step.actor) }}</span>
        </div>
        <div class="atksim__step-body">
          <div class="atksim__step-title">{{ stepText(step, 'title') }}</div>
          <div v-if="step.detail" class="atksim__step-detail">{{ stepText(step, 'detail') }}</div>
          <div v-if="step.payload" class="atksim__step-payload">
            <code>{{ step.payload }}</code>
          </div>
          <div v-if="step.detection" class="atksim__step-detection">
            <span class="atksim__detect-tag">{{ t.detected }}</span>
            <span>{{ stepText(step, 'detection') }}</span>
          </div>
        </div>
      </li>
    </ol>

    <footer class="atksim__footer">
      <span class="atksim__hint">{{ t.hint }}</span>
    </footer>
  </div>
</template>

<script setup lang="ts">
/**
 * AttackSimulation — bilingual, zero-dependency attack-chain animation
 * for VitePress markdown pages. Steps progress automatically when
 * playing, or one-by-one when the user clicks "→ Step".
 *
 * The component reads the active VitePress locale via useData() and
 * picks zh/en strings from each step. No external i18n library needed.
 */
import { computed, onUnmounted, ref, watch } from "vue";
import { useData } from "vitepress";

interface SimulationStep {
  /** Who performs this action — drives the colored badge */
  actor?: "attacker" | "victim" | "system" | "vigilyx";
  /** Step title — string for single-language, or { zh, en } object */
  title: string | { zh: string; en: string };
  /** Optional longer description */
  detail?: string | { zh: string; en: string };
  /** Optional code/command payload to render in <code> */
  payload?: string;
  /** Optional Vigilyx detection note — shown with green badge */
  detection?: string | { zh: string; en: string };
}

const props = withDefaults(
  defineProps<{
    title?: string;
    steps: SimulationStep[];
    /** ms between auto-advance steps */
    interval?: number;
    /** Auto-loop back to step 0 after the last step */
    loop?: boolean;
  }>(),
  {
    title: "Attack Simulation",
    interval: 2200,
    loop: false,
  }
);

const { lang } = useData();
const isZh = computed(() => (lang.value || "").toLowerCase().startsWith("zh"));

const currentIndex = ref(0);
const isPlaying = ref(false);
let timer: ReturnType<typeof setInterval> | null = null;

const t = computed(() =>
  isZh.value
    ? {
        badge: "攻击模拟",
        play: "播放",
        pause: "暂停",
        replay: "重播",
        step: "下一步",
        detected: "Vigilyx 检测",
        hint: "演示用动画——所有指标已脱敏，仅用于安全研究与培训",
        attacker: "攻击者",
        victim: "受害者",
        system: "系统/网关",
        vigilyx: "Vigilyx",
      }
    : {
        badge: "Attack Simulation",
        play: "Play",
        pause: "Pause",
        replay: "Replay",
        step: "Next",
        detected: "Vigilyx detects",
        hint: "Illustrative animation — all indicators sanitized, for research & training only",
        attacker: "Attacker",
        victim: "Victim",
        system: "System / Gateway",
        vigilyx: "Vigilyx",
      }
);

function stepText(step: SimulationStep, key: "title" | "detail" | "detection"): string {
  const v = step[key];
  if (!v) return "";
  if (typeof v === "string") return v;
  return isZh.value ? v.zh : v.en;
}

function actorLabel(actor: NonNullable<SimulationStep["actor"]>): string {
  return t.value[actor] ?? actor;
}

function clearTimer() {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}

function tick() {
  if (currentIndex.value >= props.steps.length - 1) {
    if (props.loop) {
      currentIndex.value = 0;
    } else {
      isPlaying.value = false;
      clearTimer();
    }
    return;
  }
  currentIndex.value += 1;
}

function play() {
  if (isPlaying.value) return;
  // If we're at the end, restart from the beginning
  if (currentIndex.value >= props.steps.length - 1 && !props.loop) {
    currentIndex.value = 0;
  }
  isPlaying.value = true;
  clearTimer();
  timer = setInterval(tick, props.interval);
}

function pause() {
  isPlaying.value = false;
  clearTimer();
}

function toggle() {
  isPlaying.value ? pause() : play();
}

function reset() {
  pause();
  currentIndex.value = 0;
}

function next() {
  pause();
  if (currentIndex.value < props.steps.length - 1) {
    currentIndex.value += 1;
  }
}

// Pause if the page is hidden — saves CPU on background tabs
function handleVisibility() {
  if (typeof document !== "undefined" && document.hidden && isPlaying.value) {
    pause();
  }
}

if (typeof document !== "undefined") {
  document.addEventListener("visibilitychange", handleVisibility);
}

watch(
  () => props.steps.length,
  () => {
    reset();
  }
);

onUnmounted(() => {
  clearTimer();
  if (typeof document !== "undefined") {
    document.removeEventListener("visibilitychange", handleVisibility);
  }
});
</script>

<style scoped>
.atksim {
  margin: 1.5rem 0;
  border: 1px solid var(--vp-c-divider);
  border-radius: 14px;
  background: linear-gradient(
    180deg,
    rgba(15, 23, 42, 0.04) 0%,
    rgba(15, 23, 42, 0.01) 100%
  );
  overflow: hidden;
  font-size: 0.92rem;
}

.dark .atksim {
  background: linear-gradient(
    180deg,
    rgba(15, 23, 42, 0.55) 0%,
    rgba(15, 23, 42, 0.25) 100%
  );
}

.atksim__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.85rem 1.1rem;
  border-bottom: 1px solid var(--vp-c-divider);
  flex-wrap: wrap;
}

.atksim__title {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  min-width: 0;
}

.atksim__title h4 {
  margin: 0;
  font-size: 1rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
  line-height: 1.4;
}

.atksim__badge {
  font-size: 0.7rem;
  font-weight: 600;
  padding: 0.2rem 0.55rem;
  border-radius: 999px;
  background: linear-gradient(135deg, #f97316, #ef4444);
  color: white;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  white-space: nowrap;
}

.atksim__controls {
  display: flex;
  gap: 0.4rem;
  flex-wrap: wrap;
}

.atksim__btn {
  font: inherit;
  font-size: 0.82rem;
  font-weight: 500;
  padding: 0.35rem 0.7rem;
  border-radius: 7px;
  border: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-1);
  cursor: pointer;
  transition: background 0.15s ease, border-color 0.15s ease;
  white-space: nowrap;
}

.atksim__btn:hover:not(:disabled) {
  background: var(--vp-c-bg-mute);
  border-color: var(--vp-c-brand-1);
}

.atksim__btn:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

.atksim__btn--ghost {
  background: transparent;
}

.atksim__progress {
  display: flex;
  gap: 4px;
  padding: 0.5rem 1.1rem 0.4rem;
}

.atksim__tick {
  flex: 1;
  height: 3px;
  border-radius: 2px;
  background: var(--vp-c-divider);
  transition: background 0.3s ease;
}

.atksim__tick--done {
  background: var(--vp-c-brand-1);
}

.atksim__tick--active {
  background: linear-gradient(90deg, var(--vp-c-brand-1) 0%, #f97316 100%);
  animation: atksim-pulse 1.4s ease-in-out infinite;
}

@keyframes atksim-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.55; }
}

.atksim__stage {
  list-style: none;
  margin: 0;
  padding: 0.75rem 1.1rem 0.5rem;
  counter-reset: none;
}

.atksim__step {
  position: relative;
  display: flex;
  gap: 0.85rem;
  padding: 0.7rem 0;
  border-left: 2px solid transparent;
  padding-left: 0.85rem;
  margin-left: 0.5rem;
  opacity: 0.42;
  transition: opacity 0.45s ease, transform 0.45s ease, border-color 0.3s ease;
}

.atksim__step + .atksim__step {
  border-top: 1px dashed var(--vp-c-divider);
}

.atksim__step--done {
  opacity: 0.78;
  border-left-color: var(--vp-c-brand-1);
}

.atksim__step--active {
  opacity: 1;
  border-left-color: #f97316;
  transform: translateX(2px);
  animation: atksim-slide-in 0.5s ease;
}

.atksim__step--pending {
  filter: grayscale(0.4);
}

@keyframes atksim-slide-in {
  from {
    transform: translateX(-6px);
    opacity: 0.2;
  }
  to {
    transform: translateX(2px);
    opacity: 1;
  }
}

.atksim__step-marker {
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.35rem;
  width: 90px;
}

.atksim__step-num {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  border-radius: 50%;
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--vp-c-text-2);
}

.atksim__step--active .atksim__step-num {
  background: linear-gradient(135deg, #f97316, #ef4444);
  border-color: transparent;
  color: white;
  box-shadow: 0 0 0 4px rgba(249, 115, 22, 0.18);
}

.atksim__step--done .atksim__step-num {
  background: var(--vp-c-brand-1);
  border-color: transparent;
  color: white;
}

.atksim__step-actor {
  font-size: 0.68rem;
  font-weight: 600;
  padding: 0.15rem 0.45rem;
  border-radius: 4px;
  text-align: center;
  letter-spacing: 0.02em;
  white-space: nowrap;
}

.atksim__step-actor[data-actor="attacker"] {
  background: rgba(239, 68, 68, 0.15);
  color: #b91c1c;
  border: 1px solid rgba(239, 68, 68, 0.3);
}
.dark .atksim__step-actor[data-actor="attacker"] {
  color: #fca5a5;
  background: rgba(239, 68, 68, 0.18);
}

.atksim__step-actor[data-actor="victim"] {
  background: rgba(234, 179, 8, 0.15);
  color: #a16207;
  border: 1px solid rgba(234, 179, 8, 0.3);
}
.dark .atksim__step-actor[data-actor="victim"] {
  color: #fde68a;
  background: rgba(234, 179, 8, 0.18);
}

.atksim__step-actor[data-actor="system"] {
  background: rgba(100, 116, 139, 0.15);
  color: #475569;
  border: 1px solid rgba(100, 116, 139, 0.3);
}
.dark .atksim__step-actor[data-actor="system"] {
  color: #cbd5e1;
  background: rgba(100, 116, 139, 0.22);
}

.atksim__step-actor[data-actor="vigilyx"] {
  background: rgba(34, 197, 94, 0.15);
  color: #15803d;
  border: 1px solid rgba(34, 197, 94, 0.35);
}
.dark .atksim__step-actor[data-actor="vigilyx"] {
  color: #86efac;
  background: rgba(34, 197, 94, 0.2);
}

.atksim__step-body {
  flex: 1;
  min-width: 0;
}

.atksim__step-title {
  font-weight: 600;
  color: var(--vp-c-text-1);
  line-height: 1.45;
  margin-bottom: 0.25rem;
}

.atksim__step-detail {
  font-size: 0.86rem;
  color: var(--vp-c-text-2);
  line-height: 1.55;
  margin-bottom: 0.4rem;
}

.atksim__step-payload {
  margin: 0.4rem 0 0.3rem;
  padding: 0.5rem 0.7rem;
  background: var(--vp-c-bg-alt);
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  font-family: var(--vp-font-family-mono);
  font-size: 0.78rem;
  overflow-x: auto;
  word-break: break-all;
  white-space: pre-wrap;
  color: var(--vp-c-text-1);
}

.atksim__step-payload code {
  background: transparent;
  padding: 0;
  font-size: inherit;
  color: inherit;
}

.atksim__step-detection {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  margin-top: 0.45rem;
  padding: 0.45rem 0.65rem;
  background: rgba(34, 197, 94, 0.08);
  border-left: 3px solid #22c55e;
  border-radius: 4px;
  font-size: 0.84rem;
  color: var(--vp-c-text-1);
  line-height: 1.5;
}

.dark .atksim__step-detection {
  background: rgba(34, 197, 94, 0.12);
}

.atksim__detect-tag {
  flex-shrink: 0;
  font-size: 0.7rem;
  font-weight: 700;
  padding: 0.1rem 0.45rem;
  border-radius: 3px;
  background: #22c55e;
  color: white;
  letter-spacing: 0.03em;
  text-transform: uppercase;
  white-space: nowrap;
}

.atksim__footer {
  padding: 0.55rem 1.1rem 0.7rem;
  border-top: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg-soft);
}

.atksim__hint {
  font-size: 0.74rem;
  color: var(--vp-c-text-3);
  font-style: italic;
}

@media (max-width: 640px) {
  .atksim__step {
    flex-direction: column;
    gap: 0.4rem;
  }
  .atksim__step-marker {
    flex-direction: row;
    width: auto;
  }
}

/* Honor reduced-motion preference: skip animations entirely */
@media (prefers-reduced-motion: reduce) {
  .atksim__step,
  .atksim__step--active,
  .atksim__tick--active {
    animation: none !important;
    transition: none !important;
  }
}
</style>
