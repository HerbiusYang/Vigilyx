<template>
  <div class="hero-backdrop" aria-hidden="true">
    <canvas v-if="enableCanvas" ref="canvasRef" class="hero-backdrop__canvas"></canvas>
    <div class="hero-backdrop__grid"></div>
    <div class="hero-backdrop__glow hero-backdrop__glow--teal"></div>
    <div class="hero-backdrop__glow hero-backdrop__glow--blue"></div>
    <div v-if="enableCanvas" class="hero-backdrop__scanline"></div>
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from "vue";

const canvasRef = ref<HTMLCanvasElement | null>(null);
const enableCanvas = ref(true);

let rafId = 0;
let resizeObserver: ResizeObserver | null = null;
let visibilityHandler: (() => void) | null = null;
let intersectionObserver: IntersectionObserver | null = null;
let running = false;
let lastFrame = 0;

interface Node {
  x: number;
  y: number;
  vx: number;
  vy: number;
  r: number;
  teal: boolean;
}

interface Packet {
  from: number;
  to: number;
  progress: number;
  speed: number;
  teal: boolean;
}

// Decide up-front whether to run canvas at all
function shouldEnableCanvas(): boolean {
  if (typeof window === "undefined") return false;
  if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return false;
  // Disable on small screens — pure-CSS glow is enough for mobile
  if (window.innerWidth < 900) return false;
  // Low-end hint: require a decent CPU — CPU-only hosts (no GPU accel)
  // can feel sluggish even with 4 cores, so raise the bar
  const cores = (navigator as any).hardwareConcurrency ?? 4;
  if (cores <= 4) return false;
  // Save-Data / low memory hint
  const mem = (navigator as any).deviceMemory;
  if (typeof mem === "number" && mem <= 4) return false;
  return true;
}

onMounted(() => {
  enableCanvas.value = shouldEnableCanvas();
  if (!enableCanvas.value) return;

  // Wait for DOM update so canvas is rendered
  requestAnimationFrame(() => setupCanvas());
});

function setupCanvas() {
  const canvas = canvasRef.value;
  if (!canvas) return;

  const ctx = canvas.getContext("2d", { alpha: true });
  if (!ctx) return;

  // Cap DPR to keep pixel count small on CPU-only hosts
  const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
  let width = 0;
  let height = 0;
  const nodes: Node[] = [];
  const packets: Packet[] = [];

  // Pre-rendered node glow sprites — avoid createRadialGradient per frame
  const spriteSize = 48;
  const tealSprite = buildGlowSprite(168);
  const blueSprite = buildGlowSprite(198);

  function buildGlowSprite(hue: number): HTMLCanvasElement {
    const off = document.createElement("canvas");
    off.width = spriteSize;
    off.height = spriteSize;
    const octx = off.getContext("2d");
    if (!octx) return off;
    const cx = spriteSize / 2;
    const grad = octx.createRadialGradient(cx, cx, 0, cx, cx, cx);
    grad.addColorStop(0, `hsla(${hue}, 95%, 78%, 0.95)`);
    grad.addColorStop(0.25, `hsla(${hue}, 90%, 70%, 0.45)`);
    grad.addColorStop(1, `hsla(${hue}, 90%, 70%, 0)`);
    octx.fillStyle = grad;
    octx.fillRect(0, 0, spriteSize, spriteSize);
    return off;
  }

  const resize = () => {
    const rect = canvas.getBoundingClientRect();
    width = rect.width;
    height = rect.height;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    seedNodes();
  };

  const seedNodes = () => {
    nodes.length = 0;
    packets.length = 0;
    // Cap tightly: 10–14 nodes total
    const area = width * height;
    const count = Math.max(10, Math.min(14, Math.floor(area / 90000)));
    for (let i = 0; i < count; i += 1) {
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.14,
        vy: (Math.random() - 0.5) * 0.14,
        r: 1.4 + Math.random() * 1.2,
        teal: Math.random() < 0.55,
      });
    }
  };

  const spawnPacket = () => {
    if (nodes.length < 2) return;
    const from = Math.floor(Math.random() * nodes.length);
    let to = Math.floor(Math.random() * nodes.length);
    if (to === from) to = (to + 1) % nodes.length;
    packets.push({
      from,
      to,
      progress: 0,
      speed: 0.005 + Math.random() * 0.006,
      teal: Math.random() < 0.6,
    });
  };

  const MAX_DIST = 160;
  const MAX_DIST_SQ = MAX_DIST * MAX_DIST;
  const FRAME_INTERVAL = 1000 / 24; // 24fps cap — plenty for ambient motion

  const draw = (t: number) => {
    if (!running) return;
    rafId = requestAnimationFrame(draw);

    // Throttle to ~30fps
    if (t - lastFrame < FRAME_INTERVAL) return;
    lastFrame = t;

    ctx.clearRect(0, 0, width, height);

    // Move
    for (let i = 0; i < nodes.length; i += 1) {
      const n = nodes[i];
      n.x += n.vx;
      n.y += n.vy;
      if (n.x < 0 || n.x > width) n.vx = -n.vx;
      if (n.y < 0 || n.y > height) n.vy = -n.vy;
    }

    // Links (O(n²) but n ≤ 14 → ≤ 91 pairs)
    ctx.lineWidth = 0.6;
    for (let i = 0; i < nodes.length; i += 1) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j += 1) {
        const b = nodes[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const d2 = dx * dx + dy * dy;
        if (d2 >= MAX_DIST_SQ) continue;
        const d = Math.sqrt(d2);
        const alpha = (1 - d / MAX_DIST) * 0.22;
        ctx.strokeStyle = `rgba(125, 211, 252, ${alpha})`;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();
      }
    }

    // Nodes via cached sprites — drawImage is cheap
    const half = spriteSize / 2;
    for (let i = 0; i < nodes.length; i += 1) {
      const n = nodes[i];
      ctx.drawImage(n.teal ? tealSprite : blueSprite, n.x - half, n.y - half);
    }

    // Packets — cap at 4 concurrent
    if (packets.length < 4 && Math.random() < 0.03) spawnPacket();

    for (let i = packets.length - 1; i >= 0; i -= 1) {
      const p = packets[i];
      p.progress += p.speed;
      if (p.progress >= 1) {
        packets.splice(i, 1);
        continue;
      }
      const a = nodes[p.from];
      const b = nodes[p.to];
      if (!a || !b) {
        packets.splice(i, 1);
        continue;
      }
      const x = a.x + (b.x - a.x) * p.progress;
      const y = a.y + (b.y - a.y) * p.progress;
      const tp = Math.max(0, p.progress - 0.1);
      const tx = a.x + (b.x - a.x) * tp;
      const ty = a.y + (b.y - a.y) * tp;

      // Simple translucent stroke — no gradient per frame
      ctx.strokeStyle = p.teal
        ? "rgba(94, 234, 212, 0.75)"
        : "rgba(125, 211, 252, 0.75)";
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.moveTo(tx, ty);
      ctx.lineTo(x, y);
      ctx.stroke();

      ctx.fillStyle = p.teal
        ? "rgba(167, 243, 208, 1)"
        : "rgba(186, 230, 253, 1)";
      ctx.beginPath();
      ctx.arc(x, y, 2, 0, Math.PI * 2);
      ctx.fill();
    }
  };

  const start = () => {
    if (running) return;
    running = true;
    lastFrame = 0;
    rafId = requestAnimationFrame(draw);
  };

  const stop = () => {
    running = false;
    if (rafId) cancelAnimationFrame(rafId);
    rafId = 0;
  };

  resize();

  if (typeof ResizeObserver !== "undefined") {
    resizeObserver = new ResizeObserver(() => resize());
    resizeObserver.observe(canvas);
  }

  // Pause when tab hidden
  visibilityHandler = () => {
    if (document.hidden) stop();
    else start();
  };
  document.addEventListener("visibilitychange", visibilityHandler);

  // Pause when hero scrolled off-screen
  if (typeof IntersectionObserver !== "undefined") {
    intersectionObserver = new IntersectionObserver(
      (entries) => {
        const visible = entries.some((e) => e.isIntersecting);
        if (visible) start();
        else stop();
      },
      { threshold: 0.05 },
    );
    intersectionObserver.observe(canvas);
  } else {
    start();
  }
}

onBeforeUnmount(() => {
  running = false;
  if (rafId) cancelAnimationFrame(rafId);
  if (resizeObserver) resizeObserver.disconnect();
  if (intersectionObserver) intersectionObserver.disconnect();
  if (visibilityHandler) document.removeEventListener("visibilitychange", visibilityHandler);
});
</script>

<style scoped>
.hero-backdrop {
  position: absolute;
  inset: 0;
  overflow: hidden;
  pointer-events: none;
  z-index: 0;
  /* Promote to own layer, but avoid expensive will-change on children */
  contain: strict;
}

.hero-backdrop__canvas {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  opacity: 0.8;
}

.hero-backdrop__grid {
  position: absolute;
  inset: -2px;
  background-image:
    linear-gradient(rgba(94, 234, 212, 0.06) 1px, transparent 1px),
    linear-gradient(90deg, rgba(125, 211, 252, 0.05) 1px, transparent 1px);
  background-size: 56px 56px;
  mask-image: radial-gradient(ellipse 80% 60% at 50% 40%, black 40%, transparent 85%);
  -webkit-mask-image: radial-gradient(ellipse 80% 60% at 50% 40%, black 40%, transparent 85%);
  opacity: 0.55;
}

/* Static glows — no animation to keep CPU idle */
.hero-backdrop__glow {
  position: absolute;
  border-radius: 50%;
  filter: blur(40px);
  opacity: 0.35;
}

.hero-backdrop__glow--teal {
  top: -8%;
  left: 8%;
  width: 360px;
  height: 360px;
  background: radial-gradient(circle, rgba(94, 234, 212, 0.55), transparent 70%);
}

.hero-backdrop__glow--blue {
  bottom: -15%;
  right: 5%;
  width: 440px;
  height: 440px;
  background: radial-gradient(circle, rgba(59, 130, 246, 0.45), transparent 70%);
}

/* One lightweight animated element only */
.hero-backdrop__scanline {
  position: absolute;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(94, 234, 212, 0.55), transparent);
  top: 0;
  animation: heroScan 12s linear infinite;
  opacity: 0.5;
}

@keyframes heroScan {
  0% {
    transform: translateY(0);
    opacity: 0;
  }
  10% {
    opacity: 0.6;
  }
  90% {
    opacity: 0.6;
  }
  100% {
    transform: translateY(100vh);
    opacity: 0;
  }
}

@media (max-width: 760px) {
  .hero-backdrop__glow {
    filter: blur(28px);
  }
  .hero-backdrop__glow--teal {
    width: 240px;
    height: 240px;
    opacity: 0.35;
  }
  .hero-backdrop__glow--blue {
    width: 280px;
    height: 280px;
    opacity: 0.3;
  }
  .hero-backdrop__grid {
    background-size: 40px 40px;
  }
  .hero-backdrop__scanline {
    display: none;
  }
}

@media (prefers-reduced-motion: reduce) {
  .hero-backdrop__scanline {
    animation: none;
    display: none;
  }
}
</style>
