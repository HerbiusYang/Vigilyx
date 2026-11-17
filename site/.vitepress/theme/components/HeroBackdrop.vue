<template>
  <div class="hero-backdrop" aria-hidden="true">
    <div class="hero-backdrop__grid"></div>
    <div class="hero-backdrop__scan"></div>
    <div class="hero-backdrop__packet"></div>
    <div class="hero-backdrop__glow hero-backdrop__glow--teal"></div>
    <div class="hero-backdrop__glow hero-backdrop__glow--blue"></div>
    <div class="hero-backdrop__noise"></div>
  </div>
</template>

<script setup lang="ts">
// Pure CSS backdrop — zero runtime cost.
// Previously used a canvas animation, but on CPU-only hosts the compositor
// overhead outweighed the visual payoff. A static, layered gradient reads
// as "premium" without paying any per-frame cost.
</script>

<style scoped>
.hero-backdrop {
  position: absolute;
  inset: 0;
  overflow: hidden;
  pointer-events: none;
  z-index: 0;
  contain: strict;
}

/* Subtle dot grid — single static layer */
.hero-backdrop__grid {
  position: absolute;
  inset: 0;
  background-image:
    radial-gradient(rgba(148, 163, 184, 0.22) 1px, transparent 1px);
  background-size: 28px 28px;
  background-position: 0 0;
  mask-image: radial-gradient(
    ellipse 85% 70% at 50% 35%,
    #000 30%,
    transparent 85%
  );
  -webkit-mask-image: radial-gradient(
    ellipse 85% 70% at 50% 35%,
    #000 30%,
    transparent 85%
  );
  opacity: 0.5;
  animation: vig-grid-drift 28s linear infinite;
}

.hero-backdrop__scan {
  position: absolute;
  left: 0;
  right: 0;
  height: 18%;
  top: -20%;
  background: linear-gradient(
    180deg,
    transparent,
    rgba(94, 234, 212, 0.07) 45%,
    rgba(94, 234, 212, 0.16) 50%,
    rgba(94, 234, 212, 0.07) 55%,
    transparent
  );
  animation: vig-scan 7.5s ease-in-out infinite;
  will-change: transform;
}

.hero-backdrop__packet {
  position: absolute;
  top: 42%;
  left: -8%;
  width: 72px;
  height: 2px;
  border-radius: 999px;
  background: linear-gradient(90deg, transparent, #5eead4 40%, #93c5fd);
  box-shadow: 0 0 12px rgba(94, 234, 212, 0.45);
  animation: vig-packet 9s linear infinite;
  will-change: transform;
}

@keyframes vig-grid-drift {
  to { background-position: 28px 28px; }
}

@keyframes vig-scan {
  0% { transform: translateY(0); }
  100% { transform: translateY(680%); }
}

@keyframes vig-packet {
  0% { transform: translateX(0); opacity: 0; }
  12% { opacity: 1; }
  88% { opacity: 1; }
  100% { transform: translateX(140vw); opacity: 0; }
}

/* Two static corner glows — no animation, no blur (pre-baked gradient) */
.hero-backdrop__glow {
  position: absolute;
  border-radius: 50%;
  /* Use soft radial gradient stops instead of filter: blur — cheaper */
  opacity: 0.55;
}

.hero-backdrop__glow--teal {
  top: -20%;
  left: -5%;
  width: 520px;
  height: 520px;
  background: radial-gradient(
    circle,
    rgba(45, 212, 191, 0.28) 0%,
    rgba(45, 212, 191, 0.08) 40%,
    transparent 70%
  );
}

.hero-backdrop__glow--blue {
  bottom: -25%;
  right: -8%;
  width: 580px;
  height: 580px;
  background: radial-gradient(
    circle,
    rgba(59, 130, 246, 0.22) 0%,
    rgba(59, 130, 246, 0.06) 40%,
    transparent 70%
  );
}

/* Grain overlay — adds texture, no animation */
.hero-backdrop__noise {
  position: absolute;
  inset: 0;
  opacity: 0.04;
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='140' height='140'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2'/><feColorMatrix values='0 0 0 0 0.8 0 0 0 0 0.9 0 0 0 0 1 0 0 0 1 0'/></filter><rect width='140' height='140' filter='url(%23n)'/></svg>");
  mix-blend-mode: overlay;
  pointer-events: none;
}

@media (max-width: 760px) {
  .hero-backdrop__glow--teal {
    width: 320px;
    height: 320px;
    opacity: 0.4;
  }
  .hero-backdrop__glow--blue {
    width: 360px;
    height: 360px;
    opacity: 0.35;
  }
  .hero-backdrop__grid {
    background-size: 22px 22px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .hero-backdrop__grid,
  .hero-backdrop__scan,
  .hero-backdrop__packet {
    animation: none;
  }
  .hero-backdrop__scan,
  .hero-backdrop__packet {
    display: none;
  }
}
</style>
