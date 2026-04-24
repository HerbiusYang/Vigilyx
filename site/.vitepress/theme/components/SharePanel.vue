<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useData, useRoute } from "vitepress";
import QRCode from "qrcode";

const props = withDefaults(
  defineProps<{
    mode?: "home" | "doc";
  }>(),
  {
    mode: "doc",
  }
);

const route = useRoute();
const { lang, page, site } = useData();

const currentUrl = ref("");
const qrCodeDataUrl = ref("");
const qrOpen = ref(false);
const copied = ref(false);

const isZh = computed(() => lang.value.startsWith("zh"));
const shareTitle = computed(() => page.value.title || site.value.title || "Vigilyx");
const shareText = computed(() =>
  isZh.value
    ? `${shareTitle.value} · Vigilyx 邮件安全网关`
    : `${shareTitle.value} · Vigilyx email security gateway`
);

// Canonical deployed URL, injected by .vitepress/config.mts themeConfig.
// Falls back to the known GitHub Pages URL so dev/localhost never leaks.
const canonicalBase = computed<string>(() => {
  const cfg = site.value.themeConfig as unknown as { siteUrl?: string };
  return cfg.siteUrl ?? "https://herbiusyang.github.io/Vigilyx/";
});

const xShareUrl = computed(() => {
  if (!currentUrl.value) {
    return "";
  }

  const url = encodeURIComponent(currentUrl.value);
  const text = encodeURIComponent(shareText.value);
  return `https://twitter.com/intent/tweet?url=${url}&text=${text}`;
});

// Rewrite the current window URL onto the canonical origin so shares always
// resolve to the public GitHub Pages site, even when the dev server is running
// on localhost.
function computeCanonicalUrl(): string {
  if (typeof window === "undefined") return canonicalBase.value;
  try {
    const target = new URL(canonicalBase.value);
    const { pathname, search, hash } = window.location;
    target.pathname = pathname;
    target.search = search;
    target.hash = hash;
    return target.toString();
  } catch {
    return window.location.href;
  }
}

async function refreshShareState(): Promise<void> {
  if (typeof window === "undefined") {
    return;
  }

  currentUrl.value = computeCanonicalUrl();
  qrCodeDataUrl.value = await QRCode.toDataURL(currentUrl.value, {
    margin: 1,
    width: 220,
    color: {
      dark: "#08111E",
      light: "#F8FBFF",
    },
  });
}

async function copyLink(): Promise<void> {
  if (!currentUrl.value || typeof navigator === "undefined" || !navigator.clipboard) {
    return;
  }

  await navigator.clipboard.writeText(currentUrl.value);
  copied.value = true;
  window.setTimeout(() => {
    copied.value = false;
  }, 1800);
}

function openXShare(): void {
  if (!xShareUrl.value || typeof window === "undefined") {
    return;
  }

  window.open(xShareUrl.value, "_blank", "noopener,noreferrer");
}

onMounted(() => {
  void refreshShareState();
});

watch(
  () => route.path,
  () => {
    copied.value = false;
    qrOpen.value = false;
    void refreshShareState();
  }
);
</script>

<template>
  <section :class="['share-panel', `share-panel--${props.mode}`]">
    <div class="share-panel__content">
      <div class="share-panel__copy">
        <p class="share-panel__eyebrow">
          {{ isZh ? "支持开源" : "Support Open Source" }}
        </p>
        <h3 class="share-panel__title">
          {{ isZh ? "喜欢这个方向？给 Vigilyx 一个 Star。" : "Like the direction? Star Vigilyx." }}
        </h3>
        <p class="share-panel__desc">
          {{
            isZh
              ? "Star 会让更多安全团队看到这个项目。也可以把页面转给同事，方便一起评估。"
              : "A Star helps more security teams discover the project. Share the page when you want a teammate to evaluate it."
          }}
        </p>
      </div>

      <div class="share-panel__controls">
        <a
          class="share-star"
          href="https://github.com/HerbiusYang/Vigilyx"
          target="_blank"
          rel="noreferrer"
        >
          <span class="share-star__icon" aria-hidden="true">
            <svg viewBox="0 0 16 16" width="22" height="22" fill="currentColor">
              <path d="M8 0C3.58 0 0 3.69 0 8.24c0 3.64 2.29 6.72 5.47 7.81.4.08.55-.18.55-.4 0-.2-.01-.86-.01-1.56-2.01.38-2.53-.5-2.69-.95-.09-.23-.48-.95-.82-1.14-.28-.16-.68-.55-.01-.56.63-.01 1.08.6 1.23.84.72 1.24 1.87.89 2.33.68.07-.54.28-.89.51-1.1-1.78-.21-3.64-.92-3.64-4.07 0-.9.31-1.64.82-2.22-.08-.21-.36-1.05.08-2.18 0 0 .67-.22 2.2.85A7.43 7.43 0 0 1 8 3.96c.68 0 1.36.09 2 .28 1.53-1.07 2.2-.85 2.2-.85.44 1.13.16 1.97.08 2.18.51.58.82 1.31.82 2.22 0 3.16-1.87 3.86-3.65 4.07.29.26.54.76.54 1.53 0 1.1-.01 1.99-.01 2.26 0 .22.15.48.55.4A8.18 8.18 0 0 0 16 8.24C16 3.69 12.42 0 8 0z"/>
            </svg>
          </span>
          <span class="share-star__body">
            <span class="share-star__label">{{ isZh ? "GitHub 上 Star" : "Star on GitHub" }}</span>
            <span class="share-star__hint">{{ isZh ? "AGPL-3.0 · 无遥测 · 无授权服务器" : "AGPL-3.0 · no telemetry · no license server" }}</span>
          </span>
          <span class="share-star__arrow" aria-hidden="true">
            <svg viewBox="0 0 16 16" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M3 8h10M9 4l4 4-4 4"/>
            </svg>
          </span>
        </a>

        <div
          class="share-panel__quick"
          role="group"
          :aria-label="isZh ? '分享操作' : 'Share actions'"
        >
          <button
            class="share-quick"
            type="button"
            :disabled="!currentUrl"
            @click="openXShare"
          >
            <span class="share-quick__icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" width="17" height="17" fill="currentColor">
                <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
              </svg>
            </span>
            <span>{{ isZh ? "X" : "X" }}</span>
          </button>

          <button
            :class="['share-quick', { 'is-copied': copied }]"
            type="button"
            :disabled="!currentUrl"
            @click="copyLink"
          >
            <span class="share-quick__icon" aria-hidden="true">
              <svg v-if="!copied" viewBox="0 0 16 16" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                <path d="M6.5 9.5a2.5 2.5 0 0 0 3.54 0l2-2a2.5 2.5 0 0 0-3.54-3.54l-.6.6"/>
                <path d="M9.5 6.5a2.5 2.5 0 0 0-3.54 0l-2 2a2.5 2.5 0 0 0 3.54 3.54l.6-.6"/>
              </svg>
              <svg v-else viewBox="0 0 16 16" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M3.5 8.5l3 3 6-7"/>
              </svg>
            </span>
            <span>{{ copied ? (isZh ? "已复制" : "Copied") : (isZh ? "复制链接" : "Copy") }}</span>
          </button>

          <button
            :class="['share-quick', { 'is-open': qrOpen }]"
            type="button"
            :disabled="!currentUrl"
            :aria-expanded="qrOpen"
            @click="qrOpen = !qrOpen"
          >
            <span class="share-quick__icon" aria-hidden="true">
              <svg viewBox="0 0 16 16" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round">
                <rect x="2" y="2" width="5" height="5" rx="0.6"/>
                <rect x="9" y="2" width="5" height="5" rx="0.6"/>
                <rect x="2" y="9" width="5" height="5" rx="0.6"/>
                <path d="M9 9h1.5v1.5H9zM12.5 9H14v1.5h-1.5zM9 12.5h1.5V14H9zM12.5 12.5H14V14h-1.5z"/>
              </svg>
            </span>
            <span>{{ isZh ? "微信" : "WeChat" }}</span>
          </button>
        </div>
      </div>
    </div>

    <div v-if="qrOpen" class="share-panel__qr">
      <img
        :src="qrCodeDataUrl"
        :alt="isZh ? '当前页面微信分享二维码' : 'WeChat share QR code for the current page'"
      />
      <div class="share-panel__qr-body">
        <p class="share-panel__qr-title">
          {{ isZh ? "用微信扫一扫" : "Scan with WeChat" }}
        </p>
        <p class="share-panel__qr-desc">
          {{
            isZh
              ? "把当前页面发给团队或社区。二维码指向你现在正在看的地址。"
              : "Send this page to your team or community. The QR encodes the URL you're currently on."
          }}
        </p>
      </div>
    </div>
  </section>
</template>
