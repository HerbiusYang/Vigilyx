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

const xShareUrl = computed(() => {
  if (!currentUrl.value) {
    return "";
  }

  const url = encodeURIComponent(currentUrl.value);
  const text = encodeURIComponent(shareText.value);
  return `https://twitter.com/intent/tweet?url=${url}&text=${text}`;
});

async function refreshShareState(): Promise<void> {
  if (typeof window === "undefined") {
    return;
  }

  currentUrl.value = window.location.href;
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
    <div class="share-panel__copy">
      <p class="share-panel__eyebrow">
        {{ isZh ? "分享页面" : "Share this page" }}
      </p>
      <p class="share-panel__title">
        {{
          isZh
            ? "支持 X 直达分享，也支持用微信二维码或复制链接传播当前页面。"
            : "Share directly to X, or use a WeChat QR code and copyable link for the current page."
        }}
      </p>
    </div>

    <div class="share-panel__actions">
      <button
        class="share-panel__button share-panel__button--x"
        type="button"
        :disabled="!currentUrl"
        @click="openXShare"
      >
        {{ isZh ? "分享到 X" : "Share on X" }}
      </button>
      <button
        class="share-panel__button"
        type="button"
        :disabled="!currentUrl"
        @click="qrOpen = !qrOpen"
      >
        {{ isZh ? "微信二维码" : "WeChat QR" }}
      </button>
      <button
        class="share-panel__button"
        type="button"
        :disabled="!currentUrl"
        @click="copyLink"
      >
        {{
          copied
            ? (isZh ? "链接已复制" : "Link copied")
            : (isZh ? "复制链接" : "Copy link")
        }}
      </button>
    </div>

    <div v-if="qrOpen" class="share-panel__qr">
      <img
        :src="qrCodeDataUrl"
        :alt="isZh ? '当前页面微信分享二维码' : 'WeChat share QR code for the current page'"
      />
      <p>
        {{
          isZh
            ? "用微信扫码，把当前页面发给团队或社区。"
            : "Scan in WeChat to share the current page with your team or community."
        }}
      </p>
    </div>
  </section>
</template>
