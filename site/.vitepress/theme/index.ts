import { h } from "vue";
import DefaultTheme from "vitepress/theme";
import type { EnhanceAppContext } from "vitepress";
import HomeLanding from "./components/HomeLanding.vue";
import HeroBackdrop from "./components/HeroBackdrop.vue";
import SharePanel from "./components/SharePanel.vue";
import "./custom.css";

export default {
  extends: DefaultTheme,
  enhanceApp(ctx: EnhanceAppContext) {
    DefaultTheme.enhanceApp?.(ctx);
    const { app } = ctx;
    app.component("HomeLanding", HomeLanding);
    app.component("HeroBackdrop", HeroBackdrop);
  },
  Layout() {
    return h(DefaultTheme.Layout, null, {
      "doc-footer-before": () => h(SharePanel, { mode: "doc" }),
    });
  },
};
