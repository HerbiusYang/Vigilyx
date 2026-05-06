import { h } from "vue";
import DefaultTheme from "vitepress/theme";
import type { EnhanceAppContext } from "vitepress";
import HomeLanding from "./components/HomeLanding.vue";
import HeroBackdrop from "./components/HeroBackdrop.vue";
import SharePanel from "./components/SharePanel.vue";
import AttackSimulation from "./components/AttackSimulation.vue";
import HtmlCloakingDemo from "./components/HtmlCloakingDemo.vue";
import TOADTimeline from "./components/TOADTimeline.vue";
import KnowledgeGrid from "./components/KnowledgeGrid.vue";
import "./custom.css";

export default {
  extends: DefaultTheme,
  enhanceApp(ctx: EnhanceAppContext) {
    DefaultTheme.enhanceApp?.(ctx);
    const { app } = ctx;
    app.component("HomeLanding", HomeLanding);
    app.component("HeroBackdrop", HeroBackdrop);
    // Globally registered so attack case studies can embed
    // <AttackSimulation /> directly in markdown.
    app.component("AttackSimulation", AttackSimulation);
    app.component("HtmlCloakingDemo", HtmlCloakingDemo);
    app.component("TOADTimeline", TOADTimeline);
    app.component("KnowledgeGrid", KnowledgeGrid);
  },
  Layout() {
    return h(DefaultTheme.Layout, null, {
      "doc-footer-before": () => h(SharePanel, { mode: "doc" }),
    });
  },
};
