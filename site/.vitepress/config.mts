import { defineConfig, type DefaultTheme } from "vitepress";

function ensureLeadingSlash(value: string): string {
  return value.startsWith("/") ? value : `/${value}`;
}

function ensureTrailingSlash(value: string): string {
  return value.endsWith("/") ? value : `${value}/`;
}

const siteBase = ensureTrailingSlash(
  ensureLeadingSlash(process.env.SITE_BASE ?? "/Vigilyx/")
);
const siteUrl = ensureTrailingSlash(
  process.env.SITE_URL ?? "https://herbiusyang.github.io/Vigilyx/"
);

const localSearch = {
  provider: "local",
  options: {
    locales: {
      root: {
        translations: {
          button: {
            buttonText: "Search docs",
            buttonAriaLabel: "Search docs",
          },
          modal: {
            displayDetails: "Display detailed list",
            noResultsText: "No results for this query",
            resetButtonTitle: "Reset search",
            backButtonTitle: "Close search",
            footer: {
              selectText: "Select",
              selectKeyAriaLabel: "enter",
              navigateText: "Navigate",
              navigateUpKeyAriaLabel: "up arrow",
              navigateDownKeyAriaLabel: "down arrow",
              closeText: "Close",
              closeKeyAriaLabel: "escape",
            },
          },
        },
      },
      zh: {
        translations: {
          button: {
            buttonText: "搜索文档",
            buttonAriaLabel: "搜索文档",
          },
          modal: {
            displayDetails: "显示详细列表",
            noResultsText: "没有找到相关结果",
            resetButtonTitle: "清空搜索",
            backButtonTitle: "关闭搜索",
            footer: {
              selectText: "选择",
              selectKeyAriaLabel: "回车",
              navigateText: "切换",
              navigateUpKeyAriaLabel: "上箭头",
              navigateDownKeyAriaLabel: "下箭头",
              closeText: "关闭",
              closeKeyAriaLabel: "ESC",
            },
          },
        },
      },
    },
  },
} as const;

function createThemeConfig(locale: "en" | "zh"): DefaultTheme.Config {
  const isZh = locale === "zh";
  const docsPrefix = isZh ? "/zh/docs/" : "/docs/";

  return {
    logo: "/logo.png",
    siteTitle: "Vigilyx",
    search: localSearch,
    nav: isZh
      ? [
          { text: "指南", link: "/zh/docs/" },
          { text: "快速开始", link: "/zh/docs/quick-start" },
          { text: "部署方式", link: "/zh/docs/deployment" },
          { text: "架构", link: "/zh/docs/architecture" },
          { text: "GitHub", link: "https://github.com/HerbiusYang/Vigilyx" },
        ]
      : [
          { text: "Guide", link: "/docs/" },
          { text: "Quick Start", link: "/docs/quick-start" },
          { text: "Deployment", link: "/docs/deployment" },
          { text: "Architecture", link: "/docs/architecture" },
          { text: "GitHub", link: "https://github.com/HerbiusYang/Vigilyx" },
        ],
    sidebar: {
      [docsPrefix]: [
        {
          text: isZh ? "开始使用" : "Get Started",
          items: [
            { text: isZh ? "概览" : "Overview", link: `${docsPrefix}` },
            { text: isZh ? "快速开始" : "Quick Start", link: `${docsPrefix}quick-start` },
            { text: isZh ? "部署" : "Deployment", link: `${docsPrefix}deployment` },
            { text: isZh ? "架构" : "Architecture", link: `${docsPrefix}architecture` },
            { text: isZh ? "项目站点" : "Project Site", link: `${docsPrefix}project-site` },
          ],
        },
      ],
    },
    socialLinks: [
      { icon: "github", link: "https://github.com/HerbiusYang/Vigilyx" },
    ],
    footer: {
      message: isZh ? "基于 AGPL-3.0-only 发布。" : "Released under AGPL-3.0-only.",
      copyright: isZh
        ? "Copyright © 2026 Vigilyx contributors"
        : "Copyright © 2026 Vigilyx contributors",
    },
    docFooter: {
      prev: isZh ? "上一页" : "Previous",
      next: isZh ? "下一页" : "Next",
    },
    outline: {
      label: isZh ? "本页目录" : "On this page",
    },
    langMenuLabel: isZh ? "语言" : "Languages",
    returnToTopLabel: isZh ? "返回顶部" : "Return to top",
    sidebarMenuLabel: isZh ? "菜单" : "Menu",
    darkModeSwitchLabel: isZh ? "外观" : "Appearance",
    lightModeSwitchTitle: isZh ? "切换到浅色模式" : "Switch to light theme",
    darkModeSwitchTitle: isZh ? "切换到深色模式" : "Switch to dark theme",
    lastUpdatedText: isZh ? "最后更新" : "Last updated",
  };
}

function canonicalFor(relativePath: string): string {
  if (relativePath === "index.md") {
    return new URL(".", siteUrl).toString();
  }

  if (relativePath.endsWith("/index.md")) {
    return new URL(`${relativePath.slice(0, -"index.md".length)}`, siteUrl).toString();
  }

  return new URL(relativePath.replace(/\.md$/, ""), siteUrl).toString();
}

export default defineConfig({
  lang: "en-US",
  title: "Vigilyx",
  description:
    "Rust-powered email security gateway and analysis platform for passive mirror monitoring and inline MTA inspection.",
  locales: {
    root: {
      label: "English",
      lang: "en-US",
      title: "Vigilyx",
      description:
        "Rust-powered email security gateway and analysis platform for passive mirror monitoring and inline MTA inspection.",
      themeConfig: createThemeConfig("en"),
    },
    zh: {
      label: "简体中文",
      lang: "zh-CN",
      link: "/zh/",
      title: "Vigilyx",
      description:
        "Rust 驱动的邮件安全网关与邮件安全分析平台，支持旁路镜像分析与 Inline MTA 检测。",
      themeConfig: createThemeConfig("zh"),
    },
  },
  base: siteBase,
  cleanUrls: true,
  lastUpdated: true,
  sitemap: {
    hostname: siteUrl,
  },
  head: [
    ["meta", { name: "theme-color", content: "#0f172a" }],
    [
      "meta",
      {
        name: "keywords",
        content:
          "Vigilyx,email security gateway,email security analysis platform,SMTP proxy,MTA inspection,邮件安全网关,邮件安全分析平台",
      },
    ],
    ["meta", { property: "og:site_name", content: "Vigilyx" }],
    ["meta", { property: "og:image", content: new URL("share-card.jpg", siteUrl).toString() }],
    ["meta", { property: "og:image:secure_url", content: new URL("share-card.jpg", siteUrl).toString() }],
    ["meta", { property: "og:image:type", content: "image/jpeg" }],
    ["meta", { property: "og:image:width", content: "1200" }],
    ["meta", { property: "og:image:height", content: "630" }],
    ["meta", { property: "og:image:alt", content: "Vigilyx email security gateway branding" }],
    ["meta", { name: "twitter:card", content: "summary_large_image" }],
    ["meta", { name: "twitter:image", content: new URL("share-card.jpg", siteUrl).toString() }],
    ["link", { rel: "icon", type: "image/png", href: `${siteBase}logo.png` }],
  ],
  transformHead({ pageData }) {
    const canonical = canonicalFor(pageData.relativePath);
    const pageDescription = pageData.description || "Vigilyx product and documentation site.";
    const isHome = pageData.relativePath === "index.md";

    return [
      ["link", { rel: "canonical", href: canonical }],
      ["meta", { name: "description", content: pageDescription }],
      ["meta", { property: "og:title", content: pageData.title || "Vigilyx" }],
      ["meta", { property: "og:description", content: pageDescription }],
      ["meta", { property: "og:url", content: canonical }],
      ["meta", { property: "og:type", content: isHome ? "website" : "article" }],
      ["meta", { name: "twitter:title", content: pageData.title || "Vigilyx" }],
      ["meta", { name: "twitter:description", content: pageDescription }],
    ];
  },
});
