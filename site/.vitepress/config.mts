import { defineConfig } from "vitepress";

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
    ["meta", { property: "og:image", content: new URL("og-card.svg", siteUrl).toString() }],
    ["meta", { name: "twitter:card", content: "summary_large_image" }],
    ["meta", { name: "twitter:image", content: new URL("og-card.svg", siteUrl).toString() }],
    ["link", { rel: "icon", type: "image/svg+xml", href: `${siteBase}logo.svg` }],
  ],
  themeConfig: {
    logo: "/logo.svg",
    siteTitle: "Vigilyx",
    search: {
      provider: "local",
    },
    nav: [
      { text: "Guide", link: "/docs/" },
      { text: "Quick Start", link: "/docs/quick-start" },
      { text: "Deployment", link: "/docs/deployment" },
      { text: "Architecture", link: "/docs/architecture" },
      { text: "Project Site", link: "/docs/project-site" },
      { text: "GitHub", link: "https://github.com/HerbiusYang/Vigilyx" },
    ],
    sidebar: {
      "/docs/": [
        {
          text: "Get Started",
          items: [
            { text: "Overview", link: "/docs/" },
            { text: "Quick Start", link: "/docs/quick-start" },
            { text: "Deployment", link: "/docs/deployment" },
            { text: "Architecture", link: "/docs/architecture" },
            { text: "Project Site", link: "/docs/project-site" },
          ],
        },
      ],
    },
    socialLinks: [
      { icon: "github", link: "https://github.com/HerbiusYang/Vigilyx" },
    ],
    footer: {
      message: "Released under AGPL-3.0-only.",
      copyright: "Copyright © 2026 Vigilyx contributors",
    },
    docFooter: {
      prev: "Previous",
      next: "Next",
    },
    outline: {
      label: "On this page",
    },
  },
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
