import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const siteRoot = path.resolve(currentDir, "..");
const distDir = path.join(siteRoot, ".vitepress", "dist");

function ensureTrailingSlash(value) {
  return value.endsWith("/") ? value : `${value}/`;
}

const siteUrl = ensureTrailingSlash(
  process.env.SITE_URL ?? "https://herbiusyang.github.io/Vigilyx/"
);
const customDomain = (process.env.SITE_CUSTOM_DOMAIN ?? "").trim();

await mkdir(distDir, { recursive: true });

const robots = [
  "User-agent: *",
  "Allow: /",
  "",
  `Sitemap: ${new URL("sitemap.xml", siteUrl).toString()}`,
  "",
].join("\n");

await writeFile(path.join(distDir, "robots.txt"), robots, "utf8");

if (customDomain) {
  await writeFile(path.join(distDir, "CNAME"), `${customDomain}\n`, "utf8");
}
