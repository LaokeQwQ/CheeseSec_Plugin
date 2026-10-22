import { normalizeCatalog, filterCatalog } from "/catalog.mjs";

const copy = {
  zh: {
    skip: "跳到插件目录", store: "插件商店", explore: "发现插件", docs: "文档",
    heroTitle: "为每一种防护，\n找到合适的扩展。", heroDescription: "面向 CheeseSec 全生态的独立插件，在不同产品间扩展你的安全工具。",
    learnPlugins: "了解 CheeseSec 插件", categories: "分类", categoryAll: "全部插件", categorySecurity: "检测与防护", categoryIntelligence: "威胁情报", categoryNotifications: "通知与集成", categoryAnalysis: "分析与审计", categoryTools: "开发工具",
    sidebarNote: "有一个好想法？\n从开发你的第一个插件开始。", developerGuide: "开发指南", sortLabel: "排序方式", sortNewest: "最近发布", sortName: "名称排序", catalogCaption: "适合你的下一份能力",
    loadingTitle: "正在查看插件目录", loadingDescription: "稍等片刻，新的能力正在加载。", emptyTitle: "暂无已发布插件", emptyDescription: "第一批插件正在准备中。你可以先了解插件的使用方式，或开始开发自己的扩展。",
    noResultsTitle: "没有找到匹配的插件", noResultsDescription: "换一个关键词，或清除筛选看看其他插件。", errorTitle: "暂时无法读取插件目录", errorDescription: "请检查网络连接，然后重新加载。", retry: "重新加载", resetFilters: "清除筛选",
    gettingStarted: "从这里开始", guideTitle: "认识插件，找到更多可能", guideDescription: "使用说明、发布方式与安全边界，一处读懂。", buildTogether: "和我们一起创造", buildTitle: "把你的想法，变成一个插件", buildDescription: "阅读开发指南，从一个清晰的小能力开始。",
    footerNote: "让安全的能力，触手可及。", catalogApi: "目录 API", detailNote: "请在插件说明中确认适用的 CheeseSec 产品、兼容版本与安装方式。", viewDocs: "查看使用文档",
    searchPlaceholder: "搜索插件名称或发布者", searchLabel: "搜索插件", clearSearch: "清除搜索", themeLight: "切换浅色模式", themeDark: "切换深色模式", closeDialog: "关闭详情", homeLabel: "CheeseSec 首页", navigation: "主导航", detailsLabel: "查看插件详情", version: "版本", publisher: "发布者", packageSize: "资源大小", releaseSequence: "发布序号", digest: "SHA-256 摘要",
    trustOfficial: "官方", trustEnterprise: "企业", trustCommunity: "社区", trustPersonal: "个人", trustTest: "测试", trustDevelopment: "开发",
    lifecycleDescription: "生命周期示例，不提供防护能力。", lifecycleDetails: "这个示例仅用于验证启动、健康检查和停止流程，不检测攻击，也不采集数据。", compatibility: "适用平台", platformLinux: "仅支持 Linux amd64。", platformMac: "仅支持 macOS arm64（Apple 芯片）。", downloadPackage: "下载 .crp 包", verificationGuide: "签名校验说明", compatibilityGuide: "兼容性与安装说明",
  },
  en: {
    skip: "Skip to plugin catalog", store: "Plugin store", explore: "Explore", docs: "Documentation",
    heroTitle: "A little more power.\nA whole new possibility.", heroDescription: "Independent plugins for the CheeseSec ecosystem. Extend your security tools across products.",
    learnPlugins: "Meet CheeseSec plugins", categories: "CATEGORIES", categoryAll: "All plugins", categorySecurity: "Detection & protection", categoryIntelligence: "Threat intelligence", categoryNotifications: "Notifications & integrations", categoryAnalysis: "Analysis & audit", categoryTools: "Developer tools",
    sidebarNote: "Have an idea?\nStart with your first plugin.", developerGuide: "Developer guide", sortLabel: "Sort plugins", sortNewest: "Latest releases", sortName: "Name, A–Z", catalogCaption: "Find your next capability",
    loadingTitle: "Opening the plugin catalog", loadingDescription: "Just a moment. More possibilities are on their way.", emptyTitle: "The first plugins are on their way", emptyDescription: "There are no published plugins yet. Explore how plugins work, or start creating an extension of your own.",
    noResultsTitle: "No matching plugins", noResultsDescription: "Try another search, or clear your filters to see more plugins.", errorTitle: "The catalog could not be loaded", errorDescription: "Check your connection, then try loading it again.", retry: "Try again", resetFilters: "Clear filters",
    gettingStarted: "A GOOD PLACE TO START", guideTitle: "Get to know plugins", guideDescription: "Learn how plugins work, how they are released, and how to use them safely.", buildTogether: "LET’S BUILD SOMETHING", buildTitle: "Make your idea a plugin", buildDescription: "Open the developer guide. Start with one useful capability.",
    footerNote: "More possibilities. The same care for security.", catalogApi: "Catalog API", detailNote: "Check the plugin documentation for supported CheeseSec products, compatible versions, and installation steps.", viewDocs: "Read the documentation",
    searchPlaceholder: "Search plugin names or publishers", searchLabel: "Search plugins", clearSearch: "Clear search", themeLight: "Use light theme", themeDark: "Use dark theme", closeDialog: "Close plugin details", homeLabel: "CheeseSec home", navigation: "Main navigation", detailsLabel: "View plugin details", version: "Version", publisher: "Publisher", packageSize: "Package size", releaseSequence: "Release sequence", digest: "SHA-256 digest",
    trustOfficial: "Official", trustEnterprise: "Enterprise", trustCommunity: "Community", trustPersonal: "Personal", trustTest: "Test", trustDevelopment: "Development",
    lifecycleDescription: "Lifecycle example. No protection capabilities.", lifecycleDetails: "This example only checks startup, health, and shutdown. It does not detect attacks or collect data.", compatibility: "Supported platform", platformLinux: "Linux amd64 only.", platformMac: "macOS arm64 (Apple silicon) only.", downloadPackage: "Download .crp package", verificationGuide: "Signature verification", compatibilityGuide: "Compatibility & installation",
  },
};

const categoryKeys = { all: "categoryAll", security: "categorySecurity", intelligence: "categoryIntelligence", notifications: "categoryNotifications", analysis: "categoryAnalysis", tools: "categoryTools" };
const categoryIcons = { security: "shield", intelligence: "radar", notifications: "bell", analysis: "chart", tools: "code" };
const trustKeys = { official: "trustOfficial", enterprise: "trustEnterprise", community: "trustCommunity", personal: "trustPersonal", test: "trustTest", development: "trustDevelopment" };
const byId = id => document.getElementById(id);
const readPreference = key => { try { return localStorage.getItem(key); } catch { return null; } };
const savePreference = (key, value) => { try { localStorage.setItem(key, value); } catch { /* Preferences are optional. */ } };
const preferredLanguage = readPreference("cheesesec-store-language");
const state = {
  language: preferredLanguage === "zh" || preferredLanguage === "en" ? preferredLanguage : navigator.language.toLowerCase().startsWith("zh") ? "zh" : "en",
  theme: readPreference("cheesesec-store-theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"),
  category: "all", query: "", sort: "newest", plugins: [], status: "loading", currentPlugin: null,
};
if (!["light", "dark"].includes(state.theme)) state.theme = "light";
const t = key => copy[state.language][key] || key;
const docsRoot = () => `https://docs.cheesesec.com/${state.language === "zh" ? "zh/" : ""}docs/plugins/`;

function textLines(element, value) {
  const lines = String(value).split("\n");
  element.replaceChildren();
  lines.forEach((line, index) => {
    if (index) element.append(document.createElement("br"));
    element.append(document.createTextNode(line));
  });
}

function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.classList.add("icon");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `#icon-${name}`);
  svg.append(use);
  return svg;
}

function applyLanguage() {
  document.documentElement.lang = state.language === "zh" ? "zh-CN" : "en";
  document.title = state.language === "zh" ? "CheeseSec · 插件商店" : "CheeseSec · Plugin store";
  document.querySelectorAll("[data-i18n]").forEach(element => textLines(element, t(element.dataset.i18n)));
  document.querySelectorAll(".docs-link").forEach(link => { link.href = docsRoot(); });
  document.querySelectorAll(".developer-link").forEach(link => { link.href = docsRoot(); });
  byId("plugin-search").placeholder = t("searchPlaceholder");
  byId("plugin-search").setAttribute("aria-label", t("searchLabel"));
  byId("clear-search").setAttribute("aria-label", t("clearSearch"));
  byId("sort-select").setAttribute("aria-label", t("sortLabel"));
  byId("close-dialog").setAttribute("aria-label", t("closeDialog"));
  document.querySelector(".brand").setAttribute("aria-label", t("homeLabel"));
  document.querySelector(".top-nav").setAttribute("aria-label", t("navigation"));
  byId("categories").setAttribute("aria-label", t("categories"));
  document.querySelector(".catalog-sidebar").setAttribute("aria-label", t("categories"));
  byId("language-toggle").textContent = state.language === "zh" ? "EN" : "中文";
  byId("language-toggle").setAttribute("aria-label", state.language === "zh" ? "Switch to English" : "切换到简体中文");
  updateTheme();
  render();
  if (state.currentPlugin && byId("plugin-dialog").open) fillDetails(state.currentPlugin);
}

function updateTheme() {
  document.documentElement.dataset.theme = state.theme;
  byId("theme-toggle").setAttribute("aria-label", t(state.theme === "dark" ? "themeLight" : "themeDark"));
  document.querySelector('meta[name="theme-color"]').content = state.theme === "dark" ? "#1b1b16" : "#fdfaf2";
}

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function renderCard(plugin) {
  const card = makeElement("button", "plugin-card");
  card.type = "button";
  card.setAttribute("aria-label", `${t("detailsLabel")}: ${plugin.name}`);
  const top = makeElement("div", "plugin-card-top");
  const glyph = makeElement("span", "plugin-card-icon");
  glyph.append(icon(plugin.lifecycleExample ? "puzzle" : categoryIcons[plugin.category] || "puzzle"));
  top.append(glyph, makeElement("span", "trust-chip", t(trustKeys[plugin.trustLevel] || "trustCommunity")));
  const bottom = makeElement("div", "plugin-card-bottom");
  bottom.append(makeElement("span", "plugin-card-version", `v${plugin.version}`), icon("arrow"));
  card.append(top, makeElement("h3", "", plugin.name));
  if (plugin.lifecycleExample) {
    card.append(makeElement("span", "platform-chip", plugin.lifecycleExample.platformLabel));
    card.append(makeElement("p", "plugin-purpose", t("lifecycleDescription")));
  } else card.append(makeElement("p", "", t(categoryKeys[plugin.category] || "categoryTools")));
  card.append(bottom);
  card.addEventListener("click", () => {
    state.currentPlugin = plugin;
    fillDetails(plugin);
    byId("plugin-dialog").showModal();
  });
  return card;
}

function setCatalogState(kind) {
  const section = byId("catalog-state");
  section.dataset.state = kind;
  section.hidden = kind === "results";
  const titleKeys = { loading: "loadingTitle", empty: "emptyTitle", noResults: "noResultsTitle", error: "errorTitle" };
  const descriptionKeys = { loading: "loadingDescription", empty: "emptyDescription", noResults: "noResultsDescription", error: "errorDescription" };
  if (kind !== "results") {
    byId("state-title").textContent = t(titleKeys[kind]);
    byId("state-description").textContent = t(descriptionKeys[kind]);
  }
  byId("state-icon").replaceChildren(icon(kind === "error" ? "error" : kind === "noResults" ? "search" : "puzzle").firstElementChild);
  byId("retry-button").hidden = kind !== "error";
  byId("state-docs").hidden = kind !== "empty";
  byId("reset-filters").hidden = kind !== "noResults";
}

function render() {
  const grid = byId("plugin-grid");
  const filtered = filterCatalog(state.plugins, { query: state.query, category: state.category, sort: state.sort });
  byId("catalog-title").textContent = t(categoryKeys[state.category]);
  byId("result-count").textContent = state.status === "loading" ? "—" : String(filtered.length);
  byId("clear-search").hidden = state.query.length === 0;
  document.querySelectorAll("[data-category]").forEach(button => {
    const selected = button.dataset.category === state.category;
    button.classList.toggle("selected", selected);
    button.setAttribute("aria-pressed", String(selected));
  });
  grid.replaceChildren();
  byId("catalog").setAttribute("aria-busy", String(state.status === "loading"));
  if (state.status === "loading") { setCatalogState("loading"); return; }
  if (state.status === "error") { setCatalogState("error"); return; }
  if (state.plugins.length === 0) { setCatalogState("empty"); return; }
  if (filtered.length === 0) { setCatalogState("noResults"); return; }
  setCatalogState("results");
  filtered.forEach(plugin => grid.append(renderCard(plugin)));
}

function fillDetails(plugin) {
  byId("detail-title").textContent = plugin.name;
  byId("detail-namespace").textContent = plugin.namespace;
  byId("detail-trust").textContent = t(trustKeys[plugin.trustLevel] || "trustCommunity");
  const fields = [["version", plugin.version], ["publisher", plugin.source], ["packageSize", formatSize(plugin.size)], ["releaseSequence", String(plugin.releaseSequence)], ["digest", plugin.sha256]];
  if (plugin.lifecycleExample) fields.unshift(["compatibility", plugin.lifecycleExample.platformLabel]);
  const metadata = byId("detail-metadata");
  metadata.replaceChildren();
  fields.forEach(([label, value]) => { metadata.append(makeElement("dt", "", t(label)), makeElement("dd", "", value)); });
  const lifecycle = byId("detail-lifecycle");
  lifecycle.hidden = !plugin.lifecycleExample;
  lifecycle.replaceChildren();
  if (plugin.lifecycleExample) {
    lifecycle.append(makeElement("strong", "", t("lifecycleDescription")), makeElement("p", "", t("lifecycleDetails")), makeElement("p", "detail-platform", t(plugin.lifecycleExample.platform === "linux-amd64" ? "platformLinux" : "platformMac")));
  }
  const download = byId("detail-download");
  download.href = plugin.downloadUrl;
  download.setAttribute("download", plugin.downloadUrl.split("/").at(-1));
  download.setAttribute("aria-label", `${t("downloadPackage")}: ${plugin.name}${plugin.lifecycleExample ? ` · ${plugin.lifecycleExample.platformLabel}` : ""}`);
}

function formatSize(value) {
  if (!Number.isFinite(value) || value < 0) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let index = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
  return new Intl.NumberFormat(state.language === "zh" ? "zh-CN" : "en", { maximumFractionDigits: index ? 1 : 0 }).format(value) + " " + units[index];
}

let requestVersion = 0;
async function loadCatalog() {
  const version = ++requestVersion;
  state.status = "loading";
  render();
  try {
    const response = await fetch("/v1/catalog/index.json", { credentials: "omit", redirect: "error", cache: "no-store", headers: { Accept: "application/json" }, signal: AbortSignal.timeout(10000) });
    if (!response.ok || !response.headers.get("content-type")?.toLowerCase().includes("application/json")) throw new Error("catalog unavailable");
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > 1024 * 1024) throw new Error("catalog too large");
    const { plugins } = normalizeCatalog(JSON.parse(text));
    if (version !== requestVersion) return;
    state.plugins = plugins;
    state.status = "ready";
  } catch {
    if (version !== requestVersion) return;
    state.status = "error";
    state.plugins = [];
  }
  render();
}

byId("language-toggle").addEventListener("click", () => {
  state.language = state.language === "zh" ? "en" : "zh";
  savePreference("cheesesec-store-language", state.language);
  applyLanguage();
});
byId("theme-toggle").addEventListener("click", () => {
  state.theme = state.theme === "dark" ? "light" : "dark";
  savePreference("cheesesec-store-theme", state.theme);
  updateTheme();
});
byId("search-form").addEventListener("submit", event => { event.preventDefault(); state.query = byId("plugin-search").value.trim(); render(); });
byId("plugin-search").addEventListener("input", () => { state.query = byId("plugin-search").value.trim(); render(); });
byId("clear-search").addEventListener("click", () => { state.query = ""; byId("plugin-search").value = ""; render(); byId("plugin-search").focus(); });
byId("sort-select").addEventListener("change", event => { state.sort = event.target.value; render(); });
document.querySelectorAll("[data-category]").forEach(button => button.addEventListener("click", () => { state.category = button.dataset.category; render(); }));
byId("retry-button").addEventListener("click", loadCatalog);
byId("reset-filters").addEventListener("click", () => { state.query = ""; state.category = "all"; byId("plugin-search").value = ""; render(); byId("plugin-search").focus(); });
byId("close-dialog").addEventListener("click", () => byId("plugin-dialog").close());
byId("plugin-dialog").addEventListener("click", event => { if (event.target === byId("plugin-dialog")) { const bounds = event.target.getBoundingClientRect(); if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) event.target.close(); } });
byId("plugin-dialog").addEventListener("close", () => { state.currentPlugin = null; });
applyLanguage();
loadCatalog();
