import brandLogo from "../storefront/cheesesec-logo.png";
import { forbiddenResponse, methodNotAllowed, notFoundResponse } from "./response-policy";
import { readServiceCounters, serviceForHost, withDeadline, type CounterSnapshot, type ServiceName } from "./service-counters";

type Probe = {
  id: string;
  status: "available" | "unavailable";
  checked_at: string;
  detail: string;
};
type ServiceStatus = {
  api_version: "cheesesec.com/service-status/v1";
  service: ServiceName;
  hostname: string;
  status: "operational" | "degraded";
  checked_at: string;
  probes: Probe[];
  counters: CounterSnapshot;
  counting: typeof COUNTING;
};

const COUNTING = {
  visits: "Successful GET service requests (2xx or 304), including status pages; status JSON, UI assets, HEAD and failed requests are excluded. Requests are not unique people.",
  downloads: "Resource GET responses with status 200 or 206 and a valid Content-Length. HEAD, 304 and failed responses are excluded. Each range response is one response, not one unique download.",
  transferred_bytes: "Sum of Content-Length for counted resource responses; ranges use their response length. This measures bytes offered by the service, not confirmed client receipt or files saved to disk.",
  persistence: "Durable Object SQLite totals per service since started_at; asynchronous delivery accounting may lag or undercount if the counter service is unavailable. Earlier traffic is not backfilled.",
  privacy: "Only service name, aggregate counters and timestamps are stored. No IP addresses, user agents, URLs, cookies or visitor identifiers are collected by these counters.",
} as const;
const TITLES: Record<ServiceName, string> = { store: "插件商店", ota: "更新分发", res: "公共资源" };
const DESCRIPTIONS: Record<ServiceName, string> = {
  store: "发现生态扩展，读取可信插件目录。",
  ota: "为 CheeseWAF 与 CRP 插件提供版本和更新索引。",
  res: "分发不可变发布包、签名与公开资源。",
};
const RESOURCE_PROBE_KEY = "releases/v0.4.5/SHA256SUMS";
const brandDataUrl = `data:image/png;base64,${btoa(String.fromCharCode(...brandLogo))}`;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

async function metadataProbe(bucket: R2Bucket | undefined, key: string, id: string): Promise<Probe> {
  try {
    if (!bucket) throw new Error();
    const object = await withDeadline(bucket.head(key));
    if (!object || object.size <= 0) throw new Error();
    return { id, status: "available", checked_at: new Date().toISOString(), detail: "关键发布对象可读取" };
  } catch {
    return { id, status: "unavailable", checked_at: new Date().toISOString(), detail: "关键发布对象缺失或暂时无法读取" };
  }
}

async function indexProbe(env: Env, key: string, id: "crp-stable" | "software-stable"): Promise<Probe> {
  try {
    if (!env.PUBLICATION_INDEX) throw new Error();
    const data: unknown = await withDeadline((async () => {
      const object = await env.PUBLICATION_INDEX.get(key);
      // Read only small publication indexes, never release bodies or an
      // arbitrary user-selected R2 object. Reject oversized/malformed indexes.
      if (!object || !object.size || object.size > 262144 || !("body" in object)) throw new Error();
      return new Response(object.body).json();
    })());
    if (!isRecord(data)) throw new Error();
    let detail: string;
    if (id === "crp-stable") {
      if (data.api_version !== "ota.cheesesec.com/v1" || !Number.isSafeInteger(data.index_sequence)
        || (data.index_sequence as number) < 0 || !Array.isArray(data.releases)
        || data.mode !== "pull-only") throw new Error();
      detail = data.releases.length ? `CRP 稳定通道：${data.releases.length} 条发布记录` : "CRP 稳定通道可用 · 暂无更新";
    } else {
      if (data.api_version !== "ota.cheesesec.com/software/v1" || data.channel !== "stable"
        || typeof data.tag_name !== "string" || !/^v\d+\.\d+\.\d+$/.test(data.tag_name)
        || !Array.isArray(data.assets) || !data.assets.length || !data.assets.every(asset =>
          isRecord(asset) && typeof asset.name === "string" && /^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(asset.name)
          && Number.isSafeInteger(asset.size) && (asset.size as number) > 0
          && typeof asset.sha256 === "string" && /^[a-f0-9]{64}$/.test(asset.sha256)
          && asset.url === `https://res.cheesesec.com/releases/${data.tag_name}/${asset.name}`)) throw new Error();
      detail = `CheeseWAF 稳定版本 ${data.tag_name}`;
    }
    return { id, status: "available", checked_at: new Date().toISOString(), detail };
  } catch {
    return { id, status: "unavailable", checked_at: new Date().toISOString(), detail: "更新索引缺失、格式无效或暂时无法读取" };
  }
}

async function getStatus(env: Env, service: ServiceName, hostname: string, visit: boolean): Promise<ServiceStatus> {
  const probesPromise = service === "store"
    ? Promise.all([metadataProbe(env.PUBLICATION_INDEX, "catalog/index.json", "catalog")])
    : service === "ota"
      ? Promise.all([
        indexProbe(env, "ota/channels/stable/index.json", "crp-stable"),
        indexProbe(env, "software/channels/stable/index.json", "software-stable"),
      ])
      : Promise.all([metadataProbe(env.PUBLIC_RESOURCES, RESOURCE_PROBE_KEY, "release-checksums")]);
  const [probes, counters] = await Promise.all([probesPromise, readServiceCounters(env, service, visit)]);
  return {
    api_version: "cheesesec.com/service-status/v1", service, hostname,
    status: probes.every(probe => probe.status === "available") && counters.available ? "operational" : "degraded",
    checked_at: new Date().toISOString(), probes, counters, counting: COUNTING,
  };
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]!);
}

function number(value: number | null): string {
  return value === null ? "—" : value.toLocaleString("zh-CN");
}

function bytes(value: number | null): string {
  if (value === null) return "—";
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB", "PiB"];
  const power = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length);
  return `${(value / 1024 ** power).toLocaleString("zh-CN", { maximumFractionDigits: 2 })} ${units[power - 1]}`;
}

const CSS = `:root{color-scheme:light;--surface:#fdfaf2;--card:#fffdf7;--container:#f1eee4;--ink:#25251f;--muted:#66655b;--line:#dddbcf;--primary:#775a00;--yellow:#ffe28c;--green:#e4ece1;--green-ink:#3c5946;--warning:#ffedd1;--warning-ink:#745219}*{box-sizing:border-box}body{margin:0;background:var(--surface);color:var(--ink);font:15px/1.7 "Avenir Next","Segoe UI Variable Text","PingFang SC","Microsoft YaHei",sans-serif}a{color:inherit;text-decoration:none}a:focus-visible{outline:3px solid var(--primary);outline-offset:5px}header,main,footer{max-width:1080px;margin:auto;padding:0 32px}header{height:88px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);gap:20px}.brand{display:flex;align-items:center;gap:12px;font-size:21px;font-weight:700;letter-spacing:-.5px}.brand img{width:40px;height:40px;object-fit:contain}nav{display:flex;gap:24px;color:var(--muted);font-size:13px}nav a{min-height:44px;display:inline-flex;align-items:center}nav a[aria-current]{color:var(--primary)}main{padding-top:64px;padding-bottom:48px}.eyebrow{font-size:11px;letter-spacing:2px;color:var(--muted);margin:0 0 16px}.hero{display:flex;justify-content:space-between;align-items:flex-start;gap:24px}h1{font-size:clamp(34px,5vw,48px);letter-spacing:-1.8px;line-height:1.25;margin:0 0 18px;font-weight:650}.description{color:var(--muted);margin:0;max-width:570px}.hostname{font:12px/1.8 ui-monospace,"SFMono-Regular",monospace;color:var(--muted);overflow-wrap:anywhere;margin-top:18px}.state{display:inline-flex;align-items:center;gap:10px;white-space:nowrap;border-radius:999px;padding:11px 18px;background:var(--green);color:var(--green-ink);font-size:14px;font-weight:600}.state.degraded{background:var(--warning);color:var(--warning-ink)}.dot{width:8px;height:8px;border-radius:50%;background:currentColor}.metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin:40px 0 28px}.metric{border:1px solid var(--line);border-radius:26px;background:var(--card);padding:25px 26px;min-width:0}.metric p{font-size:12px;color:var(--muted);margin:0 0 14px}.value{font-size:clamp(26px,3.4vw,38px);font-weight:600;letter-spacing:-1.1px;line-height:1.3;overflow-wrap:anywhere}.metric small{display:block;margin-top:10px;font-size:11px;color:var(--muted)}.panel{background:var(--container);border-radius:26px;padding:28px 30px;margin-top:18px}h2{font-size:17px;letter-spacing:-.3px;margin:0 0 18px}.probe{display:flex;align-items:center;justify-content:space-between;gap:24px;padding:15px 0;border-top:1px solid var(--line)}.probe p{margin:0;font-size:13px}.probe span{font-size:12px;color:var(--green-ink);white-space:nowrap}.probe .unavailable{color:var(--warning-ink)}.meta{color:var(--muted);font-size:12px;margin:12px 0 0}.actions{display:flex;flex-wrap:wrap;align-items:center;gap:10px 24px;margin-top:24px;font-size:13px;color:var(--primary)}.button{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:10px 23px;border-radius:999px;background:var(--primary);color:var(--card);font-weight:600}.notes{margin:0;padding-left:20px;font-size:12px;color:var(--muted);display:grid;gap:9px}.notice{color:var(--warning-ink);font-size:13px;margin:0 0 20px}footer{display:flex;justify-content:space-between;gap:20px;padding-top:24px;padding-bottom:30px;border-top:1px solid var(--line);font-size:11px;color:var(--muted)}footer a{color:var(--primary)}@media(prefers-color-scheme:dark){:root{color-scheme:dark;--surface:#1b1b16;--card:#24241e;--container:#292921;--ink:#e8e5d8;--muted:#c6c3b5;--line:#434338;--primary:#e9c360;--yellow:#594400;--green:#2b3c31;--green-ink:#bfd6c1;--warning:#493b21;--warning-ink:#ecd09a}.button{color:#3e2f00}}@media(max-width:680px){header,main,footer{padding-left:20px;padding-right:20px}header{height:76px}nav{gap:14px;font-size:12px}.brand{font-size:19px;gap:8px}.brand img{width:34px;height:34px}main{padding-top:38px}.hero{display:block}.state{margin-top:24px}.metrics{grid-template-columns:1fr;margin-top:28px;gap:12px}.metric{padding:20px 23px;display:grid;grid-template-columns:1fr auto;gap:0 15px;align-items:center}.metric p{margin:0}.value{font-size:29px;grid-column:2;grid-row:1 / span 2}.metric small{margin-top:4px}.panel{padding:23px}.probe{align-items:flex-start;gap:12px}footer{flex-wrap:wrap}}`;

function renderPage(status: ServiceStatus): string {
  const operational = status.status === "operational";
  const { counters, service } = status;
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#fdfaf2"><meta name="description" content="CheeseSec ${TITLES[service]}服务状态与累计服务统计"><title>CheeseSec · ${TITLES[service]}状态</title><link rel="icon" href="${brandDataUrl}"><style>${CSS}</style></head><body>
<header><a class="brand" href="https://cheesesec.com/" aria-label="CheeseSec 首页"><img src="${brandDataUrl}" width="40" height="40" alt=""><span>CheeseSec</span></a><nav aria-label="服务导航">${(["store", "ota", "res"] as const).map(name => `<a href="https://${name}.cheesesec.com/${name === "store" ? "status" : ""}"${name === service ? ' aria-current="page"' : ""}>${TITLES[name]}</a>`).join("")}</nav></header>
<main><p class="eyebrow">CHEESESEC SERVICE STATUS</p><section class="hero" aria-labelledby="title"><div><h1 id="title">${TITLES[service]}，<br>每一次连接都有回应。</h1><p class="description">${DESCRIPTIONS[service]} 在这里查看当前发布服务状态与启用统计以来的累计数据。</p><p class="hostname">${status.hostname}</p></div><div class="state${operational ? "" : " degraded"}" role="status"><span class="dot" aria-hidden="true"></span>${operational ? "服务正常" : "服务降级"}</div></section>
<section class="metrics" aria-label="累计服务统计"><article class="metric"><p>累计访问</p><div class="value">${number(counters.visits)}</div><small>成功的 GET 服务请求</small></article><article class="metric"><p>累计下载响应</p><div class="value">${number(counters.downloads)}</div><small>资源 GET 200 / 206 响应</small></article><article class="metric"><p>累计分发量</p><div class="value" title="${number(counters.transferred_bytes)} bytes">${bytes(counters.transferred_bytes)}</div><small>按响应声明的字节数累计</small></article></section>
${counters.available ? "" : '<p class="notice" role="status">累计统计暂时不可读取，显示为「—」。资源分发继续独立运行。</p>'}
<section class="panel" aria-labelledby="checks"><h2 id="checks">发布服务检查</h2>${status.probes.map(probe => `<div class="probe"><p>${escapeHtml(probe.detail)}</p><span class="${probe.status}">${probe.status === "available" ? "可用" : "待恢复"}</span></div>`).join("")}<p class="meta">检查时间 <time datetime="${status.checked_at}">${status.checked_at}</time> · 检查关键 R2 发布数据，不代表所有历史版本或完整业务链路。</p><div class="actions"><a class="button" href="/status">刷新状态</a><a href="/v1/status.json">查看 JSON API ↗</a>${service === "ota" ? '<a href="/v1/software/channels/stable/index.json">软件稳定通道 ↗</a>' : service === "store" ? '<a href="/">进入插件商店 ↗</a>' : '<a href="/releases/v0.4.5/SHA256SUMS">发布校验清单 ↗</a>'}</div></section>
<section class="panel" aria-labelledby="counting"><h2 id="counting">这些数字如何累计</h2><ul class="notes"><li>统计起点：${counters.started_at ? `<time datetime="${counters.started_at}">${counters.started_at}</time>` : "暂时无法读取"}。仅累计启用后的请求，历史流量不追补；各服务分别保存。</li><li>访问按成功的 GET 服务请求累计，包含本状态页。状态 JSON、网页静态资源、HEAD 和失败请求不计入；访问次数不等于独立用户数。</li><li>下载按资源 GET 的 200 / 206 响应累计。Range 分段各算一次响应，按该段 Content-Length 计量；HEAD、304、失败请求不增加下载或分发量。</li><li>分发量表示服务提供的响应字节，不代表客户端完整接收或已保存到磁盘。统计异步写入，短时可能延后；统计服务故障时可能少计。</li><li>累计值持久保存。仅保存服务名称、聚合数字和时间，不收集 IP、User-Agent、URL、Cookie 或访客标识。</li></ul></section></main><footer><span>CheeseSec · 让安全的能力，触手可及。</span><a href="https://docs.cheesesec.com/zh/">使用文档 ↗</a></footer></body></html>`;
}

export async function serveServiceStatus(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  const service = serviceForHost(url.hostname);
  if (!service) return null;
  const json = url.pathname === "/v1/status.json";
  const page = url.pathname === "/status" || url.pathname === "/status/" || (url.pathname === "/" && service !== "store");
  if (!json && !page) return null;
  const rawPath = request.url.match(/^[a-z][a-z\d+.-]*:\/\/[^/]*(\/[^?#]*)?/i)?.[1] ?? "/";
  if (rawPath !== url.pathname || /%(?:2f|5c|2e)|\\|\/\//i.test(rawPath)) return notFoundResponse();
  if (url.username || url.password || request.headers.has("authorization") || request.headers.has("x-csrf-token")
    || (json && request.headers.has("cookie"))
    || [...url.searchParams.keys()].some(key => /^(?:access[_-]?token|api[_-]?key|authorization|cookie|credential|csrf|secret|signature|token)$/i.test(key))) return forbiddenResponse();
  if (request.method !== "GET" && request.method !== "HEAD") return methodNotAllowed();
  const status = await getStatus(env, service, url.hostname, page && request.method === "GET");
  const body = json ? JSON.stringify(status) : renderPage(status);
  const headers = new Headers({
    "content-type": json ? "application/json; charset=utf-8" : "text/html; charset=utf-8",
    "content-length": String(new TextEncoder().encode(body).byteLength),
    "cache-control": "no-store", "cdn-cache-control": "no-store",
    "x-content-type-options": "nosniff", "x-frame-options": "DENY",
    "referrer-policy": "no-referrer", "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "content-security-policy": "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  });
  return new Response(request.method === "HEAD" ? null : body, { status: 200, headers });
}
