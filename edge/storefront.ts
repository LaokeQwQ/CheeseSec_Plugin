import page from "../storefront/index.html";
import styles from "../storefront/storefront.css";
import script from "../storefront/storefront.js";
import catalog from "../storefront/catalog.mjs";
import logo from "../storefront/logo.png";
import pluginsLogo from "../storefront/plugins-logo.svg";
import { methodNotAllowed } from "./response-policy";

const assets = new Map<string, { body: string | Uint8Array; type: string }>([
  ["/", { body: page, type: "text/html; charset=utf-8" }],
  ["/storefront.css", { body: styles, type: "text/css; charset=utf-8" }],
  ["/storefront.js", { body: script, type: "text/javascript; charset=utf-8" }],
  ["/catalog.mjs", { body: catalog, type: "text/javascript; charset=utf-8" }],
  ["/logo.png", { body: logo, type: "image/png" }],
  ["/plugins-logo.svg", { body: pluginsLogo, type: "image/svg+xml" }],
  ["/favicon.ico", { body: logo, type: "image/png" }],
]);

export function serveStorefront(request: Request): Response | null {
  const url = new URL(request.url);
  if (url.hostname !== "store.cheesesec.com") return null;
  const asset = assets.get(url.pathname);
  if (!asset) return null;
  if (request.method !== "GET" && request.method !== "HEAD") return methodNotAllowed();
  const headers = new Headers({
    "content-type": asset.type,
    "content-length": String(typeof asset.body === "string" ? new TextEncoder().encode(asset.body).byteLength : asset.body.byteLength),
    "cache-control": "public, max-age=60, must-revalidate",
    "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
  });
  return new Response(request.method === "HEAD" ? null : asset.body, { headers });
}
