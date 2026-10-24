import assert from "node:assert/strict";
import { before, test } from "node:test";
import { fileURLToPath } from "node:url";

let worker;
before(async () => {
  const { build } = await import(process.env.CHEESESEC_ESBUILD_MODULE || "esbuild");
  const result = await build({
    entryPoints: [fileURLToPath(new URL("./index.ts", import.meta.url))], bundle: true,
    format: "esm", platform: "browser", write: false, tsconfigRaw: {},
    loader: { ".html": "text", ".css": "text", ".js": "text", ".mjs": "text", ".png": "binary", ".svg": "text" },
  });
  worker = (await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString("base64")}`)).default;
});

function fixture() {
  const calls = [];
  const rows = new Map();
  const pending = [];
  const metadata = (key, size = 10) => ({ key, size, etag: "fixture", httpEtag: '"fixture"', uploaded: new Date("2026-10-22T00:00:00Z"), writeHttpMetadata() {} });
  const env = {
    EDGE_POLICY_VERSION: "test",
    SERVICE_COUNTERS: {
      idFromName(name) { calls.push(["counter-name", name]); return name; },
      get(name) {
        return { async fetch(url, init) {
          const input = JSON.parse(init.body);
          calls.push(["counter", name, new URL(url).pathname, input]);
          const row = rows.get(name) ?? { service: input.service, started_at: "2026-10-24T00:00:00.000Z", updated_at: "2026-10-24T00:00:00.000Z", visits: 0, downloads: 0, transferred_bytes: 0 };
          if (input.delta) for (const key of ["visits", "downloads", "transferred_bytes"]) row[key] += input.delta[key];
          rows.set(name, row);
          return Response.json(row);
        } };
      },
    },
    PUBLICATION_INDEX: {
      async head(key) { calls.push(["publication-head", key]); return metadata(key); },
      async get(key) {
        calls.push(["publication-get", key]);
        const data = key.startsWith("software/")
          ? { api_version: "ota.cheesesec.com/software/v1", channel: "stable", tag_name: "v0.4.5", assets: [{ name: "archive.tar.gz", size: 10, sha256: "a".repeat(64), url: "https://res.cheesesec.com/releases/v0.4.5/archive.tar.gz" }] }
          : { api_version: "ota.cheesesec.com/v1", index_sequence: 0, mode: "pull-only", releases: [] };
        const body = JSON.stringify(data);
        return { ...metadata(key, Buffer.byteLength(body)), body: new Response(body).body };
      },
    },
    PUBLIC_RESOURCES: {
      async head(key) { calls.push(["resource-head", key]); return metadata(key); },
      async get(key, options) {
        calls.push(["resource-get", key, options]);
        const body = "0123456789";
        const range = options?.range;
        return { ...metadata(key), body: new Response(range ? body.slice(range.offset, range.offset + range.length) : body).body };
      },
    },
  };
  const ctx = { waitUntil(promise) { pending.push(promise); } };
  return { env, calls, rows, ctx, async drain() { await Promise.all(pending); } };
}

const resourceUrl = `https://res.cheesesec.com/sha256/${"a".repeat(64)}/fixture.crp`;

test("service roots and status pages are self contained, branded, fresh, and count only page GETs", async () => {
  for (const host of ["store", "ota", "res"]) {
    const { env, rows } = fixture();
    for (const path of host === "store" ? ["/status", "/status/"] : ["/", "/status"]) {
      const response = await worker.fetch(new Request(`https://${host}.cheesesec.com${path}`), env);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("cache-control"), "no-store");
      assert.match(response.headers.get("content-security-policy"), /script-src 'none'/);
      const html = await response.text();
      assert.match(html, /data:image\/png;base64,/);
      assert.match(html, /累计下载响应/);
      assert.match(html, /不代表客户端完整接收或已保存到磁盘/);
      assert.doesNotMatch(html, /<script|<link[^>]+stylesheet|<img[^>]+src="https?:/);
    }
    const before = { ...rows.get(`service:${host}`) };
    const head = await worker.fetch(new Request(`https://${host}.cheesesec.com/status`, { method: "HEAD" }), env);
    assert.equal(head.body, null);
    assert.deepEqual(rows.get(`service:${host}`), before);
    const json = await worker.fetch(new Request(`https://${host}.cheesesec.com/v1/status.json`), env);
    const status = await json.json();
    assert.equal(status.status, "operational");
    assert.equal(status.service, host);
    assert.equal(status.counters.visits, 2);
    assert.equal(status.counters.downloads, 0);
    assert.ok(Date.parse(status.checked_at));
    assert.deepEqual(rows.get(`service:${host}`), before);
  }
});

test("status performs exact fixed R2 probes including both valid OTA indexes", async () => {
  const { env, calls } = fixture();
  for (const host of ["store", "ota", "res"]) {
    const status = await (await worker.fetch(new Request(`https://${host}.cheesesec.com/v1/status.json`), env)).json();
    assert.equal(status.status, "operational");
    if (host === "ota") {
      assert.match(status.probes[0].detail, /暂无更新/);
      assert.match(status.probes[1].detail, /v0\.4\.5/);
    }
  }
  assert.deepEqual(calls.filter(call => call[0].includes("-head") || call[0].includes("-get")), [
    ["publication-head", "catalog/index.json"],
    ["publication-get", "ota/channels/stable/index.json"],
    ["publication-get", "software/channels/stable/index.json"],
    ["resource-head", "releases/v0.4.5/SHA256SUMS"],
  ]);
});

test("missing or failing R2 and invalid or empty OTA indexes are visibly degraded", async () => {
  for (const failure of [null, new Error("private bucket details"), { size: 0 }]) {
    for (const host of ["store", "res"]) {
      const { env } = fixture();
      const bucket = host === "store" ? env.PUBLICATION_INDEX : env.PUBLIC_RESOURCES;
      bucket.head = async () => { if (failure instanceof Error) throw failure; return failure; };
      const status = await (await worker.fetch(new Request(`https://${host}.cheesesec.com/v1/status.json`), env)).json();
      assert.equal(status.status, "degraded");
      assert.equal(status.probes[0].status, "unavailable");
      assert.doesNotMatch(JSON.stringify(status), /private bucket details/);
    }
  }
  for (const value of [null, "not-json", {}, { api_version: "ota.cheesesec.com/software/v1", channel: "stable", tag_name: "v0.4.5", assets: [] }]) {
    const { env } = fixture();
    const original = env.PUBLICATION_INDEX.get;
    env.PUBLICATION_INDEX.get = async key => key.startsWith("software/")
      ? (value === null ? null : { size: 10, body: new Response(typeof value === "string" ? value : JSON.stringify(value)).body }) : original(key);
    const status = await (await worker.fetch(new Request("https://ota.cheesesec.com/v1/status.json"), env)).json();
    assert.equal(status.status, "degraded");
    assert.equal(status.probes[0].status, "available");
    assert.equal(status.probes[1].status, "unavailable");
  }
});

test("stalled R2 and counter services produce a bounded degraded status instead of hanging", { timeout: 5000 }, async () => {
  const { env } = fixture();
  const never = () => new Promise(() => {});
  env.PUBLICATION_INDEX.get = never;
  env.SERVICE_COUNTERS.get = () => ({ fetch: never });
  const start = performance.now();
  const response = await worker.fetch(new Request("https://ota.cheesesec.com/v1/status.json"), env);
  const status = await response.json();
  assert.equal(status.status, "degraded");
  assert.equal(status.counters.available, false);
  assert.ok(status.probes.every(probe => probe.status === "unavailable"));
  assert.ok(performance.now() - start < 4500);
});

test("counter failure displays null totals without inventing zeros or disrupting range downloads", async () => {
  for (const replacement of [undefined, { idFromName() { throw new Error("secret"); } }, {
    idFromName(name) { return name; }, get() { return { fetch: async () => new Response(null, { status: 503 }) }; },
  }, { idFromName(name) { return name; }, get() { return { fetch: async () => Response.json({ visits: 0 }) }; } }]) {
    const { env, ctx, drain } = fixture();
    env.SERVICE_COUNTERS = replacement;
    const status = await (await worker.fetch(new Request("https://res.cheesesec.com/v1/status.json"), env)).json();
    assert.equal(status.status, "degraded");
    assert.deepEqual(status.counters, { available: false, started_at: null, updated_at: null, visits: null, downloads: null, transferred_bytes: null });
    const download = await worker.fetch(new Request(resourceUrl, { headers: { range: "bytes=2-5" } }), env, ctx);
    assert.equal(download.status, 206);
    assert.equal(download.headers.get("content-range"), "bytes 2-5/10");
    assert.equal(download.headers.get("content-length"), "4");
    assert.equal(await download.text(), "2345");
    await drain();
  }
});

test("downloads count final GET200/206 lengths, exclude HEAD/304/404/416/503, and retain headers", async () => {
  const { env, rows, ctx, drain } = fixture();
  const cases = [
    [{}, 200, "10"], [{ headers: { range: "bytes=2-5" } }, 206, "4"],
    [{ headers: { range: "bytes=-2" } }, 206, "2"],
    [{ method: "HEAD", headers: { range: "bytes=0-2" } }, 200, "10"],
    [{ headers: { "if-none-match": '"fixture"' } }, 304, "10"],
    [{ headers: { range: "bytes=90-100" } }, 416, "0"],
  ];
  for (const [init, expectedStatus, expectedLength] of cases) {
    const response = await worker.fetch(new Request(resourceUrl, init), env, ctx);
    assert.equal(response.status, expectedStatus);
    assert.equal(response.headers.get("content-length"), expectedLength);
  }
  env.PUBLIC_RESOURCES.head = async () => null;
  assert.equal((await worker.fetch(new Request(resourceUrl), env, ctx)).status, 404);
  env.PUBLIC_RESOURCES.head = async key => ({ size: 12, key, etag: "changed", uploaded: new Date(), writeHttpMetadata() {} });
  assert.equal((await worker.fetch(new Request(resourceUrl), env, ctx)).status, 503);
  await drain();
  const row = rows.get("service:res");
  assert.equal(row.downloads, 3);
  assert.equal(row.transferred_bytes, 16);
  assert.equal(row.visits, 4);
});

test("known hosts only; forbidden, malformed and unsupported requests do not access storage", async () => {
  const { env, calls } = fixture();
  const cases = [
    ["https://evil.example/status", {}, 421], ["https://api.cheesesec.com/status", {}, 404],
    ["https://console.cheesesec.com/status", {}, 404],
    ["https://ota.cheesesec.com/status", { method: "POST" }, 405],
    ["https://res.cheesesec.com/v1/status.json", { headers: { cookie: "private=yes" } }, 403],
    ["https://res.cheesesec.com/status", { headers: { authorization: "secret" } }, 403],
    ["https://ota.cheesesec.com/status?token=private", {}, 403],
    ["https://ota.cheesesec.com/%2fstatus", {}, 404],
    ["https://ota.cheesesec.com//status", {}, 404],
  ];
  for (const [url, init, status] of cases) assert.equal((await worker.fetch(new Request(url, init), env)).status, status, url);
  assert.deepEqual(calls, []);
});

test("counts include catalog and store page GETs, omit static assets and never forward request data", async () => {
  const { env, calls, rows, ctx, drain } = fixture();
  const privateHeaders = { "user-agent": "private-agent", "cf-connecting-ip": "192.0.2.1", referer: "https://private.example/" };
  await worker.fetch(new Request("https://store.cheesesec.com/?q=private-search", { headers: { ...privateHeaders, cookie: "locale=zh-CN" } }), env, ctx);
  await worker.fetch(new Request("https://store.cheesesec.com/storefront.css"), env, ctx);
  await worker.fetch(new Request("https://store.cheesesec.com/v1/catalog/index.json?search=private-search", { headers: privateHeaders }), env, ctx);
  await drain();
  assert.equal(rows.get("service:store").visits, 2);
  assert.equal(rows.get("service:store").downloads, 0);
  const counterCalls = calls.filter(call => call[0].startsWith("counter"));
  assert.doesNotMatch(JSON.stringify(counterCalls), /private|192\.0\.2\.1|locale|referer|user-agent|search/);
  assert.ok(counterCalls.every(call => call[1] === "service:store"));
});
