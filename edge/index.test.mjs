import assert from "node:assert/strict";
import { before, test } from "node:test";
import { fileURLToPath } from "node:url";

let worker;
before(async () => {
  const module = process.env.CHEESESEC_ESBUILD_MODULE || "esbuild";
  const { build } = await import(module);
  const result = await build({
    entryPoints: [fileURLToPath(new URL("./index.ts", import.meta.url))],
    bundle: true,
    format: "esm",
    platform: "browser",
    loader: { ".html": "text", ".css": "text", ".js": "text", ".mjs": "text", ".png": "binary" },
    write: false,
    tsconfigRaw: {},
  });
  worker = (await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString("base64")}`)).default;
});

function fixture(publication = '{"index_sequence":1}', resource = "0123456789") {
  const calls = [];
  const metadata = (key, size) => ({
    key, size, etag: "fixture", httpEtag: '"fixture"',
    uploaded: new Date("2026-10-22T00:00:00Z"),
    customMetadata: { index_sequence: "1" },
    writeHttpMetadata() {},
  });
  const env = {
    EDGE_POLICY_VERSION: "public-read-test",
    PUBLICATION_INDEX: {
      async get(key) {
        calls.push(["publication", key]);
        return publication === null ? null : {
          ...metadata(key, Buffer.byteLength(publication)),
          body: new Response(publication).body,
        };
      },
    },
    PUBLIC_RESOURCES: {
      async head(key) {
        calls.push(["resource-head", key]);
        return resource === null ? null : metadata(key, resource.length);
      },
      async get(key, options) {
        calls.push(["resource", key, options]);
        if (resource === null) return null;
        const range = options?.range;
        if (range && (range.offset >= resource.length || range.length <= 0 || range.offset + range.length > resource.length)) {
          throw new Error("unsatisfiable R2 range reached the storage adapter");
        }
        const body = range ? resource.slice(range.offset, range.offset + range.length) : resource;
        return {
          ...metadata(key, resource.length),
          range: range ? { offset: range.offset, length: range.length, suffix: undefined } : undefined,
          body: new Response(body).body,
        };
      },
    },
  };
  return { env, calls };
}

test("catalog, policies, schemas and all OTA channels use fixed publication keys", async () => {
  const cases = [
    ["store.cheesesec.com/v1/catalog/index.json", "catalog/index.json"],
    ...["endpoints", "trust-roots", "source-registry", "revocations"].map(name => [`store.cheesesec.com/v1/policy/${name}.json`, `policy/${name}.json`]),
    ["store.cheesesec.com/v1/schema/crp/manifest.schema.json", "schema/crp-v1/manifest.schema.json"],
    ["store.cheesesec.com/v1/schema/store/catalog.schema.json", "schema/store-v1/catalog.schema.json"],
    ...["stable", "canary", "dev"].map(channel => [`ota.cheesesec.com/v1/channels/${channel}/index.json`, `ota/channels/${channel}/index.json`]),
  ];
  for (const [path, key] of cases) {
    const { env, calls } = fixture();
    const response = await worker.fetch(new Request(`https://${path}`), env);
    assert.equal(response.status, 200, path);
    assert.equal(await response.text(), '{"index_sequence":1}');
    assert.deepEqual(calls, [["publication", key]]);
  }
});

test("publication HEAD and conditional reads retain metadata without a response body", async () => {
  for (const [init, status] of [[{ method: "HEAD" }, 200], [{ headers: { "if-none-match": 'W/"fixture"' } }, 304]]) {
    const { env } = fixture();
    const response = await worker.fetch(new Request("https://store.cheesesec.com/v1/catalog/index.json", init), env);
    assert.equal(response.status, status);
    assert.equal(response.body, null);
    assert.equal(response.headers.get("etag"), '"fixture"');
  }
});

test("unknown public paths never fall through to a bucket or an origin", async () => {
  for (const path of ["ota.cheesesec.com/", "res.cheesesec.com/", "store.cheesesec.com/api/sites", "store.cheesesec.com/v1/policy/private.json", "ota.cheesesec.com/v1/channels/latest/index.json", "res.cheesesec.com/resources/private", "store.cheesesec.com/v1/schema/crp/%2e%2e%2fsecret.schema.json"]) {
    const { env, calls } = fixture();
    const response = await worker.fetch(new Request(`https://${path}`), env);
    assert.equal(response.status, 404, path);
    assert.deepEqual(calls, []);
  }
});

test("ordinary browsers receive a store page while v1 remains a separate JSON read surface", async () => {
  const { env, calls } = fixture();
  const page = await worker.fetch(new Request("https://store.cheesesec.com/", { headers: { cookie: "cheesec-locale=zh-CN" } }), env);
  assert.equal(page.status, 200);
  assert.equal(page.headers.get("content-type"), "text/html; charset=utf-8");
  assert.match(await page.text(), /<html\b/);
  assert.match(page.headers.get("content-security-policy"), /script-src 'self'/);
  assert.deepEqual(calls, []);
  const api = await worker.fetch(new Request("https://store.cheesesec.com/v1/catalog/index.json"), env);
  assert.equal(api.status, 200);
  assert.equal(api.headers.get("content-type"), "application/json; charset=utf-8");
  const head = await worker.fetch(new Request("https://store.cheesesec.com/", { method: "HEAD" }), env);
  assert.equal(head.status, 200);
  assert.equal(head.body, null);
  for (const path of ["/storefront.css", "/storefront.js", "/catalog.mjs", "/logo.png"]) {
    const asset = await worker.fetch(new Request(`https://store.cheesesec.com${path}`), env);
    assert.equal(asset.status, 200);
    assert.equal(asset.headers.get("x-content-type-options"), "nosniff");
    const rejected = await worker.fetch(new Request(`https://store.cheesesec.com${path}`, { method: "POST" }), env);
    assert.equal(rejected.status, 405);
    assert.equal(rejected.headers.get("allow"), "GET, HEAD");
  }
});

test("website, local, API and console hosts have no assets or management proxy in this service", async () => {
  for (const path of ["cheesesec.com/", "www.cheesesec.com/api/health", "docs.cheesesec.com/", "localhost/", "api.cheesesec.com/api/sites", "console.cheesesec.com/setup"]) {
    const { env, calls } = fixture();
    const response = await worker.fetch(new Request(`https://${path}`), env);
    assert.equal(response.status, 404, path);
    assert.deepEqual(calls, []);
  }
  const { env, calls } = fixture();
  const response = await worker.fetch(new Request("https://unknown.example/"), env);
  assert.equal(response.status, 421);
  assert.deepEqual(calls, []);
});

test("all public hosts reject write methods without storage access", async () => {
  for (const path of ["store.cheesesec.com/v1/catalog/index.json", "ota.cheesesec.com/v1/channels/stable/index.json", `res.cheesesec.com/sha256/${"a".repeat(64)}/bundle.crp`]) {
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
      const { env, calls } = fixture();
      const response = await worker.fetch(new Request(`https://${path}`, { method }), env);
      assert.equal(response.status, 405, `${method} ${path}`);
      assert.equal(response.headers.get("allow"), "GET, HEAD");
      assert.deepEqual(calls, []);
    }
  }
});

test("credentials on public reads fail closed before bucket access", async () => {
  for (const init of [{ headers: { authorization: "Bearer must-not-forward" } }, { headers: { cookie: "session=must-not-forward" } }, { headers: { "x-csrf-token": "must-not-forward" } }]) {
    const { env, calls } = fixture();
    const response = await worker.fetch(new Request("https://store.cheesesec.com/v1/catalog/index.json", init), env);
    assert.equal(response.status, 403);
    assert.deepEqual(calls, []);
  }
  const { env, calls } = fixture();
  const response = await worker.fetch(new Request("https://ota.cheesesec.com/v1/channels/stable/index.json?token=must-not-forward"), env);
  assert.equal(response.status, 403);
  assert.deepEqual(calls, []);
});

test("content-addressed resources stream exact single ranges with real R2 optional field shape", async () => {
  const digest = "a".repeat(64);
  const { env, calls } = fixture();
  const response = await worker.fetch(new Request(`https://res.cheesesec.com/sha256/${digest}/bundle.crp`, { headers: { range: "bytes=2-4" } }), env);
  assert.equal(response.status, 206);
  assert.equal(response.headers.get("content-range"), "bytes 2-4/10");
  assert.equal(await response.text(), "234");
  assert.deepEqual(calls, [["resource-head", `resources/sha256/${digest}/bundle.crp`], ["resource", `resources/sha256/${digest}/bundle.crp`, { range: { offset: 2, length: 3 } }]]);
});

test("out-of-bounds ranges cannot become storage errors and missing resources remain 404", async () => {
  const path = `https://res.cheesesec.com/sha256/${"a".repeat(64)}/bundle.crp`;
  const { env, calls } = fixture();
  const response = await worker.fetch(new Request(path, { headers: { range: "bytes=10-" } }), env);
  assert.equal(response.status, 416);
  assert.equal(response.headers.get("content-range"), "bytes */10");
  assert.equal(calls.length, 1);
  const missing = fixture(null, null);
  const missingResponse = await worker.fetch(new Request(path, { headers: { range: "bytes=0-1" } }), missing.env);
  assert.equal(missingResponse.status, 404);
  assert.equal(missing.calls.length, 1);
});
