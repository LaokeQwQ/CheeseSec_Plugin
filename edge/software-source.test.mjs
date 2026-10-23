import assert from "node:assert/strict";
import { before, test } from "node:test";
import { fileURLToPath } from "node:url";

let classifyRequest, serveResource;
before(async () => {
  const { build } = await import(process.env.CHEESESEC_ESBUILD_MODULE || "esbuild");
  async function bundle(name) {
    const result = await build({ entryPoints: [fileURLToPath(new URL(name, import.meta.url))], bundle: true, format: "esm", platform: "browser", write: false, tsconfigRaw: {} });
    return import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString("base64")}`);
  }
  ({ classifyRequest } = await bundle("./route-policy.ts"));
  ({ serveResource } = await bundle("./publication.ts"));
});

test("software metadata has a separate namespace from strict CRP OTA indexes", () => {
  for (const channel of ["stable", "canary", "dev"]) {
    const decision = classifyRequest(new Request(`https://ota.cheesesec.com/v1/software/channels/${channel}/index.json`));
    assert.equal(decision.kind, "publication");
    assert.equal(decision.key, `software/channels/${channel}/index.json`);
    assert.equal(classifyRequest(new Request(`https://ota.cheesesec.com/v1/channels/${channel}/index.json`)).key, `ota/channels/${channel}/index.json`);
  }
});

test("official release paths remain versioned, read-only and credential-free", () => {
  const url = "https://res.cheesesec.com/releases/v0.4.5/cheesewaf-amd64-linux-0.4.5.tar.gz";
  const decision = classifyRequest(new Request(url));
  assert.equal(decision.kind, "resource");
  assert.equal(decision.key, "releases/v0.4.5/cheesewaf-amd64-linux-0.4.5.tar.gz");
  assert.equal(classifyRequest(new Request(url, { method: "POST" })).kind, "method-not-allowed");
  assert.equal(classifyRequest(new Request(url, { headers: { authorization: "Bearer bad" } })).kind, "forbidden");
  assert.equal(classifyRequest(new Request(url + "?token=bad")).kind, "forbidden");
  for (const path of ["/releases/latest/a.tar.gz", "/releases/v0.4.5/a/secret", "/releases/v0.4.5/a%2Fb", "/releases/v0.4.5/a..tar.gz", "/releases/v0.4.5-/a", "/releases/v0.4.5-a..b/a"]) {
    assert.equal(classifyRequest(new Request("https://res.cheesesec.com" + path)).kind, "not-found", path);
  }
});

test("official packages reuse R2 range and conditional integrity checks", async () => {
  const bytes = "release-package";
  const metadata = { size: bytes.length, etag: "same", httpEtag: '"same"', uploaded: new Date("2026-10-21T00:00:00Z"), writeHttpMetadata() {} };
  let gets = 0;
  const env = { PUBLIC_RESOURCES: {
    async head() { return metadata; },
    async get(key, options) {
      gets++;
      assert.equal(key, "releases/v0.4.5/archive.tar.gz");
      const range = options?.range;
      return { ...metadata, body: new Response(range ? bytes.slice(range.offset, range.offset + range.length) : bytes).body };
    },
  } };
  const url = "https://res.cheesesec.com/releases/v0.4.5/archive.tar.gz";
  let request = new Request(url, { headers: { range: "bytes=2-5" } });
  let response = await serveResource(request, env, classifyRequest(request));
  assert.equal(response.status, 206);
  assert.equal(await response.text(), bytes.slice(2, 6));
  assert.equal(response.headers.get("content-range"), `bytes 2-5/${bytes.length}`);
  request = new Request(url, { headers: { "if-none-match": '"same"' } });
  response = await serveResource(request, env, classifyRequest(request));
  assert.equal(response.status, 304);
  assert.equal(response.body, null);
  request = new Request(url, { method: "HEAD" });
  response = await serveResource(request, env, classifyRequest(request));
  assert.equal(response.status, 200);
  assert.equal(response.body, null);
  assert.equal(gets, 1);
});
