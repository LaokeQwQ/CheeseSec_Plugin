import assert from "node:assert/strict";
import { test } from "node:test";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, matchesGlob, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

const execFileAsync = promisify(execFile);
const root = fileURLToPath(new URL("../", import.meta.url));

test("Wrangler's complete emitted module graph starts in workerd with real ArrayBuffer PNG modules", { timeout: 60000 }, async t => {
  const temporary = await mkdtemp(join(tmpdir(), "cheesesec-worker-runtime-"));
  const output = join(temporary, "bundle");
  let runtime;
  try {
    // Exercise Wrangler's deployment bundle, including its actual external
    // Text/Data modules. esbuild's binary loader returns Uint8Array instead
    // of workerd's ArrayBuffer and cannot detect production startup failures.
    const wrangler = resolve(dirname(fileURLToPath(import.meta.resolve("wrangler"))), "../bin/wrangler.js");
    const { stdout, stderr } = await execFileAsync(process.execPath, [wrangler, "deploy", "--config", join(root, "wrangler.jsonc"), "--dry-run", "--outdir", output], {
      cwd: root, timeout: 30000, maxBuffer: 1024 * 1024,
      env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "true" },
    });
    assert.match(stdout + stderr, /--dry-run: exiting now/);
    const config = JSON.parse(await readFile(join(root, "wrangler.jsonc"), "utf8"));
    const entry = join(output, "index.js");
    const source = await readFile(entry, "utf8");
    const imports = [...new Set([...source.matchAll(/^import\s+.*?\s+from\s+["']([^"']+)["'];?$/gm)].map(match => match[1]))];
    assert.ok(imports.length >= 7, "Wrangler must preserve external storefront modules");
    const modules = [{ type: "ESModule", path: entry }];
    for (const specifier of imports) {
      assert.match(specifier, /^\.\/[a-f0-9]{40}-[A-Za-z0-9._+-]+$/);
      const filename = basename(specifier).replace(/^[a-f0-9]{40}-/, "");
      const original = `storefront/${filename}`;
      const rule = config.rules.find(candidate => candidate.globs.some(glob => matchesGlob(original, glob)));
      assert.ok(rule, `No Wrangler module rule for ${original}`);
      assert.ok(rule.type === "Text" || rule.type === "Data");
      modules.push({ type: rule.type, path: resolve(dirname(entry), specifier) });
    }
    const brand = modules.find(module => module.type === "Data" && module.path.endsWith("-cheesesec-logo.png"));
    assert.ok(brand, "the exact Wrangler PNG output must enter workerd as a Data module");
    const emitted = (await readdir(output)).filter(filename => filename !== "README.md" && !filename.endsWith(".map"));
    assert.deepEqual(emitted.sort(), modules.map(module => basename(module.path)).sort(), "all emitted deployment modules must enter workerd");
    const brandBytes = await readFile(brand.path);
    assert.deepEqual(brandBytes, await readFile(join(root, "storefront/cheesesec-logo.png")));
    t.diagnostic(`Wrangler module graph: ${JSON.stringify(modules.map(module => ({ type: module.type, file: basename(module.path) })))}`);

    const main = {
      name: "publication-runtime-test", modules, modulesRoot: output,
      compatibilityDate: config.compatibility_date,
      durableObjects: { SERVICE_COUNTERS: { className: "ServiceCounters", useSQLite: true } },
      r2Buckets: ["PUBLICATION_INDEX", "PUBLIC_RESOURCES"],
      bindings: config.vars,
    };
    // A second worker confirms the actual runtime value for the same Data
    // graph entry. No loader transformation or Uint8Array shim is involved.
    const shape = {
      name: "data-module-shape", modulesRoot: output,
      compatibilityDate: config.compatibility_date,
      modules: [
        { type: "ESModule", path: join(output, "data-shape.mjs"), contents: `import logo from "./${basename(brand.path)}"; export default { fetch() { return Response.json({ shape: Object.prototype.toString.call(logo), size: logo.byteLength, iterable: typeof logo[Symbol.iterator] === "function" }); } };` },
        brand,
      ],
    };
    runtime = new Miniflare(convertV4MiniflareOptions({ workers: [main, shape], cf: false, telemetry: { enabled: false } }));
    await runtime.ready;
    const shapeResponse = await (await runtime.getWorker("data-module-shape")).fetch("https://shape.invalid/");
    assert.deepEqual(await shapeResponse.json(), { shape: "[object ArrayBuffer]", size: brandBytes.byteLength, iterable: false });

    const publication = await runtime.getR2Bucket("PUBLICATION_INDEX", main.name);
    const resources = await runtime.getR2Bucket("PUBLIC_RESOURCES", main.name);
    await publication.put("catalog/index.json", JSON.stringify({ api_version: "store.cheesesec.com/v1", catalog_sequence: 1, releases: [], withdrawals: [] }));
    await publication.put("ota/channels/stable/index.json", JSON.stringify({ api_version: "ota.cheesesec.com/v1", index_sequence: 0, mode: "pull-only", releases: [] }));
    await publication.put("software/channels/stable/index.json", JSON.stringify({
      api_version: "ota.cheesesec.com/software/v1", channel: "stable", tag_name: "v0.4.5",
      assets: [{ name: "archive.tar.gz", size: 10, sha256: "a".repeat(64), url: "https://res.cheesesec.com/releases/v0.4.5/archive.tar.gz" }],
    }));
    await resources.put("releases/v0.4.5/SHA256SUMS", "fixture-checksums\n");
    await resources.put("releases/v0.4.5/archive.tar.gz", "0123456789");
    const worker = await runtime.getWorker(main.name);
    const statusFor = async host => (await worker.fetch(`https://${host}.cheesesec.com/v1/status.json`)).json();
    for (const host of ["store", "ota", "res"]) {
      const before = await statusFor(host);
      assert.equal(before.status, "operational");
      assert.equal(before.counters.visits, 0);
      const response = await worker.fetch(`https://${host}.cheesesec.com/status`);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("content-type"), "text/html; charset=utf-8");
      assert.equal(response.headers.get("cache-control"), "no-store");
      assert.equal(response.headers.get("x-content-type-options"), "nosniff");
      assert.match(response.headers.get("content-security-policy"), /script-src 'none'/);
      const html = await response.text();
      assert.equal(Number(response.headers.get("content-length")), Buffer.byteLength(html));
      assert.ok(html.includes(`data:image/png;base64,${brandBytes.toString("base64")}`));
      assert.match(html, /CheeseSec|累计下载响应/);
      const after = await statusFor(host);
      assert.equal(after.counters.visits, 1);
      assert.equal(after.counters.downloads, 0);
      assert.equal((await statusFor(host)).counters.visits, 1, "status polling must not count as visits");
      t.diagnostic(`${host} /status headers: ${JSON.stringify({ status: response.status, contentType: response.headers.get("content-type"), cacheControl: response.headers.get("cache-control"), bytes: response.headers.get("content-length") })}; counters: ${JSON.stringify(after.counters)}`);
    }
    const png = await worker.fetch("https://store.cheesesec.com/cheesesec-logo.png");
    assert.equal(png.headers.get("content-type"), "image/png");
    assert.equal(png.headers.get("content-length"), String(brandBytes.byteLength));
    assert.deepEqual(Buffer.from(await png.arrayBuffer()), brandBytes);
    const storefront = await worker.fetch("https://store.cheesesec.com/");
    assert.equal(storefront.status, 200);
    assert.match(await storefront.text(), /href="\/status"/);
    for (const host of ["ota", "res"]) assert.equal((await worker.fetch(`https://${host}.cheesesec.com/`)).status, 200);

    const download = await worker.fetch("https://res.cheesesec.com/releases/v0.4.5/archive.tar.gz", { headers: { range: "bytes=2-5" } });
    assert.equal(download.status, 206);
    assert.equal(download.headers.get("content-range"), "bytes 2-5/10");
    assert.equal(download.headers.get("content-length"), "4");
    assert.equal(await download.text(), "2345");
    const namespace = await runtime.getDurableObjectNamespace("SERVICE_COUNTERS", main.name);
    // A direct read on the same object is ordered after the waitUntil write;
    // it also verifies the real Worker, namespace and SQLite export connect.
    const counter = await namespace.get(namespace.idFromName("service:res")).fetch("https://service-counters.invalid/snapshot", { method: "POST", body: JSON.stringify({ service: "res" }) });
    const totals = await counter.json();
    assert.equal(totals.visits, 3);
    assert.equal(totals.downloads, 1);
    assert.equal(totals.transferred_bytes, 4);
    t.diagnostic(`Range response headers: ${JSON.stringify(Object.fromEntries(download.headers))}; counters: ${JSON.stringify(totals)}`);
    assert.equal((await worker.fetch("https://foreign.example/status")).status, 421);
  } finally {
    await runtime?.dispose();
    await rm(temporary, { recursive: true, force: true });
  }
});
