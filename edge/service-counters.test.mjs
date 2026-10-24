import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

test("SQLite counter totals are atomic under concurrent requests and survive runtime restarts", { timeout: 60000 }, async () => {
  const { build } = await import(process.env.CHEESESEC_ESBUILD_MODULE || "esbuild");
  const result = await build({ entryPoints: [fileURLToPath(new URL("./service-counters.ts", import.meta.url))], bundle: true, format: "esm", write: false, tsconfigRaw: {} });
  const persistence = await mkdtemp(join(tmpdir(), "cheesesec-counters-test-"));
  const options = convertV4MiniflareOptions({
    name: "service-counters-test", modules: true,
    script: `${result.outputFiles[0].text}\nexport default { fetch() { return new Response(null, { status: 404 }); } };`,
    compatibilityDate: "2026-08-18", cf: false,
    durableObjects: { SERVICE_COUNTERS: { className: "ServiceCounters", useSQLite: true } },
    resourcePersistencePath: persistence,
    telemetry: { enabled: false },
  });
  let runtime;
  const call = async (namespace, service, action, delta) => {
    const id = namespace.idFromName(`service:${service}`);
    return namespace.get(id).fetch(`https://service-counters.invalid/${action}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ service, ...(delta ? { delta } : {}) }),
    });
  };
  try {
    runtime = new Miniflare(options);
    let namespace = await runtime.getDurableObjectNamespace("SERVICE_COUNTERS");
    const responses = await Promise.all(Array.from({ length: 100 }, (_, index) => call(namespace, "res", "record", { visits: 1, downloads: 1, transferred_bytes: index + 1 })));
    const rows = await Promise.all(responses.map(response => response.json()));
    assert.equal(new Set(rows.map(row => row.visits)).size, 100);
    const before = await (await call(namespace, "res", "snapshot")).json();
    assert.equal(before.visits, 100);
    assert.equal(before.downloads, 100);
    assert.equal(before.transferred_bytes, 5050);
    assert.ok(Date.parse(before.started_at));
    const other = await (await call(namespace, "ota", "snapshot")).json();
    assert.equal(other.visits, 0);
    assert.equal(other.downloads, 0);
    await runtime.dispose();
    runtime = new Miniflare(options);
    namespace = await runtime.getDurableObjectNamespace("SERVICE_COUNTERS");
    assert.deepEqual(await (await call(namespace, "res", "snapshot")).json(), before);
    await Promise.all(Array.from({ length: 10 }, () => call(namespace, "res", "record", { visits: 1, downloads: 1, transferred_bytes: 2 })));
    const after = await (await call(namespace, "res", "snapshot")).json();
    assert.equal(after.started_at, before.started_at);
    assert.equal(after.visits, 110);
    assert.equal(after.downloads, 110);
    assert.equal(after.transferred_bytes, 5070);

    for (const invalid of [
      { service: "arbitrary-host" },
      { service: "res", delta: { visits: 999, downloads: 1, transferred_bytes: 1 } },
      { service: "res", delta: { visits: 1, downloads: 0, transferred_bytes: 1 } },
      { service: "res", delta: { visits: 1, downloads: 1, transferred_bytes: -1 } },
      { service: "res", delta: { visits: 1, downloads: 1, transferred_bytes: 1 }, ip: "192.0.2.1" },
    ]) {
      const response = await namespace.get(namespace.idFromName("service:res")).fetch("https://service-counters.invalid/record", { method: "POST", body: JSON.stringify(invalid) });
      assert.equal(response.status, 400);
    }
    const mismatch = await namespace.get(namespace.idFromName("service:res")).fetch("https://service-counters.invalid/snapshot", { method: "POST", body: JSON.stringify({ service: "store" }) });
    assert.equal(mismatch.status, 409);
    assert.deepEqual(await (await call(namespace, "res", "snapshot")).json(), after);
    assert.deepEqual(Object.keys(after).sort(), ["downloads", "service", "started_at", "transferred_bytes", "updated_at", "visits"]);
  } finally {
    await runtime?.dispose();
    await rm(persistence, { recursive: true, force: true });
  }
});
