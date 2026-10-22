import test from "node:test";
import assert from "node:assert/strict";
import { categoryForRelease, downloadUrlForRelease, filterCatalog, lifecycleExampleForRelease, normalizeCatalog } from "./catalog.mjs";

function release(plugin = "threat-intel", sequence = 1, overrides = {}) {
  const namespace = `official/${plugin}`;
  return {
    api_version: "store.cheesesec.com/v1", record_type: "publication", plugin_id: plugin,
    namespace, trust_level: "official", version: "1.0.0", source: "official", immutable: true,
    release_id: `${namespace}@1.0.0#${sequence}`, release_sequence: sequence,
    crp: { size: 1024, digests: { sha256: "a".repeat(64) }, resource_url: `https://res.cheesesec.com/sha256/${"a".repeat(64)}/${plugin}.crp` },
    review: { decision: "approved" }, signature_evidence: { status: "verified" }, ...overrides,
  };
}
function catalog(releases = [], withdrawals = []) {
  return { api_version: "store.cheesesec.com/v1", catalog_sequence: 1, releases, withdrawals };
}

test("empty production catalog remains empty without example items", () => {
  assert.deepEqual(normalizeCatalog(catalog()), { plugins: [], sequence: 1 });
});

test("contract examples, unapproved and unverified records are excluded", () => {
  const result = normalizeCatalog(catalog([
    release("example", 1, { record_type: "contract-example" }),
    release("pending", 2, { review: { decision: "draft" } }),
    release("unsigned", 3, { signature_evidence: { status: "unsigned_example" } }),
    release("actual", 4),
  ]));
  assert.deepEqual(result.plugins.map(plugin => plugin.name), ["actual"]);
});

test("withdrawals are applied before selecting latest namespace version", () => {
  const first = release("rules", 1);
  const latest = release("rules", 2);
  const result = normalizeCatalog(catalog([first, latest], [{ release_id: latest.release_id }]));
  assert.equal(result.plugins.length, 1);
  assert.equal(result.plugins[0].id, first.release_id);
});

test("latest identity is namespace rather than plugin id", () => {
  const other = release("rules", 2, {
    namespace: "community/acme/rules", trust_level: "community", release_id: "community/acme/rules@1.0.0#2",
  });
  const result = normalizeCatalog(catalog([release("rules", 1), release("rules", 3), other]));
  assert.equal(result.plugins.length, 2);
  assert.equal(result.plugins[0].releaseSequence, 3);
  assert.equal(result.plugins[1].namespace, "community/acme/rules");
});

test("invalid catalogs and withdrawal records fail without a misleading empty state", () => {
  for (const payload of [null, {}, catalog({}, []), catalog([], [null]), catalog([], [{ release_id: "" }]), { ...catalog(), catalog_sequence: 2 ** 53 }]) {
    assert.throws(() => normalizeCatalog(payload), /Invalid/);
  }
});

test("malformed published identities and digests cannot enter display results", () => {
  for (const invalid of [
    release("rules", 1, { release_id: "javascript:alert(1)" }),
    release("rules", 1, { namespace: "official/<script>" }),
    release("rules", 1, { crp: { size: 10, digests: { sha256: "not-a-digest" } } }),
    release("rules", 1, { source: "bad\nsource" }),
  ]) assert.throws(() => normalizeCatalog(catalog([invalid])), /Invalid published/);
  assert.throws(() => normalizeCatalog(catalog([release(), release()])), /Duplicated/);
});

test("category classification uses bounded plugin names and defaults to tools", () => {
  assert.equal(categoryForRelease(release("threat-intel")), "intelligence");
  assert.equal(categoryForRelease(release("feishu-notifier")), "notifications");
  assert.equal(categoryForRelease(release("audit-report")), "analysis");
  assert.equal(categoryForRelease(release("sqli-rules")), "security");
  assert.equal(categoryForRelease(release("misc")), "tools");
});

test("search filters name namespace and source, with independent sort and category", () => {
  const { plugins } = normalizeCatalog(catalog([release("threat-intel", 1), release("audit-report", 3), release("feishu-notifier", 2)]));
  assert.deepEqual(filterCatalog(plugins, { category: "intelligence" }).map(x => x.name), ["threat-intel"]);
  assert.deepEqual(filterCatalog(plugins, { query: " OFFICIAL/FEISHU " }).map(x => x.name), ["feishu-notifier"]);
  assert.deepEqual(filterCatalog(plugins, { sort: "name" }).map(x => x.name), ["audit-report", "feishu-notifier", "threat-intel"]);
  assert.deepEqual(filterCatalog(plugins, { trust: "community" }), []);
  assert.equal(plugins[0].name, "audit-report");
});

test("download URL is limited to the exact digest-bound public CRP resource", () => {
  const item = release();
  const valid = item.crp.resource_url;
  assert.equal(downloadUrlForRelease(item), valid);
  assert.equal(normalizeCatalog(catalog([item])).plugins[0].downloadUrl, valid);
  for (const resource_url of [
    valid.replace("https:", "http:"), valid.replace("res.cheesesec.com", "res.cheesesec.com.evil.example"),
    valid.replace("res.cheesesec.com", "user:password@res.cheesesec.com"),
    valid.replace("res.cheesesec.com", "res.cheesesec.com:443"), valid + "?download=1", valid + "#file",
    valid.replace("/" + "a".repeat(64) + "/", "/" + "b".repeat(64) + "/"),
    valid.replace("threat-intel.crp", "../threat-intel.crp"), valid.replace("threat-intel.crp", "file%2ecrp"),
    valid.replace("threat-intel.crp", "file..crp"), valid.replace(".crp", ".zip"), "javascript:alert(1)",
  ]) {
    const candidate = { ...item, crp: { ...item.crp, resource_url } };
    assert.equal(downloadUrlForRelease(candidate), null, resource_url);
    assert.throws(() => normalizeCatalog(catalog([candidate])), /Invalid published resource URL/);
  }
});

test("known Hello releases carry exact platform and lifecycle-only display metadata", () => {
  const items = ["linux-amd64", "darwin-arm64"].map(platform => {
    const pluginId = `hello-cheesesec-${platform}`;
    return release(pluginId, 1, { version: "0.1.0", release_id: `official/${pluginId}@0.1.0#1` });
  });
  const { plugins } = normalizeCatalog(catalog(items));
  assert.equal(plugins.length, 2);
  for (const plugin of plugins) {
    assert.equal(plugin.name, "Hello CheeseSec");
    assert.equal(plugin.lifecycleExample.kind, "lifecycle-example");
    assert.equal(plugin.downloadUrl, plugin.raw.crp.resource_url);
  }
  assert.deepEqual(plugins.map(x => x.lifecycleExample.platformLabel).sort(), ["Linux · amd64", "macOS · arm64"].sort());
  assert.equal(filterCatalog(plugins, { query: "hello-cheesesec-linux-amd64" })[0].lifecycleExample.platform, "linux-amd64");
  assert.equal(filterCatalog(plugins, { query: "macOS" }).length, 1);
  assert.equal(lifecycleExampleForRelease(release("hello-cheesesec-linux-amd64")), null, "unknown version must not inherit compatibility");
  assert.equal(lifecycleExampleForRelease({ ...items[0], namespace: "community/acme/hello-cheesesec-linux-amd64", trust_level: "community" }), null);
  assert.equal(lifecycleExampleForRelease(release("unrelated")), null);
});
