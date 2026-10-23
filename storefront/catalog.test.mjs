import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { categoryForRelease, descriptorUrlForExtension, downloadUrlForRelease, filterCatalog, lifecycleExampleForRelease, normalizeCatalog } from "./catalog.mjs";

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
function extension(overrides = {}) {
  const digest = "b".repeat(64);
  return {
    extension_id: "official-feishu-bot-1.0.0", plugin_id: "feishu-notifier", namespace: "official/feishu-notifier",
    type: "notifier-provider", version: "1.0.0", status: "planned", installable: false,
    title: "Feishu bot", summary: "Planned Feishu destination pack for the core notifier.",
    descriptor_sha256: digest, descriptor_url: `https://res.cheesesec.com/sha256/${digest}/feishu-notifier.json`,
    ...overrides,
  };
}
function catalog(releases = [], withdrawals = [], extensions) {
  return { api_version: "store.cheesesec.com/v1", catalog_sequence: 1, releases, withdrawals, ...(extensions === undefined ? {} : { extensions }) };
}

test("empty production catalog remains empty without example items", () => {
  assert.deepEqual(normalizeCatalog(catalog()), { plugins: [], extensions: [], sequence: 1 });
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

test("planned extensions project to non-installable cards without a download", () => {
  const { plugins, extensions } = normalizeCatalog(catalog([], [], [extension()]));
  assert.deepEqual(plugins, []);
  assert.equal(extensions.length, 1);
  const [item] = extensions;
  assert.equal(item.id, "official-feishu-bot-1.0.0");
  assert.equal(item.kind, "extension");
  assert.equal(item.planned, true);
  assert.equal(item.installable, false);
  assert.equal(item.downloadUrl, null);
  assert.equal(item.lifecycleExample, null);
  assert.equal(item.sha256, null);
  assert.equal(item.name, "Feishu bot");
  assert.equal(item.namespace, "official/feishu-notifier");
  assert.equal(item.pluginId, "feishu-notifier");
  assert.equal(item.extensionType, "notifier-provider");
  assert.equal(item.trustLevel, "official");
  assert.equal(item.category, "notifications");
  assert.equal(item.version, "1.0.0");
  assert.equal(item.releaseSequence, -1);
  assert.equal(item.descriptorSha256, "b".repeat(64));
  assert.equal(item.descriptorUrl, item.raw.descriptor_url);
  assert.equal(item.raw.installable, false);
});

test("extension categories follow the pack type without inventing new ones", () => {
  for (const [type, category] of [["notifier-provider", "notifications"], ["storage-provider", "analysis"], ["extension-descriptor", "tools"]]) {
    const [item] = normalizeCatalog(catalog([], [], [extension({ type, extension_id: `official-pack-${type}`, plugin_id: "pack" })])).extensions;
    assert.equal(item.category, category, type);
    assert.equal(item.extensionType, type);
    assert.equal(item.installable, false);
  }
});

test("extension records are rejected unless planned, non-installable and strictly shaped", () => {
  for (const invalid of [
    extension({ status: "published" }), extension({ status: "PLANNED" }), extension({ status: undefined }),
    extension({ installable: true }), extension({ installable: "false" }), extension({ installable: undefined }),
    extension({ type: "sidecar" }), extension({ type: "notifier" }), extension({ type: undefined }),
    extension({ extension_id: "bad id" }), extension({ extension_id: "" }), extension({ extension_id: "x".repeat(129) }),
    extension({ plugin_id: "<script>" }), extension({ namespace: "official/<script>" }), extension({ namespace: "official" }),
    extension({ version: "1.0.0.0" }), extension({ version: "" }),
    extension({ title: " Feishu bot" }), extension({ title: "Feishu bot " }), extension({ title: "Feishu\nbot" }),
    extension({ title: "" }), extension({ title: "x".repeat(97) }),
    extension({ summary: " leading" }), extension({ summary: "trailing " }), extension({ summary: "line\nbreak" }),
    extension({ summary: "x".repeat(281) }), extension({ summary: undefined }),
    extension({ descriptor_sha256: "B".repeat(64) }), extension({ descriptor_sha256: "b".repeat(63) }),
    extension({ descriptor_sha256: undefined }),
    null, "extension", [], {},
  ]) assert.throws(() => normalizeCatalog(catalog([], [], [invalid])), /Invalid catalog extension/);
});

test("extension descriptor references stay digest-bound and never become downloads", () => {
  const item = extension();
  const valid = item.descriptor_url;
  assert.equal(descriptorUrlForExtension(item), valid);
  assert.equal(descriptorUrlForExtension({ descriptor_sha256: "b".repeat(64) }), null);
  for (const descriptor_url of [
    valid.replace("https:", "http:"), valid.replace("res.cheesesec.com", "res.cheesesec.com.evil.example"),
    valid.replace("res.cheesesec.com", "user:password@res.cheesesec.com"),
    valid.replace("res.cheesesec.com", "res.cheesesec.com:443"), valid + "?download=1", valid + "#file",
    valid.replace("/" + "b".repeat(64) + "/", "/" + "c".repeat(64) + "/"),
    valid.replace("feishu-notifier.json", "../feishu-notifier.json"),
    valid.replace("feishu-notifier.json", "feishu..notifier.json"),
    valid.replace("feishu-notifier.json", "feishu-notifier.crp"),
    valid.replace("res.cheesesec.com", "store.cheesesec.com"),
    valid.replace("/sha256/", "/resources/sha256/"), "javascript:alert(1)",
  ]) {
    assert.equal(descriptorUrlForExtension({ ...item, descriptor_url }), null, descriptor_url);
    assert.throws(() => normalizeCatalog(catalog([], [], [{ ...item, descriptor_url }])), /Invalid extension descriptor URL/);
  }
});

test("duplicated, oversized and non-array extension lists fail closed", () => {
  assert.throws(() => normalizeCatalog(catalog([], [], [extension(), extension()])), /Duplicated catalog extension/);
  const sameId = extension({ plugin_id: "dingtalk-notifier", namespace: "official/dingtalk-notifier" });
  assert.throws(() => normalizeCatalog(catalog([], [], [extension(), sameId])), /Duplicated catalog extension/);
  for (const extensions of [null, {}, "extensions", 5, false]) {
    assert.throws(() => normalizeCatalog(catalog([], [], extensions)), /Invalid plugin catalog/);
  }
  assert.throws(() => normalizeCatalog(catalog([], [], Array.from({ length: 10001 }, () => extension()))), /Invalid plugin catalog/);
});

test("planned packs share search, category and trust filters with releases", () => {
  const { plugins, extensions } = normalizeCatalog(catalog([
    release("audit-report", 2), release("sqli-rules", 5),
  ], [], [
    extension(),
    extension({ extension_id: "official-s3-archive-1.0.0", plugin_id: "s3-archive", namespace: "official/s3-archive", type: "storage-provider", title: "S3 archive", summary: "Planned S3 audit archive destination." }),
  ]));
  const items = [...plugins, ...extensions];
  assert.equal(items.length, 4);
  assert.deepEqual(filterCatalog(items, { category: "notifications" }).map(x => x.name), ["Feishu bot"]);
  assert.deepEqual(filterCatalog(items, { query: "S3 ARCHIVE" }).map(x => x.name), ["S3 archive"]);
  assert.deepEqual(filterCatalog(items, { query: "storage-provider" }).map(x => x.name), ["S3 archive"]);
  assert.deepEqual(filterCatalog(items, { query: "planned" }).map(x => x.name), ["Feishu bot", "S3 archive"]);
  assert.equal(filterCatalog(items, { trust: "official" }).length, 4);
  assert.equal(filterCatalog(items, { trust: "community" }).length, 0);
  assert.deepEqual(filterCatalog(items, { sort: "newest" }).map(x => x.name), ["sqli-rules", "audit-report", "Feishu bot", "S3 archive"]);
  assert.deepEqual(filterCatalog(items, { sort: "name" }).map(x => x.name), ["audit-report", "Feishu bot", "S3 archive", "sqli-rules"]);
  for (const item of extensions) assert.equal(item.downloadUrl, null);
});

test("a verified release for the same namespace displaces its planned pack", () => {
  const { plugins, extensions } = normalizeCatalog(catalog([release("feishu-notifier", 3)], [], [extension()]));
  assert.equal(plugins.length, 1);
  assert.deepEqual(extensions, []);
  assert.equal(plugins[0].downloadUrl, plugins[0].raw.crp.resource_url);
  assert.equal(plugins[0].name, "feishu-notifier");
});

test("planned packs never inherit release lifecycle or download metadata", () => {
  const [item] = normalizeCatalog(catalog([], [], [
    extension({ plugin_id: "hello-cheesesec-linux-amd64", namespace: "official/hello-cheesesec-linux-amd64", title: "Hello CheeseSec" }),
  ])).extensions;
  assert.equal(item.downloadUrl, null);
  assert.equal(item.lifecycleExample, null);
  assert.equal(item.sha256, null);
  assert.equal(Object.hasOwn(item.raw, "crp"), false);
  assert.equal(lifecycleExampleForRelease(item.raw), null);
});

const schema = JSON.parse(readFileSync(new URL("../schema/store-v1/catalog.schema.json", import.meta.url), "utf8"));

test("catalog schema keeps the planned extension contract optional and strict", () => {
  assert.deepEqual(schema.required, ["api_version", "catalog_sequence", "releases", "withdrawals"], "extensions stays optional");
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(schema.properties.extensions.items, { "$ref": "#/$defs/extension" });
  assert.equal(schema.properties.extensions.uniqueItems, true);
  assert.equal(schema.properties.extensions.maxItems, 10000);
  const item = schema.$defs.extension;
  assert.equal(item.additionalProperties, false);
  assert.deepEqual(item.required, ["extension_id", "plugin_id", "namespace", "type", "version", "status", "installable", "title", "summary", "descriptor_sha256", "descriptor_url"]);
  assert.deepEqual(item.properties.type.enum, ["notifier-provider", "storage-provider", "extension-descriptor"]);
  assert.deepEqual(item.properties.status.enum, ["planned", "available"]);
  assert.equal(item.properties.installable.type, "boolean");
  assert.deepEqual(item.properties.install_mode.enum, ["descriptor", "builtin"]);
  assert.ok(Object.keys(item.properties).length >= item.required.length);
  for (const [field, value] of Object.entries(extension())) {
    const rule = item.properties[field];
    assert.ok(rule, `${field} is declared`);
    if (rule.pattern) assert.match(value, new RegExp(rule.pattern), field);
    if (rule.maxLength) assert.ok(value.length <= rule.maxLength, field);
  }
  assert.doesNotMatch("feishu-notifier.crp", new RegExp(item.properties.descriptor_url.pattern));
  assert.doesNotMatch(" Feishu bot", new RegExp(item.properties.title.pattern));
  assert.doesNotMatch("Feishu bot ", new RegExp(item.properties.title.pattern));
});

test("built-in extensions project as available without becoming a download", () => {
  const record = extension({ status: "available", installable: true, install_mode: "builtin", plugin_id: "notifier-datadog" });
  const { extensions } = normalizeCatalog(catalog([], [], [record]));
  assert.equal(extensions.length, 1);
  const [item] = extensions;
  assert.equal(item.available, true);
  assert.equal(item.planned, false);
  assert.equal(item.installable, true);
  assert.equal(item.installMode, "builtin");
  assert.equal(item.downloadUrl, null);
  assert.equal(item.sha256, null);
});

test("example releases are categorized separately and sort last", () => {
  const exampleRelease = release("hello-cheesesec-linux-amd64", 1, { version: "0.1.0", release_id: "official/hello-cheesesec-linux-amd64@0.1.0#1" });
  const { plugins } = normalizeCatalog(catalog([exampleRelease, release("ordinary", 2)]));
  const ordinary = plugins.find(plugin => plugin.pluginId === "ordinary");
  const example = plugins.find(plugin => plugin.lifecycleExample);
  assert.ok(ordinary);
  assert.ok(example);
  assert.equal(example.category, "examples");
  assert.equal(filterCatalog(plugins, { category: "examples" }).length, 1);
});
