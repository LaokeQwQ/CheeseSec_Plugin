// Display projections only. Runtime signature verification and installation
// remain the responsibility of the host product, never the browser.
const TRUST_LEVELS = new Set(["official", "enterprise", "community", "personal", "test", "development"]);
const NAMESPACE = /^(?:official\/[A-Za-z0-9][A-Za-z0-9_.-]{0,63}|(?:enterprise|community|personal|test|development)\/[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,63})$/;
const PLUGIN_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const VERSION = /^[0-9]+(?:\.[0-9]+){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const SHA256 = /^[0-9a-f]{64}$/;
const RESOURCE = /^https:\/\/res\.cheesesec\.com\/sha256\/([0-9a-f]{64})\/([A-Za-z0-9][A-Za-z0-9._+-]{0,249}\.crp)$/;
const DESCRIPTOR = /^https:\/\/res\.cheesesec\.com\/sha256\/([0-9a-f]{64})\/([A-Za-z0-9][A-Za-z0-9._+-]{0,249}\.json)$/;
const EXTENSION_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const EXTENSION_TYPES = new Set(["notifier-provider", "storage-provider", "extension-descriptor"]);
// Planned packs reuse the release categories so search, filters and sorting stay
// one surface: notification destinations are integrations, storage destinations
// are archive/audit targets, and generic descriptors are developer tooling.
const EXTENSION_CATEGORIES = new Map([
  ["notifier-provider", "notifications"],
  ["storage-provider", "analysis"],
  ["extension-descriptor", "tools"],
]);
const HELLO_PLATFORMS = new Map([
  ["hello-cheesesec-linux-amd64", { platform: "linux-amd64", platformLabel: "Linux · amd64" }],
  ["hello-cheesesec-darwin-arm64", { platform: "darwin-arm64", platformLabel: "macOS · arm64" }],
]);

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function boundedString(value, max = 128) {
  return typeof value === "string" && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
}

function safeSequence(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

export function downloadUrlForRelease(record) {
  const value = record?.crp?.resource_url;
  const sha256 = record?.crp?.digests?.sha256;
  if (typeof value !== "string" || !SHA256.test(sha256)) return null;
  const match = RESOURCE.exec(value);
  if (!match || match[1] !== sha256 || match[2].includes("..")) return null;
  // The canonical spelling rejects credentials, explicit ports, URL queries,
  // fragments and encoded filenames before a browser ever receives the link.
  const parsed = new URL(value);
  return parsed.protocol === "https:" && parsed.hostname === "res.cheesesec.com"
    && !parsed.username && !parsed.password && !parsed.port && !parsed.search && !parsed.hash
    && parsed.href === value ? value : null;
}

export function descriptorUrlForExtension(record) {
  const value = record?.descriptor_url;
  const sha256 = record?.descriptor_sha256;
  if (typeof value !== "string" || !SHA256.test(sha256)) return null;
  const match = DESCRIPTOR.exec(value);
  if (!match || match[1] !== sha256 || match[2].includes("..")) return null;
  // A planned pack points at its immutable descriptor only. It must pass the same
  // canonical-URL checks as a release download, and it can never be an archive.
  const parsed = new URL(value);
  return parsed.protocol === "https:" && parsed.hostname === "res.cheesesec.com"
    && !parsed.username && !parsed.password && !parsed.port && !parsed.search && !parsed.hash
    && parsed.href === value ? value : null;
}

export function lifecycleExampleForRelease(record) {
  const platform = HELLO_PLATFORMS.get(record?.plugin_id);
  if (!platform || record.namespace !== `official/${record.plugin_id}`
    || record.trust_level !== "official" || record.version !== "0.1.0") return null;
  return { ...platform, name: "Hello CheeseSec", kind: "lifecycle-example" };
}

export function categoryForRelease(record) {
  const name = typeof record?.plugin_id === "string" ? record.plugin_id.toLowerCase() : "";
  if (/(?:^|[_.-])(?:intel|intelligence|reputation|feed)(?:$|[_.-])/.test(name)) return "intelligence";
  if (/(?:^|[_.-])(?:notification|notifications|notifier|webhook|feishu|wecom|telegram|email)(?:$|[_.-])/.test(name)) return "notifications";
  if (/(?:^|[_.-])(?:analysis|analytics|audit|duckdb|report)(?:$|[_.-])/.test(name)) return "analysis";
  if (/(?:^|[_.-])(?:detection|detector|security|rules|waf|bot|sqli|xss)(?:$|[_.-])/.test(name)) return "security";
  return "tools";
}

function projectRelease(record) {
  if (!object(record)) throw new Error("Invalid catalog release");
  // Contract fixtures and records awaiting approval are never storefront items.
  if (record.record_type !== "publication" || record.review?.decision !== "approved" || record.signature_evidence?.status !== "verified") return null;
  if (record.api_version !== "store.cheesesec.com/v1" || record.immutable !== true
    || !boundedString(record.plugin_id, 64) || !PLUGIN_ID.test(record.plugin_id)
    || !boundedString(record.namespace, 196) || !NAMESPACE.test(record.namespace)
    || !TRUST_LEVELS.has(record.trust_level) || record.namespace.split("/")[0] !== record.trust_level
    || !boundedString(record.version, 128) || !VERSION.test(record.version)
    || !safeSequence(record.release_sequence)
    || record.release_id !== `${record.namespace}@${record.version}#${record.release_sequence}`
    || !boundedString(record.source)
    || !object(record.crp) || !safeSequence(record.crp.size) || record.crp.size > 1073741824
    || !object(record.crp.digests) || !SHA256.test(record.crp.digests.sha256)) {
    throw new Error("Invalid published catalog release");
  }
  const downloadUrl = downloadUrlForRelease(record);
  if (!downloadUrl) throw new Error("Invalid published resource URL");
  const lifecycleExample = lifecycleExampleForRelease(record);
  return {
    id: record.release_id,
    namespace: record.namespace,
    name: lifecycleExample?.name || record.plugin_id || record.namespace.split("/").at(-1),
    pluginId: record.plugin_id,
    version: record.version,
    trustLevel: record.trust_level,
    category: categoryForRelease(record),
    releaseSequence: record.release_sequence,
    sha256: record.crp.digests.sha256,
    size: record.crp.size,
    source: record.source,
    downloadUrl,
    lifecycleExample,
    raw: record,
  };
}

function projectExtension(record) {
  if (!object(record)) throw new Error("Invalid catalog extension");
  // Planned packs are descriptor-only by contract: no other status and no
  // truthy installability may ever reach a storefront card.
  if (record.status !== "planned" || record.installable !== false || !EXTENSION_TYPES.has(record.type)) {
    throw new Error("Invalid catalog extension");
  }
  if (!boundedString(record.extension_id, 128) || !EXTENSION_ID.test(record.extension_id)
    || !boundedString(record.plugin_id, 64) || !PLUGIN_ID.test(record.plugin_id)
    || !boundedString(record.namespace, 196) || !NAMESPACE.test(record.namespace)
    || !boundedString(record.version, 128) || !VERSION.test(record.version)
    || !boundedString(record.title, 96) || record.title.trim() !== record.title
    || !boundedString(record.summary, 280) || record.summary.trim() !== record.summary
    || typeof record.descriptor_sha256 !== "string" || !SHA256.test(record.descriptor_sha256)) {
    throw new Error("Invalid catalog extension");
  }
  const descriptorUrl = descriptorUrlForExtension(record);
  if (!descriptorUrl) throw new Error("Invalid extension descriptor URL");
  return {
    id: record.extension_id,
    kind: "extension",
    planned: true,
    installable: false,
    extensionType: record.type,
    namespace: record.namespace,
    name: record.title,
    pluginId: record.plugin_id,
    version: record.version,
    trustLevel: record.namespace.split("/")[0],
    category: EXTENSION_CATEGORIES.get(record.type) || "tools",
    // Planned packs sort after every published release under "newest".
    releaseSequence: -1,
    summary: record.summary,
    sha256: null,
    descriptorSha256: record.descriptor_sha256,
    descriptorUrl,
    downloadUrl: null,
    lifecycleExample: null,
    raw: record,
  };
}

export function normalizeCatalog(payload) {
  if (!object(payload) || payload.api_version !== "store.cheesesec.com/v1"
    || !safeSequence(payload.catalog_sequence) || !Array.isArray(payload.releases)
    || !Array.isArray(payload.withdrawals) || payload.releases.length > 10000 || payload.withdrawals.length > 10000
    || (payload.extensions !== undefined
      && (!Array.isArray(payload.extensions) || payload.extensions.length > 10000))) {
    throw new Error("Invalid plugin catalog");
  }
  const withdrawals = new Set();
  for (const withdrawal of payload.withdrawals) {
    if (!object(withdrawal) || !boundedString(withdrawal.release_id, 400)) throw new Error("Invalid catalog withdrawal");
    withdrawals.add(withdrawal.release_id);
  }
  const latest = new Map();
  const releaseIds = new Set();
  for (const record of payload.releases) {
    const plugin = projectRelease(record);
    if (!plugin) continue;
    if (releaseIds.has(plugin.id)) throw new Error("Duplicated catalog release");
    releaseIds.add(plugin.id);
    if (withdrawals.has(plugin.id)) continue;
    const previous = latest.get(plugin.namespace);
    if (!previous || plugin.releaseSequence > previous.releaseSequence) latest.set(plugin.namespace, plugin);
    else if (plugin.releaseSequence === previous.releaseSequence) throw new Error("Conflicting catalog release sequence");
  }
  const plugins = filterCatalog([...latest.values()]);
  // A namespace that already ships a verified CRP release wins: a planned pack
  // must never shadow or duplicate an installable release card.
  const published = new Set(plugins.map(plugin => plugin.namespace));
  const extensions = [];
  const extensionIds = new Set();
  for (const record of payload.extensions || []) {
    const extension = projectExtension(record);
    if (extensionIds.has(extension.id)) throw new Error("Duplicated catalog extension");
    extensionIds.add(extension.id);
    if (published.has(extension.namespace)) continue;
    extensions.push(extension);
  }
  extensions.sort((a, b) => a.name.localeCompare(b.name, "en", { numeric: true, sensitivity: "base" })
    || a.namespace.localeCompare(b.namespace) || a.extensionType.localeCompare(b.extensionType));
  return { plugins, extensions, sequence: payload.catalog_sequence };
}

export function filterCatalog(plugins, { query = "", category = "all", trust = "all", sort = "newest" } = {}) {
  const search = typeof query === "string" ? query.normalize("NFKC").trim().toLowerCase() : "";
  const filtered = plugins.filter(plugin => {
    const haystack = [plugin.name, plugin.pluginId, plugin.namespace, plugin.version, plugin.source, plugin.extensionType, plugin.summary, plugin.lifecycleExample?.platformLabel].join(" ").normalize("NFKC").toLowerCase();
    return (!search || haystack.includes(search))
      && (category === "all" || plugin.category === category)
      && (trust === "all" || plugin.trustLevel === trust);
  });
  return filtered.sort(sort === "name"
    ? (a, b) => a.name.localeCompare(b.name, "en", { numeric: true, sensitivity: "base" })
      || a.namespace.localeCompare(b.namespace) || (a.extensionType || "").localeCompare(b.extensionType || "")
    : (a, b) => b.releaseSequence - a.releaseSequence || a.namespace.localeCompare(b.namespace) || compareName(a, b));
}

function compareName(a, b) {
  return a.name.localeCompare(b.name, "en", { numeric: true, sensitivity: "base" });
}
