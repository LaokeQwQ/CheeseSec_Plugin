// Display projections only. Runtime signature verification and installation
// remain the responsibility of the host product, never the browser.
const TRUST_LEVELS = new Set(["official", "enterprise", "community", "personal", "test", "development"]);
const NAMESPACE = /^(?:official\/[A-Za-z0-9][A-Za-z0-9_.-]{0,63}|(?:enterprise|community|personal|test|development)\/[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,63})$/;
const PLUGIN_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const VERSION = /^[0-9]+(?:\.[0-9]+){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const SHA256 = /^[0-9a-f]{64}$/;

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function boundedString(value, max = 128) {
  return typeof value === "string" && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
}

function safeSequence(value) {
  return Number.isSafeInteger(value) && value >= 0;
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
  return {
    id: record.release_id,
    namespace: record.namespace,
    name: record.plugin_id || record.namespace.split("/").at(-1),
    version: record.version,
    trustLevel: record.trust_level,
    category: categoryForRelease(record),
    releaseSequence: record.release_sequence,
    sha256: record.crp.digests.sha256,
    size: record.crp.size,
    source: record.source,
    raw: record,
  };
}

export function normalizeCatalog(payload) {
  if (!object(payload) || payload.api_version !== "store.cheesesec.com/v1"
    || !safeSequence(payload.catalog_sequence) || !Array.isArray(payload.releases)
    || !Array.isArray(payload.withdrawals) || payload.releases.length > 10000 || payload.withdrawals.length > 10000) {
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
  return { plugins: filterCatalog([...latest.values()]), sequence: payload.catalog_sequence };
}

export function filterCatalog(plugins, { query = "", category = "all", trust = "all", sort = "newest" } = {}) {
  const search = typeof query === "string" ? query.normalize("NFKC").trim().toLowerCase() : "";
  const filtered = plugins.filter(plugin => {
    const haystack = [plugin.name, plugin.namespace, plugin.version, plugin.source].join(" ").normalize("NFKC").toLowerCase();
    return (!search || haystack.includes(search))
      && (category === "all" || plugin.category === category)
      && (trust === "all" || plugin.trustLevel === trust);
  });
  return filtered.sort(sort === "name"
    ? (a, b) => a.name.localeCompare(b.name, "en", { numeric: true, sensitivity: "base" }) || a.namespace.localeCompare(b.namespace)
    : (a, b) => b.releaseSequence - a.releaseSequence || a.namespace.localeCompare(b.namespace));
}
