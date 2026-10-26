#!/usr/bin/env node
// Initial public metadata publication only. This never publishes CRP or trust material.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readFile, realpath, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const CHANNELS = ['stable', 'canary', 'dev'];
const SCHEMAS = {
  'crp-v1': ['manifest', 'signatures'],
  'store-v1': ['catalog', 'cwedp', 'endpoint-policy', 'offline-import', 'ota', 'release',
    'revocations', 'sidecar-descriptor', 'source-registry', 'trust-levels', 'trust-roots'],
};
const decoder = new TextDecoder('utf-8', { fatal: true });
const digest = data => createHash('sha256').update(data).digest('hex');
const exactFields = (value, names) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join('\0') === [...names].sort().join('\0');
function requireThat(condition, message) { if (!condition) throw new Error(message); }
function json(data, label) {
  try { return JSON.parse(decoder.decode(data)); }
  catch { throw new Error(`invalid UTF-8 JSON: ${label}`); }
}
function validSequence(sequence) {
  return Number.isSafeInteger(sequence) && sequence > 0;
}

async function safeRead(root, relative) {
  requireThat(typeof relative === 'string' && !isAbsolute(relative) && relative !== ''
    && !relative.includes('\\') && relative.split('/').every(x => x && x !== '.' && x !== '..'),
  'unsafe bundle file path');
  const file = resolve(root, relative);
  requireThat(file.startsWith(root + sep), 'bundle file escapes root');
  let path = root;
  for (const [index, part] of relative.split('/').entries()) {
    path = join(path, part);
    const stat = await lstat(path);
    requireThat(!stat.isSymbolicLink(), `symlink in bundle path: ${relative}`);
    requireThat(index === relative.split('/').length - 1 ? stat.isFile() : stat.isDirectory(),
      `non-regular bundle path: ${relative}`);
  }
  const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    requireThat(before.isFile() && before.size <= 4 * 1024 * 1024, `bundle file exceeds 4 MiB: ${relative}`);
    const data = await handle.readFile();
    const after = await handle.stat();
    requireThat(before.isFile() && before.size <= 4 * 1024 * 1024 && data.length === before.size
      && before.dev === after.dev && before.ino === after.ino && before.size === after.size
      && before.mtimeMs === after.mtimeMs, `bundle file changed or exceeds 4 MiB: ${relative}`);
    return data;
  } finally { await handle.close(); }
}

export async function validateBootstrap(bundlePath) {
  const initialStat = await lstat(bundlePath);
  requireThat(initialStat.isDirectory() && !initialStat.isSymbolicLink(), 'bundle root must be a real directory');
  const root = await realpath(bundlePath);
  const manifest = json(await safeRead(root, 'bundle-manifest.json'), 'bundle manifest');
  requireThat(exactFields(manifest, ['format', 'source_commit', 'sequence', 'channel', 'objects', 'bootstrap_public_only'])
    && manifest.format === 'cheesesec-publication-bundle-v1' && manifest.bootstrap_public_only === true,
  'only explicit public bootstrap bundles are accepted');
  requireThat(validSequence(manifest.sequence) && /^[0-9a-f]{40}$/.test(manifest.source_commit),
    'invalid bootstrap sequence or source commit');
  requireThat(CHANNELS.includes(manifest.channel) || manifest.channel === 'all', 'invalid bootstrap channel');
  requireThat(Array.isArray(manifest.objects) && manifest.objects.length > 0 && manifest.objects.length <= 200,
    'invalid bootstrap object list');
  const sequenceText = String(manifest.sequence).padStart(20, '0');
  const channels = manifest.channel === 'all' ? CHANNELS : [manifest.channel];
  const expected = new Set(['catalog/index.json', 'pointers/catalog.json',
    `indexes/catalog/seq-${sequenceText}.json`, 'policy/endpoints.json',
    `indexes/policy/seq-${sequenceText}/endpoints.json`]);
  for (const channel of channels) {
    expected.add(`ota/channels/${channel}/index.json`);
    expected.add(`indexes/ota/${channel}/seq-${sequenceText}.json`);
    expected.add(`pointers/ota/${channel}.json`);
  }
  for (const [scope, names] of Object.entries(SCHEMAS)) for (const name of names) {
    expected.add(`schema/${scope}/${name}.schema.json`);
    expected.add(`indexes/policy/seq-${sequenceText}/${scope}/${name}.schema.json`);
  }
  const objects = new Map();
  for (const item of manifest.objects) {
    requireThat(exactFields(item, ['key', 'file', 'size', 'sha256', 'content_type', 'cache_class'])
      && expected.has(item.key) && item.file === item.key && !objects.has(item.key),
    'unapproved, duplicated or unsafe bootstrap object');
    requireThat(Number.isSafeInteger(item.size) && item.size > 0 && item.size <= 4 * 1024 * 1024
      && /^[0-9a-f]{64}$/.test(item.sha256) && item.content_type === 'application/json; charset=utf-8'
      && item.cache_class === 'short-revalidate', `invalid metadata: ${item.key}`);
    const data = await safeRead(root, item.file);
    requireThat(data.length === item.size && digest(data) === item.sha256, `bundle digest mismatch: ${item.key}`);
    requireThat(!decoder.decode(data).includes('official-demo-'), `demo trust material rejected: ${item.key}`);
    objects.set(item.key, { ...item, data, value: json(data, item.key) });
  }
  requireThat(objects.size === expected.size && [...expected].every(key => objects.has(key)),
    'bootstrap must contain the complete fixed metadata set');
  function index(key, kind) {
    const value = objects.get(key).value;
    if (kind === 'catalog') {
      requireThat(exactFields(value, ['api_version', 'catalog_sequence', 'releases', 'withdrawals'])
        && value.api_version === 'store.cheesesec.com/v1' && value.catalog_sequence === manifest.sequence
        && Array.isArray(value.releases) && value.releases.length === 0
        && Array.isArray(value.withdrawals) && value.withdrawals.length === 0, 'bootstrap catalog must be empty');
    } else {
      requireThat(exactFields(value, ['api_version', 'index_sequence', 'mode', 'releases'])
        && value.api_version === 'ota.cheesesec.com/v1' && value.index_sequence === manifest.sequence
        && value.mode === 'pull-only' && Array.isArray(value.releases) && value.releases.length === 0,
      'bootstrap OTA index must be empty and pull-only');
    }
  }
  function same(first, second) {
    requireThat(objects.get(first).data.equals(objects.get(second).data), `alias/history mismatch: ${first}`);
  }
  function pointer(key, target, channel) {
    const value = objects.get(key).value;
    requireThat(exactFields(value, channel ? ['channel', 'sequence', 'key', 'sha256'] : ['sequence', 'key', 'sha256'])
      && value.sequence === manifest.sequence && value.key === target && value.sha256 === objects.get(target).sha256
      && (!channel || value.channel === channel), `invalid pointer: ${key}`);
  }
  index('catalog/index.json', 'catalog');
  const catalogKey = `indexes/catalog/seq-${sequenceText}.json`;
  same('catalog/index.json', catalogKey);
  pointer('pointers/catalog.json', catalogKey);
  for (const channel of channels) {
    const key = `ota/channels/${channel}/index.json`;
    const historyKey = `indexes/ota/${channel}/seq-${sequenceText}.json`;
    index(key, 'ota'); same(key, historyKey); pointer(`pointers/ota/${channel}.json`, historyKey, channel);
  }
  same('policy/endpoints.json', `indexes/policy/seq-${sequenceText}/endpoints.json`);
  for (const [scope, names] of Object.entries(SCHEMAS)) for (const name of names) {
    const key = `schema/${scope}/${name}.schema.json`;
    const schema = objects.get(key).value;
    const schemaHost = scope === 'store-v1' && name === 'ota' ? 'ota' : 'store';
    const schemaPath = scope === 'store-v1' ? 'store/v1' : 'crp/v1';
    requireThat(schema && typeof schema === 'object' && !Array.isArray(schema)
      && typeof schema.$schema === 'string' && typeof schema.$id === 'string'
      && schema.$id === `https://${schemaHost}.cheesesec.com/schema/${schemaPath}/${name}.schema.json`,
    `invalid public schema: ${key}`);
    same(key, `indexes/policy/seq-${sequenceText}/${scope}/${name}.schema.json`);
  }
  const endpoints = objects.get('policy/endpoints.json').value;
  requireThat(endpoints?.api_version === 'store.cheesesec.com/v1', 'invalid endpoint policy');
  return { manifest, objects };
}

export async function publishBootstrap(env, bundlePath, { apply = false, receiptPath } = {}) {
  const { manifest, objects } = await validateBootstrap(bundlePath);
  if (receiptPath) {
    receiptPath = join(await realpath(dirname(resolve(receiptPath))), basename(receiptPath));
    requireThat(!receiptPath.startsWith(await realpath(bundlePath) + sep),
      'receipt must be outside the publication bundle');
    try { await lstat(receiptPath); throw new Error('receipt destination already exists'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const receipt = { format: 'cheesesec-publication-receipt-v1', source_commit: manifest.source_commit,
    sequence: manifest.sequence, channel: manifest.channel, applied: apply, created: [], unchanged: [],
    objects: [...objects.values()].map(({key,size,sha256}) => ({key,size,sha256})) };
  if (!apply) {
    if (receiptPath) await writeReceipt(receiptPath, receipt);
    return receipt;
  }
  const bucket = env?.PUBLICATION_INDEX;
  requireThat(bucket && ['list', 'get', 'put'].every(key => typeof bucket[key] === 'function'), 'PUBLICATION_INDEX R2 binding required');
  const existing = new Set();
  let cursor;
  do {
    const batch = await bucket.list({limit:1000, cursor});
    requireThat(batch && Array.isArray(batch.objects) && typeof batch.truncated === 'boolean', 'invalid bucket inventory response');
    for (const item of batch.objects) {
      requireThat(objects.has(item.key) && !existing.has(item.key), 'bucket is not an empty or exact-resume bootstrap target');
      existing.add(item.key);
    }
    requireThat(!batch.truncated || (typeof batch.cursor === 'string' && batch.cursor && batch.cursor !== cursor), 'invalid bucket inventory cursor');
    cursor = batch.truncated ? batch.cursor : undefined;
  } while (cursor);
  for (const key of existing) {
    const object = await bucket.get(key);
    requireThat(object && object.size === objects.get(key).size && typeof object.arrayBuffer === 'function',
      `listed object could not be read or has conflicting size: ${key}`);
    const data = Buffer.from(await object.arrayBuffer());
    requireThat(data.equals(objects.get(key).data), `existing object conflicts: ${key}`);
  }
  const phase = key => key.startsWith('indexes/') ? 0 : key.startsWith('pointers/') ? 2 : 1;
  const ordered = [...objects.values()].sort((a,b)=>phase(a.key)-phase(b.key)||a.key.localeCompare(b.key));
  try {
    for (const item of ordered) {
      if (existing.has(item.key)) { receipt.unchanged.push(item.key); continue; }
      const result = await bucket.put(item.key, item.data, {
        onlyIf: new Headers({'if-none-match':'*'}), sha256: item.sha256,
        httpMetadata:{contentType:item.content_type,cacheControl:'public, max-age=60, s-maxage=60, must-revalidate'},
        customMetadata:{sequence:String(manifest.sequence),source_commit:manifest.source_commit},
      });
      if (result === null) {
        const raced = await bucket.get(item.key);
        requireThat(raced && raced.size === item.size && typeof raced.arrayBuffer === 'function'
          && Buffer.from(await raced.arrayBuffer()).equals(item.data), `conditional create conflict: ${item.key}`);
        receipt.unchanged.push(item.key);
      } else { receipt.created.push(item.key); }
      const saved = await bucket.get(item.key);
      requireThat(saved && saved.size === item.size && typeof saved.arrayBuffer === 'function'
        && Buffer.from(await saved.arrayBuffer()).equals(item.data), `post-write verification failed: ${item.key}`);
    }
    receipt.verified = true;
    if (receiptPath) await writeReceipt(receiptPath, receipt);
    return receipt;
  } catch (error) {
    receipt.verified = false;
    receipt.error = error.message;
    if (receiptPath) {
      try { await writeReceipt(receiptPath, receipt); }
      catch (receiptError) { error.message += `; receipt write failed: ${receiptError.message}`; }
    }
    throw error;
  }
}

async function writeReceipt(path, receipt) {
  // Never replace an existing receipt or write into the source bundle.
  await writeFile(path, JSON.stringify(receipt, null, 2) + '\n', { flag:'wx', mode:0o600 });
}

async function main(args) {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--apply') { requireThat(!options.apply, 'duplicate --apply'); options.apply = true; }
    else {
      const name = {'--bundle':'bundle','--config':'config','--wrangler-module':'wranglerModule','--receipt':'receiptPath'}[args[i]];
      requireThat(name && !options[name] && args[i + 1] && !args[i + 1].startsWith('--'), 'usage: publish_bootstrap.mjs --bundle DIR [--config JSON --wrangler-module PATH --apply] [--receipt FILE]');
      options[name] = args[++i];
    }
  }
  requireThat(options.bundle, '--bundle is required');
  // Full local validation happens even before a Wrangler remote session is opened.
  await validateBootstrap(options.bundle);
  let platform;
  try {
    if (options.apply) {
      requireThat(options.config && options.wranglerModule, '--config and --wrangler-module required for apply');
      const config = json(await readFile(options.config), 'Wrangler config');
      const bindings = config.r2_buckets;
      requireThat(/^[0-9a-f]{32}$/.test(config.account_id) && Array.isArray(bindings) && bindings.length === 1
        && bindings[0].binding === 'PUBLICATION_INDEX' && bindings[0].remote === true
        && ['cheesesec-publication-index-prod', 'cheesesec-publication-bootstrap-staging'].includes(bindings[0].bucket_name)
        && !config.routes?.length && !config.assets && !config.main, 'apply requires an explicit remote metadata-only Wrangler config');
      const wrangler = await import(pathToFileURL(resolve(options.wranglerModule)).href);
      platform = await wrangler.getPlatformProxy({configPath:resolve(options.config),remoteBindings:true,persist:false,envFiles:[]});
    }
    const result = await publishBootstrap(platform?.env, options.bundle, options);
    console.log(JSON.stringify(result, null, 2));
  } finally { await platform?.dispose(); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
}
