#!/usr/bin/env node
// Publish verified CRP resources before changing the catalog with ETag CAS.
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { constants } from 'node:fs';
import { lstat, open, readFile, realpath, writeFile } from 'node:fs/promises';
import { resolve, join, sep, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const runFile = promisify(execFile);
const digest = value => createHash('sha256').update(value).digest('hex');
const check = (condition, message) => { if (!condition) throw new Error(message); };
const parse = bytes => JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(bytes));
const MAX_BYTES = 128 * 1024 * 1024;
const FIXED_POLICY = ['policy/trust-roots.json', 'policy/source-registry.json', 'policy/revocations.json'];

async function safeRead(root, name) {
  check(typeof name === 'string' && !name.includes('\\') && name.split('/').every(part => part && part !== '.' && part !== '..'), 'unsafe bundle path');
  const path = resolve(root, name);
  check(path.startsWith(root + sep), 'bundle path escapes root');
  let current = root;
  const parts = name.split('/');
  for (const [index, part] of parts.entries()) {
    current = join(current, part);
    const stat = await lstat(current);
    check(!stat.isSymbolicLink() && (index === parts.length - 1 ? stat.isFile() : stat.isDirectory()), 'symlink or non-regular path in bundle');
  }
  const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const before = await handle.stat();
    check(before.isFile() && before.size > 0 && before.size <= MAX_BYTES, 'invalid bundle file size or type');
    const data = await handle.readFile();
    const after = await handle.stat();
    check(data.length === before.size && before.size === after.size && before.ino === after.ino && before.dev === after.dev && before.mtimeMs === after.mtimeMs, 'bundle file changed during read');
    return data;
  } finally { await handle.close(); }
}

export async function validateBundle(bundlePath, python = 'python3') {
  const initial = await lstat(bundlePath);
  check(initial.isDirectory() && !initial.isSymbolicLink(), 'bundle must be a real directory');
  const root = await realpath(bundlePath);
  // Invoke the same offline schema/archive/Ed25519 gate for dry-run and apply.
  const verifier = join(dirname(fileURLToPath(import.meta.url)), 'build_signed_release.py');
  const verified = await runFile(python, [verifier, 'validate', '--bundle', root], {maxBuffer:1024*1024});
  const report = JSON.parse(verified.stdout);
  const manifestBytes = await safeRead(root, 'bundle-manifest.json');
  check(report.verified === true && report.bundle_manifest_sha256 === digest(manifestBytes), 'bundle changed after cryptographic verification');
  const manifest = parse(manifestBytes);
  check(manifest.format === 'cheesesec-signed-release-v1' && /^[0-9a-f]{40}$/.test(manifest.source_commit)
    && Number.isSafeInteger(manifest.catalog_sequence) && manifest.catalog_sequence > 1
    && /^[0-9a-f]{64}$/.test(manifest.previous_catalog_sha256)
    && manifest.previous_catalog_file === 'previous-catalog.json', 'invalid release manifest');
  const previousBytes = await safeRead(root, manifest.previous_catalog_file);
  check(digest(previousBytes) === manifest.previous_catalog_sha256, 'previous catalog snapshot is not exact');
  const previous = parse(previousBytes);
  const allowed = new Set([...FIXED_POLICY, 'catalog/index.json', 'pointers/catalog.json', `indexes/catalog/seq-${String(manifest.catalog_sequence).padStart(20,'0')}.json`]);
  check(Array.isArray(manifest.objects) && manifest.objects.length === 14, 'release bundle must contain exactly fourteen objects');
  const objects = new Map();
  for (const item of manifest.objects) {
    check(item.bucket === 'index' ? allowed.has(item.key) : item.bucket === 'resources'
      && /^resources\/sha256\/[0-9a-f]{64}\/[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$/.test(item.key), 'unapproved publication object');
    const id = item.bucket + '/' + item.key;
    check(!objects.has(id) && item.file === id && /^[0-9a-f]{64}$/.test(item.sha256)
      && Number.isSafeInteger(item.size) && item.size > 0 && item.size <= MAX_BYTES
      && ['application/octet-stream', 'application/json; charset=utf-8'].includes(item.content_type), 'invalid publication metadata');
    const data = await safeRead(root, item.file);
    check(data.length === item.size && digest(data) === item.sha256, 'publication digest mismatch');
    if (item.bucket === 'resources') check(item.key.split('/')[2] === item.sha256, 'resource address is not its digest');
    objects.set(id, {...item, data});
  }
  check([...allowed].every(key=>objects.has('index/'+key)) && [...objects.values()].filter(item=>item.bucket==='resources').length === 8, 'incomplete release bundle');
  const catalog = objects.get('index/catalog/index.json');
  const next = parse(catalog.data);
  check(next.catalog_sequence === previous.catalog_sequence + 1 && next.catalog_sequence === manifest.catalog_sequence, 'catalog sequence must increment exactly once');
  return {manifest, objects, previous, previousBytes, catalog};
}

async function savedBytes(bucket, key) {
  const object = await bucket.get(key);
  if (!object) return null;
  check(object.size > 0 && object.size <= MAX_BYTES && typeof object.etag === 'string', `invalid stored metadata: ${key}`);
  const data = Buffer.from(await object.arrayBuffer());
  check(data.length === object.size, `stored object size mismatch: ${key}`);
  return {etag:object.etag, size:object.size, customMetadata:object.customMetadata, data};
}

function optionsFor(item, etag, sequence) {
  return {onlyIf:etag ? new Headers({'if-match': '"'+etag.replaceAll('"','')+'"'}) : new Headers({'if-none-match':'*'}), sha256:item.sha256,
    httpMetadata:{contentType:item.content_type,cacheControl:item.bucket==='resources' ? 'public, max-age=31536000, immutable' : 'public, max-age=60, s-maxage=60, must-revalidate'},
    customMetadata:item.bucket==='index' ? {sequence:String(sequence),index_sequence:String(sequence)} : {}};
}

export async function publishRelease(env, validated, {apply=false} = {}) {
  const {manifest, objects, previous, previousBytes, catalog} = validated;
  const receipt = {format:'cheesesec-release-receipt-v1',release_id:manifest.release_id,catalog_sequence:manifest.catalog_sequence,source_commit:manifest.source_commit,applied:apply,created:[],unchanged:[],updated:[],verified:false};
  if (!apply) return {...receipt,planned:[...objects.values()].map(({bucket,key,size,sha256})=>({bucket,key,size,sha256}))};
  const index = env?.PUBLICATION_INDEX;
  const resources = env?.PUBLIC_RESOURCES;
  check(index && resources && [index,resources].every(bucket=>['get','put'].every(name=>typeof bucket[name]==='function')), 'both R2 publication bindings are required');
  const live = await savedBytes(index, 'catalog/index.json');
  check(live && (live.data.equals(previousBytes) || live.data.equals(catalog.data)), 'live catalog differs from reviewed snapshot; rebuild against current catalog');
  const pointerItem = objects.get('index/pointers/catalog.json');
  const pointer = await savedBytes(index,'pointers/catalog.json');
  check(pointer, 'existing catalog pointer is required');
  const pointerValue = parse(pointer.data);
  const resumed = live.data.equals(catalog.data);
  const expectedPointer = resumed && pointer.data.equals(pointerItem.data);
  check(expectedPointer || pointerValue.sequence === previous.catalog_sequence
    && pointerValue.sha256 === digest(previousBytes)
    && pointerValue.key === `indexes/catalog/seq-${String(previous.catalog_sequence).padStart(20,'0')}.json`, 'catalog pointer does not bind reviewed previous catalog');
  const staged = [...objects.values()].filter(item=>item.key!=='catalog/index.json' && item.key!=='pointers/catalog.json');
  // Complete preflight before any writes: trust material is create-only or byte-identical.
  for(const item of staged) {
    const bucket = item.bucket==='index' ? index : resources;
    const existing = await savedBytes(bucket,item.key);
    check(!existing || existing.data.equals(item.data), `immutable object conflicts: ${item.key}`);
  }
  for(const item of staged.sort((a,b)=>Number(a.bucket==='index')-Number(b.bucket==='index')||a.key.localeCompare(b.key))) {
    const bucket = item.bucket==='index' ? index : resources;
    const existing = await savedBytes(bucket,item.key);
    if(existing) {check(existing.data.equals(item.data),`immutable object changed: ${item.key}`);receipt.unchanged.push(item.key);continue;}
    const result = await bucket.put(item.key,item.data,optionsFor(item,undefined,manifest.catalog_sequence));
    const saved = await savedBytes(bucket,item.key);
    check(saved && saved.data.equals(item.data), `immutable write/read-back conflict: ${item.key}`);
    (result ? receipt.created : receipt.unchanged).push(item.key);
  }
  if(!resumed) {
    const result = await index.put(catalog.key,catalog.data,optionsFor(catalog,live.etag,manifest.catalog_sequence));
    const saved = await savedBytes(index,catalog.key);
    check(saved && saved.data.equals(catalog.data), 'catalog CAS conflict; newer catalog was preserved');
    (result ? receipt.updated : receipt.unchanged).push(catalog.key);
  } else receipt.unchanged.push(catalog.key);
  if(!expectedPointer) {
    const current = await savedBytes(index,catalog.key);
    check(current && current.data.equals(catalog.data),'catalog advanced before pointer update; leave newer state untouched');
    const result = await index.put(pointerItem.key,pointerItem.data,optionsFor(pointerItem,pointer.etag,manifest.catalog_sequence));
    const saved = await savedBytes(index,pointerItem.key);
    check(saved && saved.data.equals(pointerItem.data), 'pointer CAS conflict; rerun reviewed release to inspect');
    (result ? receipt.updated : receipt.unchanged).push(pointerItem.key);
  } else receipt.unchanged.push(pointerItem.key);
  const final = await savedBytes(index,catalog.key);
  check(final && final.data.equals(catalog.data), 'catalog changed during final verification');
  receipt.verified = true;
  return receipt;
}

async function main(args) {
  const options={};
  for(let i=0;i<args.length;i++) {
    if(args[i]==='--apply') {check(!options.apply,'duplicate apply');options.apply=true;continue;}
    const name={'--bundle':'bundle','--python':'python','--config':'config','--wrangler-module':'wranglerModule','--receipt':'receipt'}[args[i]];
    check(name && !options[name] && args[i+1] && !args[i+1].startsWith('--'),'invalid arguments');options[name]=args[++i];
  }
  check(options.bundle,'--bundle required');
  const validated=await validateBundle(options.bundle,options.python);
  if(options.receipt) {try{await lstat(options.receipt);throw new Error('receipt already exists');}catch(error){if(error.code!=='ENOENT')throw error;}}
  let platform;
  try {
    if(options.apply) {
      check(options.config && options.wranglerModule,'explicit remote config and Wrangler module required');
      const config=parse(await readFile(options.config));
      check(/^[0-9a-f]{32}$/.test(config.account_id) && !config.main && !config.assets && !config.routes?.length
        && config.r2_buckets?.length===2 && config.r2_buckets.every(binding=>binding.remote===true
          && (binding.binding==='PUBLICATION_INDEX' && ['cheesesec-publication-index-prod','cheesesec-publication-release-staging'].includes(binding.bucket_name)
            || binding.binding==='PUBLIC_RESOURCES' && ['cheesesec-public-resources-prod','cheesesec-public-resources-release-staging'].includes(binding.bucket_name))), 'apply requires a restricted two-bucket remote config');
      const names=new Set(config.r2_buckets.map(binding=>binding.binding));
      check(names.size===2,'duplicate bucket binding');
      const wrangler=await import(pathToFileURL(resolve(options.wranglerModule)).href);
      platform=await wrangler.getPlatformProxy({configPath:resolve(options.config),remoteBindings:true,persist:false,envFiles:[]});
    }
    const result=await publishRelease(platform?.env,validated,options);
    if(options.receipt) await writeFile(options.receipt,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
    console.log(JSON.stringify(result,null,2));
  } finally {await platform?.dispose();}
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) main(process.argv.slice(2)).catch(error=>{console.error(error.message);process.exitCode=1;});
