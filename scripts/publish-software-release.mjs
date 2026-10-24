#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFile, writeFile, mkdir, lstat } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const usage = `Usage: node publish-software-release.mjs --repo OWNER/REPO --tag vX.Y.Z --workdir DIR --cosign FILE --wrangler-config FILE [--wrangler-module FILE] [--channel stable] [--plan]

First runs verify-software-release.mjs (GitHub digests, signed checksums and SBOMs).
--plan verifies locally and writes software-index.json without connecting to R2.
Publishes only releases/<tag>/* and software/channels/stable/index.json, using the
PUBLIC_RESOURCES and PUBLICATION_INDEX buckets in the supplied Wrangler config.
Artifacts use conditional create, exact existing-byte verification, and readback.
The software index uses a conditional ETag update after all artifacts pass.
Credentials remain in Wrangler's authenticated environment. No production Worker is deployed.
`;
const args = new Map();
for (let i = 2; i < process.argv.length; i++) {
  const key = process.argv[i];
  if (key === '--help') { console.log(usage); process.exit(0); }
  if (key === '--plan') { args.set(key, true); continue; }
  if (!['--repo', '--tag', '--workdir', '--cosign', '--wrangler-config', '--wrangler-module', '--channel'].includes(key) || args.has(key) || !process.argv[i + 1] || process.argv[i + 1].startsWith('--')) throw new Error(`Invalid argument ${key}\n${usage}`);
  args.set(key, process.argv[++i]);
}
const required = key => { const value = args.get(key); if (!value) throw new Error(`Missing ${key}\n${usage}`); return value; };
const repo = required('--repo');
const tag = required('--tag');
const channel = args.get('--channel') || 'stable';
const root = path.resolve(required('--workdir'));
const cosign = path.resolve(required('--cosign'));
const configPath = path.resolve(required('--wrangler-config'));
if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo) || !/^v\d+\.\d+\.\d+$/.test(tag) || channel !== 'stable') throw new Error('Only stable semantic-version releases are supported');
await mkdir(root, { recursive: true });
const sourceDir = path.dirname(fileURLToPath(import.meta.url));
execFileSync(process.execPath, [path.join(sourceDir, 'verify-software-release.mjs'), '--repo', repo, '--tag', tag, '--workdir', root, '--cosign', cosign], { stdio: 'inherit' });
const receipt = JSON.parse(await readFile(path.join(root, 'verification.json'), 'utf8'));
const release = JSON.parse(await readFile(path.join(root, 'github-release.json'), 'utf8'));
const sha256 = value => createHash('sha256').update(value).digest('hex');
const expectedReleaseUrl = `https://github.com/${repo}/releases/tag/${tag}`;
if (receipt.tag_name !== tag || receipt.source !== expectedReleaseUrl || receipt.github_digest_verified !== true || receipt.release_unchanged_after_download !== true || !receipt.signatures?.results?.length || receipt.signatures.results.some(result => result.exitCode !== 0)) throw new Error('Incomplete verification receipt');
const assets = receipt.assets.map(asset => {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(asset.name) || asset.name.includes('..') || !Number.isSafeInteger(asset.size) || asset.size < 0 || !/^[a-f0-9]{64}$/.test(asset.sha256)) throw new Error('Invalid verified asset');
  return { name: asset.name, size: asset.size, sha256: asset.sha256, url: `https://res.cheesesec.com/releases/${tag}/${asset.name}` };
}).sort((a, b) => a.name.localeCompare(b.name));
if (assets.length !== release.assets.length || new Set(assets.map(asset => asset.name)).size !== assets.length) throw new Error('Asset count mismatch');
const metadata = { api_version: 'ota.cheesesec.com/software/v1', channel, tag_name: tag, published_at: receipt.published_at, release_url: expectedReleaseUrl, assets };
const metadataBytes = Buffer.from(JSON.stringify(metadata, null, 2) + '\n');
await writeFile(path.join(root, 'software-index.json'), metadataBytes);
console.log(JSON.stringify({ phase: 'publish-plan', tag, count: assets.length, bytes: assets.reduce((sum, asset) => sum + asset.size, 0), metadata_sha256: sha256(metadataBytes), metadata_key: `software/channels/${channel}/index.json`, plan_only: !!args.get('--plan') }));
if (args.get('--plan')) process.exit(0);
const requireFromConfig = createRequire(path.join(path.dirname(configPath), 'edge', 'package.json'));
const wranglerModule = args.get('--wrangler-module') ? path.resolve(args.get('--wrangler-module')) : requireFromConfig.resolve('wrangler');
const wrangler = await import(pathToFileURL(wranglerModule).href);
// Check authentication through the supported CLI without reading stored tokens.
for (let attempt = 1; ; attempt++) {
  try {
    execFileSync(process.execPath, [wranglerModule, 'whoami'], { stdio: 'inherit', timeout: 90_000, env: { ...process.env, WRANGLER_SEND_METRICS: 'false' } });
    break;
  } catch (error) {
    if (attempt >= 3) throw error;
    console.log(JSON.stringify({ phase: 'auth-check-retry', attempt, reason: 'Wrangler authentication/network check failed' }));
  }
}
const original = wrangler.unstable_readConfig({ config: configPath }, { hideWarnings: true });
const expectedBuckets = new Map([['PUBLIC_RESOURCES', 'cheesesec-public-resources-prod'], ['PUBLICATION_INDEX', 'cheesesec-publication-index-prod']]);
const r2Buckets = [];
for (const [binding, bucketName] of expectedBuckets) {
  const candidates = original.r2_buckets.filter(bucket => bucket.binding === binding);
  if (candidates.length !== 1 || candidates[0].bucket_name !== bucketName) throw new Error(`Unexpected ${binding} bucket in Wrangler config`);
  r2Buckets.push({ binding, bucket_name: bucketName, remote: true });
}
// This isolated config inherits only the publication name, account and R2 bindings.
// It excludes routes, vars, secrets, build hooks and any tracked configuration edits.
const proxyConfig = { name: original.name, compatibility_date: original.compatibility_date, r2_buckets: r2Buckets };
if (original.account_id) proxyConfig.account_id = original.account_id;
const proxyConfigPath = path.join(root, 'software-r2-proxy.json');
await writeFile(proxyConfigPath, JSON.stringify(proxyConfig, null, 2) + '\n');
const proxy = await wrangler.getPlatformProxy({ configPath: proxyConfigPath, persist: false, remoteBindings: true, envFiles: [] });
const publication = { started_at: new Date().toISOString(), repo, tag, channel, metadata_key: `software/channels/${channel}/index.json`, metadata_sha256: sha256(metadataBytes), artifacts: [] };
const receiptPath = path.join(root, 'publication-receipt.json');
const save = () => writeFile(receiptPath, JSON.stringify(publication, null, 2) + '\n');
async function verifyObject(bucket, key, expected) {
  const object = await bucket.get(key);
  if (!object) throw new Error(`Missing object during readback: ${key}`);
  const bytes = Buffer.from(await object.arrayBuffer());
  const digest = sha256(bytes);
  if (bytes.length !== expected.size || digest !== expected.sha256) throw new Error(`R2 immutable conflict or readback mismatch: ${key}`);
  return { etag: object.etag, size: bytes.length, sha256: digest };
}
try {
  const before = await proxy.env.PUBLICATION_INDEX.get(publication.metadata_key);
  const previous = before ? Buffer.from(await before.arrayBuffer()) : null;
  publication.metadata_previous = before ? { etag: before.etag, size: previous.length, sha256: sha256(previous) } : null;
  if (previous) {
    await writeFile(path.join(root, 'software-index.previous.json'), previous);
    const previousMetadata = JSON.parse(previous.toString('utf8'));
    if (previousMetadata.api_version !== metadata.api_version || previousMetadata.channel !== channel || !/^v\d+\.\d+\.\d+$/.test(previousMetadata.tag_name) || !Number.isFinite(Date.parse(previousMetadata.published_at))) throw new Error('Existing software metadata has an unexpected schema');
    if (Date.parse(previousMetadata.published_at) > Date.parse(metadata.published_at)) throw new Error('Refusing to replace a newer published software release');
    if (previousMetadata.tag_name === tag && sha256(previous) !== sha256(metadataBytes)) throw new Error('Existing same-tag software metadata differs; investigate before republishing');
  }
  await save();
  for (const asset of assets) {
    const key = `releases/${tag}/${asset.name}`;
    console.log(JSON.stringify({ phase: 'artifact-start', name: asset.name, size: asset.size }));
    const localPath = path.join(root, 'assets', asset.name);
    if (!(await lstat(localPath)).isFile()) throw new Error(`Expected regular artifact file: ${asset.name}`);
    const bytes = await readFile(localPath);
    if (bytes.length !== asset.size || sha256(bytes) !== asset.sha256) throw new Error(`Local artifact changed after verification: ${asset.name}`);
    const existing = await proxy.env.PUBLIC_RESOURCES.head(key);
    let status;
    if (existing) {
      status = 'unchanged';
    } else {
      const contentType = asset.name.endsWith('.json') || asset.name.endsWith('.bundle') ? 'application/json' : asset.name.endsWith('.sh') ? 'text/x-shellscript; charset=utf-8' : asset.name.endsWith('.tar.gz') ? 'application/gzip' : 'text/plain; charset=utf-8';
      const uploaded = await proxy.env.PUBLIC_RESOURCES.put(key, bytes, {
        onlyIf: new Headers({ 'if-none-match': '*' }), sha256: asset.sha256,
        httpMetadata: { contentType, cacheControl: 'public, max-age=31536000, immutable', contentDisposition: `attachment; filename="${asset.name}"` },
        customMetadata: { sha256: asset.sha256, source: 'github-release', repository: repo, tag }
      });
      // A competing identical creation is acceptable only after full byte verification.
      status = uploaded ? 'created' : 'unchanged-after-race';
    }
    const readback = await verifyObject(proxy.env.PUBLIC_RESOURCES, key, asset);
    publication.artifacts.push({ name: asset.name, key, status, ...readback });
    await save();
    console.log(JSON.stringify({ phase: 'artifact-published', name: asset.name, status, ...readback }));
  }
  if (previous && sha256(previous) === sha256(metadataBytes)) {
    publication.metadata_status = 'unchanged';
  } else {
    const headers = new Headers(before ? { 'if-match': before.httpEtag } : { 'if-none-match': '*' });
    const updated = await proxy.env.PUBLICATION_INDEX.put(publication.metadata_key, metadataBytes, {
      onlyIf: headers, sha256: sha256(metadataBytes),
      httpMetadata: { contentType: 'application/json; charset=utf-8', cacheControl: 'public, max-age=60' },
      customMetadata: { sha256: sha256(metadataBytes), source: 'github-release', repository: repo, tag }
    });
    if (!updated) throw new Error('Software metadata changed concurrently; conditional publication rejected');
    publication.metadata_status = before ? 'updated-with-etag' : 'created';
  }
  publication.metadata = await verifyObject(proxy.env.PUBLICATION_INDEX, publication.metadata_key, { size: metadataBytes.length, sha256: sha256(metadataBytes) });
  publication.completed_at = new Date().toISOString();
  publication.success = true;
  await save();
  console.log(JSON.stringify({ phase: 'publication-complete', metadata_status: publication.metadata_status, count: publication.artifacts.length, receipt: receiptPath, ...publication.metadata }));
} catch (error) {
  publication.success = false;
  publication.error = String(error);
  await save();
  throw error;
} finally { await proxy.dispose(); }
