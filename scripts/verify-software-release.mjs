#!/usr/bin/env node
// Download and verify a published release. Publishing belongs to a separate script.
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { constants, createReadStream } from 'node:fs';
import { link, lstat, mkdir, mkdtemp, open, realpath, rename, rmdir, unlink } from 'node:fs/promises';
import path from 'node:path';

const HELP = `Usage: node verify-software-release.mjs --tag TAG --workdir DIR --cosign PATH [--repo OWNER/REPO]

Download and verify every asset of a published, non-prerelease GitHub release.
--repo defaults to LaokeQwQ/CheeseWAF; --tag, --workdir and --cosign are required.
Use simple portable tags and asset basenames containing letters, digits, dot,
underscore or hyphen. Assets go into DIR/assets. Existing matching files are reused;
an existing file with a different GitHub digest or size fails verification.
Requires gh, curl and an operator-authenticated cosign v3.1.3 binary. Authenticate
the cosign binary against official release digests before supplying --cosign.
Outputs github-release.json, verification.json and signature-verification/*.log.
This tool only downloads and verifies; a separate publish script performs publishing.
`;
const COSIGN_VERSION = 'v3.1.3';
const ISSUER = 'https://token.actions.githubusercontent.com';
const RELEASE_FIELDS = 'tagName,publishedAt,isDraft,isPrerelease,url,assets';
const portableName = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;
const sortByName = (a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0;

function options(argv) {
  if (argv.includes('--help') || argv.includes('-h')) return null;
  const result = { repo: 'LaokeQwQ/CheeseWAF' };
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    if (!['--repo', '--tag', '--workdir', '--cosign'].includes(flag) || !argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error(`Invalid or missing argument: ${flag}`);
    const name = flag.slice(2);
    if (Object.hasOwn(result, name) && name !== 'repo') throw new Error(`Repeated argument: ${flag}`);
    if (name === 'repo' && argv.slice(0, i).includes('--repo')) throw new Error('Repeated argument: --repo');
    result[name] = argv[i + 1];
  }
  for (const key of ['tag', 'workdir', 'cosign']) if (!result[key]) throw new Error(`--${key} is required`);
  if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(result.repo)) throw new Error('Invalid GitHub OWNER/REPO');
  if (!portableName.test(result.tag) || result.tag.includes('..') || result.tag.endsWith('.')) throw new Error('Invalid or unsupported tag');
  return result;
}

function directEnvironment() {
  const env = { ...process.env, GH_HOST: 'github.com', GH_PROMPT_DISABLED: '1', NO_PROXY: '*', no_proxy: '*' };
  for (const name of Object.keys(env)) if (/^(https?|all)_proxy$/i.test(name)) delete env[name];
  return env;
}

async function regularFile(file, missingAllowed = false) {
  try {
    const info = await lstat(file);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Expected a regular file: ${file}`);
    return info;
  } catch (error) {
    if (missingAllowed && error.code === 'ENOENT') return null;
    throw error;
  }
}

async function digestFile(file) {
  // Opening without following symlinks prevents a cache entry from escaping assets/.
  await regularFile(file);
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  const before = await handle.stat();
  if (!before.isFile()) { await handle.close(); throw new Error(`Expected a regular file: ${file}`); }
  const hash = createHash('sha256');
  let size = 0;
  try {
    for await (const chunk of createReadStream(file, { fd: handle.fd, autoClose: false })) {
      size += chunk.length;
      hash.update(chunk);
    }
    const after = await handle.stat();
    const current = await lstat(file);
    if (before.dev !== current.dev || before.ino !== current.ino || !current.isFile() || current.isSymbolicLink() || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs || size !== after.size) throw new Error(`File changed during hashing: ${file}`);
    return { size, sha256: hash.digest('hex') };
  } finally { await handle.close(); }
}

async function atomicText(file, text) {
  await regularFile(file, true);
  const temporary = path.join(path.dirname(file), `.${path.basename(file)}.${randomUUID()}.tmp`);
  try {
    const handle = await open(temporary, 'wx', 0o600);
    try { await handle.writeFile(text); } finally { await handle.close(); }
    await rename(temporary, file);
  } finally { await unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
}

async function jsonFile(file, value) { await atomicText(file, JSON.stringify(value, null, 2) + '\n'); }

async function safeDirectory(directory) {
  await mkdir(directory, { recursive: true });
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`Expected a directory without a symlink: ${directory}`);
}

async function getRelease(repo, tag, env, cwd) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    let output;
    try {
      output = execFileSync('gh', ['release', 'view', tag, '--repo', `https://github.com/${repo}`, '--json', RELEASE_FIELDS], { encoding: 'utf8', env, cwd, timeout: 120_000, maxBuffer: 32 * 1024 * 1024 });
    } catch (error) {
      const transient = /\bEOF\b|timed? ?out|timeout|connection (?:reset|refused)|temporary failure|network is unreachable|TLS handshake|HTTP 5\d\d|HTTP 429|i\/o timeout/i.test(String(error.stderr || '') + String(error.message));
      if (!transient || attempt === 3) throw error;
      console.error(`GitHub metadata request failed transiently; retrying (${attempt}/3)`);
      await new Promise(resolve => setTimeout(resolve, attempt * 1000));
      continue;
    }
    return JSON.parse(output);
  }
}

function validateRelease(release, repo, tag) {
  if (release.tagName !== tag || release.isDraft !== false || release.isPrerelease !== false || typeof release.publishedAt !== 'string' || !Number.isFinite(Date.parse(release.publishedAt)) || release.url !== `https://github.com/${repo}/releases/tag/${tag}`) throw new Error('Expected an official published, non-prerelease release for the requested repo/tag');
  if (!Array.isArray(release.assets) || release.assets.length === 0) throw new Error('Release has no assets');
  const names = new Set();
  let total = 0;
  for (const asset of release.assets) {
    if (typeof asset.name !== 'string' || !portableName.test(asset.name) || asset.name.includes('..') || asset.name.endsWith('.') || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(asset.name)) throw new Error(`Unsafe asset name: ${JSON.stringify(asset.name)}`);
    const folded = asset.name.toLowerCase();
    if (names.has(folded)) throw new Error(`Duplicate or case-colliding asset: ${asset.name}`);
    names.add(folded);
    if (!Number.isSafeInteger(asset.size) || asset.size < 0 || !/^sha256:[0-9a-f]{64}$/.test(asset.digest) || asset.state !== 'uploaded' || typeof asset.id !== 'string' || asset.id.length === 0 || asset.url !== `https://github.com/${repo}/releases/download/${tag}/${asset.name}`) throw new Error(`Invalid GitHub asset URL, digest, size or state: ${asset.name}`);
    total += asset.size;
    if (!Number.isSafeInteger(total)) throw new Error('Release total size exceeds the safe integer limit');
  }
  const actualNames = new Set(release.assets.map(asset => asset.name));
  for (const required of ['SHA256SUMS', 'SHA256SUMS.bundle']) if (!actualNames.has(required)) throw new Error(`Missing required asset: ${required}`);
  for (const name of actualNames) if (name.endsWith('.bundle') && !actualNames.has(name.slice(0, -7))) throw new Error(`Bundle has no corresponding release blob: ${name}`);
}

function immutableRelease(release) {
  return JSON.stringify({ tagName: release.tagName, publishedAt: release.publishedAt, isDraft: release.isDraft, isPrerelease: release.isPrerelease, url: release.url, assets: release.assets.map(({ id, apiUrl, name, size, digest, url, state, createdAt, updatedAt }) => ({ id, apiUrl, name, size, digest, url, state, createdAt, updatedAt })).sort(sortByName) });
}

function run(program, args, env, cwd, timeout = 180_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(program, args, { env, cwd, shell: false, timeout, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let overflow = false;
    const collect = (channel, chunk) => {
      if (stdout.length + stderr.length + chunk.length > 8 * 1024 * 1024) { overflow = true; child.kill('SIGTERM'); return; }
      if (channel === 'stdout') stdout += chunk; else stderr += chunk;
    };
    child.stdout.on('data', chunk => collect('stdout', chunk.toString()));
    child.stderr.on('data', chunk => collect('stderr', chunk.toString()));
    child.once('error', reject);
    child.once('close', (exitCode, signal) => overflow ? reject(new Error(`${path.basename(program)} output exceeded limit`)) : resolve({ exitCode, signal, stdout, stderr }));
  });
}

async function downloadAsset(asset, assetsDirectory, env, cwd) {
  const target = path.join(assetsDirectory, asset.name);
  if (path.dirname(target) !== assetsDirectory) throw new Error('Asset path escaped the assets directory');
  let actual;
  const cached = await regularFile(target, true);
  if (cached) {
    actual = await digestFile(target);
    if (actual.size !== asset.size || `sha256:${actual.sha256}` !== asset.digest) throw new Error(`Existing cache digest/size mismatch: ${asset.name}`);
  } else {
    const temporaryDirectory = await mkdtemp(path.join(assetsDirectory, '.download-'));
    const temporary = path.join(temporaryDirectory, 'asset');
    try {
      const result = await run('curl', ['--noproxy', '*', '--proto', '=https', '--proto-redir', '=https', '--fail', '--location', '--silent', '--show-error', '--connect-timeout', '20', '--max-time', '900', '--retry', '3', '--output', temporary, '--', asset.url], env, cwd, 3_700_000);
      if (result.exitCode !== 0 || result.signal) throw new Error(`Download failed for ${asset.name}: ${result.stderr.trim()}`);
      actual = await digestFile(temporary);
      if (actual.size !== asset.size || `sha256:${actual.sha256}` !== asset.digest) throw new Error(`Downloaded GitHub digest/size mismatch: ${asset.name}`);
      // Atomic no-replace installation: a concurrent target creation fails EEXIST.
      await link(temporary, target);
    } finally {
      await unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; });
      await rmdir(temporaryDirectory);
    }
  }
  console.log(JSON.stringify({ phase: 'asset-verified', name: asset.name, size: actual.size, cached: Boolean(cached) }));
  return { name: asset.name, ...actual, path: target, github_url: asset.url };
}

async function mapThree(items, operation) {
  const results = new Array(items.length);
  let next = 0;
  let failure;
  async function worker() {
    while (!failure && next < items.length) {
      const index = next++;
      try { results[index] = await operation(items[index]); } catch (error) { failure ??= error; }
    }
  }
  await Promise.all([worker(), worker(), worker()]);
  if (failure) throw failure;
  return results;
}

async function verifyChecksums(assets, assetsDirectory) {
  const known = new Map(assets.map(asset => [asset.name, asset]));
  const handle = await open(path.join(assetsDirectory, 'SHA256SUMS'), constants.O_RDONLY | constants.O_NOFOLLOW);
  let manifest;
  try {
    if (!(await handle.stat()).isFile()) throw new Error('SHA256SUMS must be a regular file');
    manifest = await handle.readFile();
  } finally { await handle.close(); }
  const expectedManifest = known.get('SHA256SUMS');
  if (manifest.length !== expectedManifest.size || createHash('sha256').update(manifest).digest('hex') !== expectedManifest.sha256) throw new Error('SHA256SUMS changed before parsing');
  const text = manifest.toString('utf8');
  const lines = text.split(/\r?\n/);
  if (lines.at(-1) === '') lines.pop();
  if (!lines.length) throw new Error('SHA256SUMS is empty');
  const checked = new Set();
  for (const line of lines) {
    const match = /^([0-9a-f]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._-]{0,199})$/.exec(line);
    if (!match || !known.has(match[2]) || checked.has(match[2])) throw new Error(`Invalid, unknown or repeated SHA256SUMS entry: ${JSON.stringify(line)}`);
    const [_, expected, name] = match;
    const actual = await digestFile(known.get(name).path);
    if (actual.sha256 !== expected || actual.sha256 !== known.get(name).sha256 || actual.size !== known.get(name).size) throw new Error(`SHA256SUMS mismatch: ${name}`);
    checked.add(name);
  }
  for (const asset of assets) {
    if (asset.name !== 'SHA256SUMS' && !asset.name.endsWith('.bundle') && !checked.has(asset.name)) throw new Error(`Release payload is not protected by SHA256SUMS: ${asset.name}`);
  }
  return [...checked];
}

async function verifySignatures(assets, binary, identity, logsDirectory, env, cwd) {
  const known = new Map(assets.map(asset => [asset.name, asset]));
  const results = await mapThree(assets.filter(asset => asset.name.endsWith('.bundle')), async bundle => {
    const blob = known.get(bundle.name.slice(0, -7));
    const args = ['verify-blob', '--bundle', bundle.path, '--certificate-identity', identity, '--certificate-oidc-issuer', ISSUER, blob.path];
    const result = await run(binary, args, env, cwd, 240_000);
    const log = path.join(logsDirectory, `${blob.name}.log`);
    await atomicText(log, JSON.stringify({ program: binary, args }) + '\n' + result.stdout + result.stderr + `\nexitCode=${result.exitCode}\nsignal=${result.signal}\n`);
    return { name: blob.name, blob: blob.path, bundle: bundle.path, blobSha256: blob.sha256, bundleSha256: bundle.sha256, ...result, log };
  });
  const signatures = { binary, identity, issuer: ISSUER, results };
  await jsonFile(path.join(logsDirectory, 'results.json'), signatures);
  if (results.some(result => result.exitCode !== 0 || result.signal)) throw new Error('Signature verification failed; inspect signature-verification logs');
  return signatures;
}

async function verifyRelease(args) {
  await mkdir(path.resolve(args.workdir), { recursive: true });
  const root = await realpath(path.resolve(args.workdir));
  if (root === path.parse(root).root) throw new Error('The filesystem root cannot be used as --workdir');
  const lock = path.join(root, '.verify-software-release.lock');
  try { await mkdir(lock); } catch (error) { if (error.code === 'EEXIST') throw new Error(`Verification is already running or an interrupted lock remains: ${lock}`); throw error; }
  try {
    // A previous success must not masquerade as the result of a failed rerun.
    const receiptPath = path.join(root, 'verification.json');
    if (await regularFile(receiptPath, true)) await rename(receiptPath, path.join(root, `verification.previous-${randomUUID()}.json`));
    const assetsDirectory = path.join(root, 'assets');
    const logsDirectory = path.join(root, 'signature-verification');
    const cacheDirectory = path.join(root, 'verification-cache');
    for (const directory of [assetsDirectory, logsDirectory, cacheDirectory]) await safeDirectory(directory);
    const env = { ...directEnvironment(), XDG_CACHE_HOME: cacheDirectory };
    const binary = await realpath(path.resolve(args.cosign));
    const binaryBefore = await digestFile(binary);
    const version = JSON.parse(execFileSync(binary, ['version', '--json'], { encoding: 'utf8', env, cwd: root, timeout: 30_000, maxBuffer: 1024 * 1024 }));
    if (version.gitVersion !== COSIGN_VERSION) throw new Error(`Expected cosign ${COSIGN_VERSION}, received ${JSON.stringify(version.gitVersion)}`);
    const release = await getRelease(args.repo, args.tag, env, root);
    validateRelease(release, args.repo, args.tag);
    const assets = (await mapThree(release.assets, asset => downloadAsset(asset, assetsDirectory, env, root))).sort(sortByName);
    const checked = await verifyChecksums(assets, assetsDirectory);
    const identity = `https://github.com/${args.repo}/.github/workflows/ci.yml@refs/tags/${args.tag}`;
    const signatures = await verifySignatures(assets, binary, identity, logsDirectory, env, root);
    for (const asset of assets) {
      const after = await digestFile(asset.path);
      if (after.sha256 !== asset.sha256 || after.size !== asset.size) throw new Error(`Asset changed during verification: ${asset.name}`);
    }
    for (const result of signatures.results) result.unchangedDuringVerification = true;
    const binaryAfter = await digestFile(binary);
    if (binaryBefore.sha256 !== binaryAfter.sha256 || binaryBefore.size !== binaryAfter.size) throw new Error('cosign binary changed during verification');
    const fresh = await getRelease(args.repo, args.tag, env, root);
    validateRelease(fresh, args.repo, args.tag);
    if (immutableRelease(release) !== immutableRelease(fresh)) throw new Error('Release assets changed during download or verification');
    const receipt = { verified_at: new Date().toISOString(), source: release.url, published_at: release.publishedAt, tag_name: release.tagName, count: assets.length, bytes: assets.reduce((sum, asset) => sum + asset.size, 0), github_digest_verified: true, release_unchanged_after_download: true, checksum_entries_verified: checked, assets, signatures, cosign_version: version.gitVersion, cosign_sha256: binaryBefore.sha256 };
    await jsonFile(path.join(logsDirectory, 'results.json'), signatures);
    await jsonFile(path.join(root, 'github-release.json'), fresh);
    await jsonFile(receiptPath, receipt);
    console.log(JSON.stringify({ phase: 'verification-complete', count: receipt.count, bytes: receipt.bytes, signatures: signatures.results.length, cosign_version: receipt.cosign_version, receipt: receiptPath }));
  } finally { await rmdir(lock); }
}

try {
  const args = options(process.argv.slice(2));
  if (args) await verifyRelease(args); else console.log(HELP);
} catch (error) {
  console.error(`Verification failed: ${error.message}`);
  process.exitCode = 1;
}
