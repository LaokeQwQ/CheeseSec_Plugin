# CheeseSec Plugin Store constraints

- This directory contains catalog metadata, release indexes, and signed CRP
  publication inputs. It is not the CheeseWAF runtime.
- Publish catalog data through `store.cheesesec.com`, update indexes through
  `ota.cheesesec.com`, and immutable public resources through
  `res.cheesesec.com`.
- Never commit private keys, customer data, runtime state, generated site
  output, or Agent/editor tooling such as `@agent-eyes`, `code-inspector`, or
  `codex-acp`.
- Ansible may bootstrap infrastructure and a distribution agent only. CRP
  installation, upgrade, and rollback use CWEDP.
- Every publication record must retain its manifest, signature set, source root,
  digest, release sequence, and provenance metadata without rewriting by mirrors
  or peers. For current CRP v1, provenance is kept outside the archive; adding
  a `provenance/` archive entry is a v2 change and will be rejected by the
  current parser.
- `schema/crp-v1/` is a publication gate. Keep its public schema identifiers in
  sync with the handbook mirror, validate JSON with the pinned CI dependency,
  and verify example artifact sizes and all three digests before publication.
- GitHub Actions must use `pull_request`, have explicit least-privilege
  permissions, pin every action by commit SHA, and never receive deployment
  credentials or mutable CRP signing material. Do not use `pull_request_target`
  for repository validation. The workflow policy script is a required CI gate.
- `.crp` archives, key material, signature files, local CI environments, and
  generated output are not source inputs. They must stay ignored and be caught
  by the repository secret/release-artifact scan before staging.
