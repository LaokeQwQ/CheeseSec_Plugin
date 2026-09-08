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
