# CRP v1 schemas

These schemas are the publication-side copy of the strict CRP v1 manifest and
signature contracts. They are intentionally limited to fields accepted by the
current CheeseWAF parser; `provenance/`, SBOM, permissions, target API, and
platform fields remain v2 or extension work.

The canonical public identifiers are:

- `https://store.cheesesec.com/schema/crp/v1/manifest.schema.json`
- `https://store.cheesesec.com/schema/crp/v1/signatures.schema.json`

Schema validation is a publication gate, not a signature or installation
decision. A package still needs source-root binding, valid signatures,
threshold approval, revocation checks, and staged promotion.

The schema's `artifact.size` is required for an archive-ready publication.
The current parser also supports a compatibility form with digests at the
manifest top level; the validation script checks either location and rejects
disagreement.
