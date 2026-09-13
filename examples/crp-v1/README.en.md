# Minimal CRP v1 archive example

This directory exercises the publication schema, digest, and signature gates; it
is not an installable plugin. The signature set contains two verifiable official
Ed25519 signatures; private keys are never stored. The archive may contain exactly
these files:

```text
manifest.json
artifact/payload.txt
signatures/manifest.json
```
