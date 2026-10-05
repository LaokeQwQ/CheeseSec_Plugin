# Store and OTA v1 contract example

The descriptor in this directory demonstrates the 34A sidecar shape only; it is
not an executable plugin or a published release. runtime is fixed to sidecar,
the first mode is observe, request handling is asynchronous snapshot/hint work,
and default egress=deny is mandatory. WASM, in-process native plugins, and CRP
push through Ansible are outside the CheeseWAF contract.

A real release must bind immutable CRP, manifest, signature-set, descriptor, and
provenance digests. The store publishes only reviewed releases; withdrawal is an
append-only event and never overwrites the original record. The live catalog and
OTA indexes are empty here because no release has passed the publication gate.
