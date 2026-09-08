# Minimal CRP v1 archive example

This directory exercises the publication schema and digest gate; it is not an
installable plugin. The signature set is empty, so CheeseWAF Import and runtime
activation must reject it. The archive may contain exactly these files:

```text
manifest.json
artifact/payload.txt
signatures/manifest.json
```
