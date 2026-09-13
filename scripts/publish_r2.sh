#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s BUNDLE_DIR R2_BUCKET [--apply]\n' "$0" >&2
}

if [[ "$#" -lt 2 || "$#" -gt 3 ]]; then
  usage
  exit 2
fi

bundle_dir="$1"
bucket="$2"
apply=false
if [[ "${3:-}" == "--apply" ]]; then
  apply=true
elif [[ "${3:-}" != "" ]]; then
  usage
  exit 2
fi

if [[ ! -d "$bundle_dir" || ! -f "$bundle_dir/bundle-manifest.json" ]]; then
  printf 'publication bundle is missing bundle-manifest.json\n' >&2
  exit 1
fi
if [[ ! "$bucket" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{2,62}$ ]]; then
  printf 'R2 bucket name is invalid\n' >&2
  exit 1
fi
manifest_sequence="$(python3 - "$bundle_dir/bundle-manifest.json" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if data.get("format") != "cheesesec-publication-bundle-v1":
    raise SystemExit("unsupported publication bundle format")
sequence = data.get("sequence")
if not isinstance(sequence, int) or sequence < 0 or sequence > 99999999999999999999:
    raise SystemExit("publication sequence is invalid")
keys = [item.get("key") for item in data.get("objects", [])]
if len(keys) != len(set(keys)) or any(not isinstance(key, str) or key.startswith("/") or ".." in key.split("/") for key in keys):
    raise SystemExit("publication object keys are invalid or duplicated")
print(sequence)
PY
)"

printf 'publication plan: bucket=%s sequence=%s\n' "$bucket" "$manifest_sequence"
if [[ "$apply" != true ]]; then
  printf 'dry run only; pass --apply after reviewing the bundle and Cloudflare account\n'
  exit 0
fi

command -v wrangler >/dev/null 2>&1 || { printf 'wrangler is required for --apply\n' >&2; exit 1; }

temporary_dir="$(mktemp -d -t cheesec-r2-publish.XXXXXX)"
trap 'rm -rf "$temporary_dir"' EXIT

existing_sequence=0
if wrangler r2 object get "$bucket/pointers/catalog.json" --remote --file "$temporary_dir/catalog.json" >/dev/null 2>&1; then
  existing_sequence="$(python3 - "$temporary_dir/catalog.json" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
value = data.get("sequence")
if not isinstance(value, int) or value < 0:
    raise SystemExit("existing catalog pointer sequence is invalid")
print(value)
PY
)"
fi
if (( manifest_sequence <= existing_sequence )); then
  printf 'refusing non-increasing catalog sequence: current=%s requested=%s\n' "$existing_sequence" "$manifest_sequence" >&2
  exit 1
fi

python3 - "$bundle_dir/bundle-manifest.json" "$bundle_dir" "$bucket" <<'PY'
import json
import pathlib
import subprocess
import sys

manifest_path = pathlib.Path(sys.argv[1])
bundle = pathlib.Path(sys.argv[2])
bucket = sys.argv[3]
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for item in manifest["objects"]:
    file_path = bundle / item["file"]
    if not file_path.is_file() or file_path.is_symlink():
        raise SystemExit(f"publication object file is missing or unsafe: {file_path}")
    data = file_path.read_bytes()
    import hashlib
    if len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
        raise SystemExit(f"publication object digest mismatch: {item['key']}")
    key = item["key"]
    if key.startswith("pointers/"):
        continue
    file_path = bundle / item["file"]
    subprocess.run([
        "wrangler", "r2", "object", "put", f"{bucket}/{key}",
        "--remote", "--file", str(file_path), "--force",
        "--content-type", item["content_type"],
        "--cache-control", "public, max-age=60, s-maxage=60, must-revalidate"
        if item["cache_class"] == "short-revalidate"
        else "public, max-age=31536000, immutable",
    ], check=True)
for item in manifest["objects"]:
    if not item["key"].startswith("pointers/"):
        continue
    file_path = bundle / item["file"]
    subprocess.run([
        "wrangler", "r2", "object", "put", f"{bucket}/{item['key']}",
        "--remote", "--file", str(file_path), "--force",
        "--content-type", item["content_type"],
        "--cache-control", "public, max-age=60, s-maxage=60, must-revalidate",
    ], check=True)
PY

printf 'R2 publication completed for sequence %s\n' "$manifest_sequence"
