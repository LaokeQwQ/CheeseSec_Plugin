#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
  printf 'usage: %s OUTPUT_DIRECTORY [linux/amd64|darwin/arm64|windows/amd64 ...]\n' "$0" >&2
  exit 2
fi
build_output=$1
shift
if [ "$#" -eq 0 ]; then
  set -- linux/amd64 darwin/arm64
fi
mkdir -p "$build_output"
build_output=$(CDPATH= cd -- "$build_output" && pwd -P)
source_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cd "$source_directory"
for target in "$@"; do
  case "$target" in
    linux/amd64|darwin/arm64|windows/amd64) ;;
    *) printf 'unsupported target: %s\n' "$target" >&2; exit 2 ;;
  esac
  target_os=${target%/*}
  target_arch=${target#*/}
  artifact="hello-cheesesec-$target_os-$target_arch"
  if [ "$target_os" = windows ]; then artifact="$artifact.exe"; fi
  if [ -e "$build_output/$artifact" ] || [ -L "$build_output/$artifact" ]; then
    printf 'refusing to replace existing artifact: %s\n' "$artifact" >&2
    exit 2
  fi
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" GOTOOLCHAIN=go1.26.9 \
    go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$build_output/$artifact" .
  printf '%s\n' "$build_output/$artifact"
done
