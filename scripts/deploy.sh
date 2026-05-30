#!/bin/sh
# Push built artifacts to /data/local/tmp on the connected device.
set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$PROJECT_ROOT/out}"
ABI="${2:-arm64-v8a}"

INJ="$OUT/injector/libs/$ABI/akane-injector"
RT="$OUT/injector/libs/$ABI/libakane-runtime.so"

# The .ko is .incbin'd into the injector binary and loaded via memfd +
# finit_module on first run, so we don't push it separately.
for f in "$INJ" "$RT"; do
	if [ ! -f "$f" ]; then
		echo "missing artifact: $f" >&2
		echo "run \`make\` first" >&2
		exit 1
	fi
done

adb push "$INJ" /data/local/tmp/ > /dev/null
adb push "$RT"  /data/local/tmp/ > /dev/null
adb shell chmod 755 /data/local/tmp/akane-injector > /dev/null

echo "deployed to /data/local/tmp/{akane-injector, libakane-runtime.so}"
