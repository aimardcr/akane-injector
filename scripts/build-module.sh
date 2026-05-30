#!/bin/sh
# Build the akane kernel module against a specific ddk-min kernel variant,
# then copy the resulting .ko to $OUT/module/$KERNEL/akane.ko.
#
# Per-kernel scratch dirs live at module/build-$KERNEL so parallel builds
# don't stomp on each other. Failure to build one variant doesn't abort
# the matrix -- caller treats a missing artifact as "this kernel skipped."
set -e

OUT="$1"
KERNEL="$2"
if [ -z "$OUT" ] || [ -z "$KERNEL" ]; then
	echo "usage: $0 <out-dir> <kernel-tag>" >&2
	echo "  kernel-tag matches ghcr.io/ylarod/ddk-min, e.g. android14-6.1" >&2
	exit 2
fi

# Image tag suffix is pinned here; bump when ddk-min publishes a newer set.
DDK_DATE="20260313"
IMAGE="ghcr.io/ylarod/ddk-min:${KERNEL}-${DDK_DATE}"

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODULE_DIR="$PROJECT_ROOT/module"
SCRATCH="build-$KERNEL"

# Docker Desktop on macOS doesn't require sudo; Linux usually does.
case "$(uname -s)" in
	Darwin) DOCKER="docker" ;;
	*)      DOCKER="sudo docker" ;;
esac

echo "building akane.ko against $KERNEL ..."

cd "$MODULE_DIR"
if ! $DOCKER run --rm -v "$PWD:/work" -w /work "$IMAGE" sh -c "\
		mkdir -p $SCRATCH && cd $SCRATCH && \
		ln -sf ../*.c ../*.h ../Kbuild . && \
		CC=clang make -C \$KDIR M=/work/$SCRATCH modules"; then
	echo "WARNING: $KERNEL build failed; this variant will not be embedded" >&2
	exit 1
fi

mkdir -p "$OUT/module/$KERNEL"
cp "$MODULE_DIR/$SCRATCH/akane.ko" "$OUT/module/$KERNEL/akane.ko"
echo "  -> $OUT/module/$KERNEL/akane.ko"
