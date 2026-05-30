# akane-injector

A kernel-assisted, tracelessly-resumable shared-library injector for Android.
Loads any `.so` into a target process without `ptrace`, `dlopen` from inside,
or visible artifacts in `/proc/<pid>/maps`.

## Components

- **`module/`** — `akane.ko`, the kernel module. Exposes `/dev/akane` and
  four ioctl bands: memory (alloc / read / write / protect in a target's mm),
  maps (per-VMA naming for disguise, plus `HIDE_FROM_MEMORY` to mask perms to
  `---p` and block non-root `/proc/<pid>/{mem,smaps,pagemap}` +
  `process_vm_readv/writev` + `mincore`),
  hide (paths / modules / ports), and task_work (queue a `task_work_add` to
  redirect a target thread).
- **`injector/controller/`** — `akane-injector`, the host-side CLI. Drives the
  kernel module to map the runtime + payload into the target, patches the
  payload's GOT, and hijacks a thread via task_work to enter the bootstrap.
- **`injector/runtime/`** — `libakane-runtime.so`, loaded into the target
  alongside every payload. Provides `dl_iterate_phdr` / `dladdr` / `dlopen` /
  `dlsym` / `dlclose` / `dlerror` hooks + a payload registry so libraries that
  introspect their own loaded image (Frida gadget, unwinders, sanitizers) find
  themselves.
- **`injector/bootstrap/`** — `bootstrap.S`, a small position-independent stub
  that gets `mem_write`'d into the target as an RX page. Spawns a worker
  thread to run the payload's `.init_array`, then resumes the hijacked thread.
- **`injector/loader/`** — vendored CSOLoader (in-process ELF loader). Parses
  segments, resolves symbols, applies relocations.

## Prerequisites

- **Docker** — used to build the kernel module against an Android 12 / 5.10
  kernel via `ghcr.io/ylarod/ddk-min`.
- **Android NDK r26** — typically at `~/Android/Sdk/ndk/26.3.11579264`.
  Override with `ANDROID_NDK_HOME` if installed elsewhere.
- **adb**, with a rooted device or emulator connected.

## Device requirements

The embedded-blob model requires a **GKI 2.0** device — i.e. a kernel with a
frozen KMI (Kernel Module Interface), which is what lets a single prebuilt
`akane.ko` load across any device on that branch via `finit_module()`.

| Requirement | Supported |
|-------------|-----------|
| Android version | **12 and later** (12, 13, 14, 15, 16) |
| Kernel | **5.10 and later** (5.10, 5.15, 6.1, 6.6, 6.12) |
| GKI generation | **2.0** (stable, enforced KMI) |
| ABI | `arm64-v8a` (default), `armeabi-v7a` |
| Access | rooted device / emulator (the injector loads the module as root) |

**Not supported, by design:**

- **Android 11 / kernel 5.4 (GKI 1.0).** GKI exists here, but its KMI is *not*
  frozen — retail kernels ship divergent symbol CRCs (`CONFIG_MODVERSIONS`), so
  a universal prebuilt module is rejected with a symbol-version mismatch. Only
  per-device, exact-kernel modules work, which the embedded-blob design can't
  ship. The `ghcr.io/ylarod/ddk-min` toolchain has no 5.4 branch for the same
  reason.
- **Android 10 and older / kernels 4.x (pre-GKI).** No generic kernel image at
  all; every module is per-device.

The matching is keyed on the kernel's GKI branch (the `androidNN` tag in
`uname -r`), which is **frozen at device launch** and does not change when the
OS is updated — a device that shipped `android13-5.15` still reports it after
upgrading to Android 14.

## Quickstart

```sh
make                                                  # build everything under out/
./scripts/deploy.sh                                   # adb push to /data/local/tmp
./scripts/run.sh -p <pid> -s /data/local/tmp/your.so  # invoke on device
adb shell su -c "rmmod akane"                         # unload (optional)
```

Other Make targets: `make module`, `make injector`, `make clean`. Override the
ABI or kernel list per-invocation: `make ABI=armeabi-v7a`, `make KERNELS=android12-5.10`.

## Module auto-load (multi-kernel)

The build matrix produces one `akane.ko` per supported GKI kernel target;
every successful build is `.incbin`'d into the same `akane-injector`
binary. On each invocation the injector checks for `/dev/akane`, and on
absence it:

1. Reads `uname -r` (e.g. `5.10.236-android12-9-…`).
2. Parses out the kernel `major.minor` (`5.10`) and the Android compat
   tag (`android12`).
3. Picks the matching embedded blob: exact `(android, kernel)` first;
   same-kernel any-android fallback; otherwise refuses with a list of
   the kernels this binary was built with.
4. Writes that blob to a memfd and calls `finit_module()` — no
   `.ko` ever lands on disk in the target.

### Configured kernel targets

Default `KERNELS` list (override to build a subset):

| `KERNEL`            | Kernel | Android GKI |
|---------------------|--------|-------------|
| `android16-6.12`    | 6.12   | 16          |
| `android15-6.6`     | 6.6    | 15          |
| `android14-6.1`     | 6.1    | 14          |
| `android14-5.15`    | 5.15   | 14          |
| `android13-5.15`    | 5.15   | 13          |
| `android13-5.10`    | 5.10   | 13          |
| `android12-5.10`    | 5.10   | 12          |

```sh
make KERNELS="android14-6.1 android15-6.6"   # build a subset
```

A docker build failure for any single kernel prints a warning and is
excluded from embedding; the remaining kernels still build and the
injector still ships with whatever succeeded.

### Discovering a device's target

```sh
adb shell uname -r
# 5.10.236-android12-9-… -> android12-5.10 (or fall back to android13-5.10)
```

## Build artifacts

All outputs land under `out/`:

```
out/
├── module/
│   ├── android12-5.10/akane.ko           (embedded into the injector)
│   ├── android13-5.10/akane.ko
│   ├── android14-6.1/akane.ko
│   └── …                                  (one dir per KERNEL target)
└── injector/
    ├── blobs/                             (generated .S + table.c for embedding)
    └── libs/arm64-v8a/
        ├── akane-injector
        └── libakane-runtime.so
```

`out/` is gitignored. Source trees stay clean.

## Multi-ABI

Default ABI is `arm64-v8a`. Override per invocation:

```sh
make injector ABI=armeabi-v7a
```

## Credits

- [**ddk**](https://github.com/Ylarod/ddk) — Android kernel-module build
  toolchain; `ghcr.io/ylarod/ddk-min` builds `akane.ko` against each GKI branch.
- [**CSOLoader**](https://github.com/ThePedroo/CSOLoader) — vendored in-process
  ELF loader (`injector/loader/`) that parses segments, resolves symbols, and
  applies relocations.
