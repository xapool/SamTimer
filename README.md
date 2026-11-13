# SamTimer

One-tap Android root for the **Galaxy S23+ (SM-S9160)**, built around the
**CVE-2026-98260** timer exploit (posix-cpu-timers UAF) and a
**KernelSU** late-load module with Samsung KDP / RKP / DEFEX
compatibility.

> Based on the **CVE-2026-98260-aurora** repo — its timer LPE port is what
> `app/src/main/cpp/timer.c` evolved from.

> [!WARNING]
> For devices you own or are explicitly authorized to test. The exploit is a
> probabilistic kernel UAF: a failed run can leave the system unstable until
> the next reboot, and an unlucky reclaim can panic the kernel and reboot the
> phone. Rebooting always restores a clean, unrooted state.

## Status

Verified end to end on **SM-S9160 / S9160ZCS8FZJ1** from a clean boot with no
pre-existing root: the Shizuku shell (uid 2000) runs the chain, the payload
injects a root usermodehelper, `ksud late-load` installs the module, and

```text
/proc/modules:  kernelsu 229376 1 - Live
su -c id     -> uid=0(root) context=u:r:ksu:s0
```

The trigger is a race, so a single run can miss. Success rate per boot is
acceptable in practice but not guaranteed — see [Probabilistic
behaviour](#probabilistic-behaviour).

## Overview

| | |
| --- | --- |
| Target | SM-S9160 (Galaxy S23+, `dm2q`, Snapdragon 8 Gen 2) |
| Firmware | `S9160ZCS8FZJ1` — Android 16 / One UI 8.5 |
| Kernel | `5.15.189-android13-8-3251900-abS9160ZCS8FZJ1` |
| Exploit | CVE-2026-98260 (`timer.c`, compiled by Gradle) |
| Root module | KernelSU (embedded `android13-5.15` `kernelsu.ko`) |
| `ksud` | `samsung-v2.2-2-g76a088c5` (uapi 5), bundled as `libksud.so` |
| Manager app | **`me.weishu.kernelsu`** — from [diabl0w/KernelSU](https://github.com/diabl0w/KernelSU/releases/tag/samsung-v2.2) |
| Execution context | Shizuku shell (uid 2000) |
| su domain | `u:r:ksu:s0` |
| Root lifetime | Per-boot (ephemeral — a reboot clears it) |

## Requirements

1. **Shizuku** running (wireless debugging). For auto-root, enable Shizuku's
   boot auto-start and grant SamTimer its permission once.
2. **KernelSU manager** from
   [diabl0w/KernelSU](https://github.com/diabl0w/KernelSU/releases/tag/samsung-v2.2),
   package `me.weishu.kernelsu`.
   This exact build matters: the late-load passes
   `--package-name me.weishu.kernelsu`, so the driver only registers a manager
   uid when *that* app is installed. A different lineage (KernelSU-Next
   `com.rifsxd.ksunext`, or a stock `tiann/KernelSU` build with another
   signing/package) leaves the driver with no manager, and `su` can never be
   granted even though the module loaded.
3. The matching **`ksud`** from the same release. It is already bundled in the
   APK as `libksud.so` (`app/src/main/jniLibs/arm64-v8a/libksud.so`), so you
   normally do not install it by hand — see [Where the payload comes
   from](#where-the-payload-comes-from).

## Build

```sh
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk

./gradlew assembleRelease
# APK: app/build/outputs/apk/release/app-release-unsigned.apk
# needs a release signingConfig to be installable
```

- `app/src/main/cpp/timer.c` is compiled into
  `app/src/main/jniLibs/arm64-v8a/libtimer.so` by the `buildPayload` task
  (NDK auto-detected: `ANDROID_NDK_HOME` → `local.properties` → SDK →
  `~/android-ndk-r27c`)
- `libksud.so` is the prebuilt KernelSU late-load daemon and is kept by
  `./gradlew clean`
- the generated `libtimer.so` is git-ignored; `assembleDebug` always rebuilds it

## Usage

1. Start Shizuku, open SamTimer
2. Tap **Root now** → confirm → wait
3. Grant `su` in the KernelSU manager
4. Optionally enable **Auto-root after reboot** (waits for the 3-minute
   post-boot settle window, then runs headless; a failed run disables the
   option itself so a bad module cannot boot-loop the phone)

> [!IMPORTANT]
> One attempt per boot. A run that parks is holding a failed-plant zombie whose
> stale timer node lives in an already-reclaimed page; only a reboot clears
> that. Never force-stop the exploit process, and reboot instead of retrying in
> the same boot.

## How it works

1. **Trigger.** `timer.c` creates 4096 `CLOCK_THREAD_CPUTIME_ID` timers on the
   exec thread (one armed victim). A `CLONE_VM` helper crashes with
   `RLIMIT_CORE` unlimited after `de_thread()`, so `do_coredump()` sets
   `old_mm->core_state`; `exec_mmap()` then returns `-EINTR`,
   `begin_new_exec()` never reaches the late `posix_cpu_timers_exit()`, and
   `exit_itimers()` frees the armed `k_itimer` while it is still queued.
   (The 6.1 SIGKILL race cannot work here: `exec_mmap()`'s `mmap_read_lock` is
   uninterruptible and `exec_update_lock` is uncontended on 5.15.)
2. **Reclaim.** An 8 KiB `AF_UNIX` spray takes the freed order-1
   `posix_timers_cache` slab. Each write is one `get_order(8192) = 1` frag with
   the whole payload at offset 0 — measured on-device with `probe`, not
   assumed.
3. **Write.** The zombie's `release_task()` runs `posix_cpu_timers_exit()` →
   `rb_erase(node, root = tsk+0x740)` → `__rb_change_child`, which stores
   `node->__rb_parent_color` into `node->rb_left` (Case B, self-parent
   payload) — an 8-byte store at an address we choose.
4. **pipe r/w primitive.** The same store redirects `pipe->bufs` at a fake
   `pipe_buffer` array in a user page, giving a stable kernel read/write
   through ordinary `read()`/`write()` on the pipe. Marker page, image
   physical base (`0xa8000000 + slide`, validated by the `events_unbound`
   name check) and every later write go through it.
5. **UMH injection.** `system_unbound_wq → dfl_pwq → worker_pool` is resolved
   read-only, the pool must be idle, and a fake `work_struct` whose `func` is
   `call_usermodehelper_exec_work` is published into the pool worklist with a
   single 16-byte store. A pty kick wakes a worker.
6. **Root helper.** The kernel spawns `/system/bin/sh umh_action.sh` with a
   real kernel-issued root cred (`ctx=u:r:kernel:s0`), so no cred is forged and
   DEFEX/KDP never see a fake one. The script adopts `u:r:init:s0` and
   bind-mounts `ksud` over `/system/bin/logcat` inside a private mount
   namespace (a directly exec'ed `/data` binary can be killed before its first
   instruction).
7. **late-load.** `ksud late-load --package-name me.weishu.kernelsu` installs
   the embedded `android13-5.15` module (the loader rewrites its vermagic to
   the running `5.15.189-android13-8-3251900-abS9160ZCS8FZJ1` release), and
   the manager can grant `su`.

### Safety rails

- `panic_on_warn` is zeroed through the pipe with a byte-exact read-back once
  the primitive exists, so a later `WARN` becomes a log line instead of a
  reboot.
- A miss whose exec thread is still alive is reaped directly: its timers were
  dequeued through `siglock`, so there is no stale node to repair and no point
  spending more plants.
- A miss that leaves a held zombie stops the chain. Retrying on top of a stale
  node is how this exploit turns one miss into a panic.

## Payload modes

| argv | Purpose | Risk |
| --- | --- | --- |
| `ids` | tracefs event ids only | none (read-only) |
| `probe` | page size, tracefs, SLUB discard rate, 8 KiB carrier order | none (read-only) |
| `verify` / `shell` | credit-write path, for porting | medium |
| `fake` | mode-2 fake cred, no pipe | medium |
| `pipefake` | pipe + fake cred, shorter than `umhpipe` | medium-high |
| `umhread` | UMH dry run — resolves everything, injects nothing | high |
| `umhpipe` | **the production chain** (what the app runs) | high |

## Where the payload comes from

- **Timer exploit / UMH chain**: this repository's `app/src/main/cpp/timer.c`,
  descended from the CVE-2026-98260-aurora port.
- **`ksud` (`libksud.so`)**: the daemon from the same
  [diabl0w/KernelSU](https://github.com/diabl0w/KernelSU/releases/tag/samsung-v2.2)
  release (reports `ksud samsung-v2.2-2-g76a088c5`, uapi 5). It embeds the
  `android13-5.15` `kernelsu.ko` and rewrites the module vermagic at load time,
  which is what makes an LKM late-load possible on a release kernel that is not
  built with KernelSU.
- **Manager app**: the APK from the **same** release as `ksud`, package
  `me.weishu.kernelsu`. Manager and `ksud` must come from the same release: the
  driver keys the manager uid off `--package-name`, and the userspace uapi
  version has to match the module's.
- **Offsets**: every constant in `app/src/main/cpp/offsets.h` is derived for
  `S9160ZCS8FZJ1` from `vmlinux.nm`, the image's BTF and disassembly of the
  running kernel. They do not transfer to another build.

## Probabilistic behaviour

The abort is a race: the core dump has to still be in progress when
`exec_mmap()` checks `old_mm->core_state`, and the spray has to win the freed
slab. Both are measured, not assumed (`probe`, plus per-plant
`free_seen`/`burst hit`/`discarded` counters), and the payload compensates with
retries:

- the bootstrap uses four attempts, each on a fresh victim;
- a landed write is kept even when an earlier attempt in the same stage left a
  held zombie;
- only a miss *with* a held zombie ends the run.

So a failed run is a rolled die, not a broken build: reboot and run again.
Occasional kernel panics during a run are the same race going the other way —
a reclaim that puts our fake node somewhere the erase can follow into unmapped
memory. The safety rails above cut that exposure substantially but cannot
remove it.

## Troubleshooting

| Symptom | Meaning |
| --- | --- |
| Shizuku status not “running” | start Shizuku first; SamTimer cannot escalate without a shell-uid parent |
| Log stops at `bootstrap` / `parking` | the trigger missed this boot — reboot and re-run |
| `KSU_MISSING` after `UMHPIPE_STARTED` | the helper ran but the module did not load: check `/data/local/tmp/samtimer/umh-kdp.log` |
| Module live but no `su` | the manager is not `me.weishu.kernelsu`, or is not the release that matches `ksud` — install the matching APK |
| `KSU_CONTROL_FAIL` but `su` works | cosmetic: the control-fd probe raced the driver's kprobe registration; it retries and otherwise only affects the status card |
| Phone rebooted mid-run | the kernel panicked on a failed reclaim; reboot, re-run, expect it occasionally |

## Credits / upstream

- **CVE-2026-98260-aurora** — the timer LPE port `timer.c` evolved from
  (real-cred zero-write and fake-cred / ksud late-load chains)
- [RiosWesley/SamTimer](https://github.com/RiosWesley/SamTimer) — the
  pipe_buffer read/write primitive and the UMH workqueue-injection design
- [BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy) —
  the verified Samsung KSU late-load flow this app mirrors (`su_daemon.c`
  shape, `.ksud-stage` staging, manager pairing)
- [BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads) —
  per-target `ksud`/`kernelsu.ko` pairs and the Samsung KDP/RKP/DEFEX port
  methodology (exact-release vermagic, no patch-text)
- [diabl0w/KernelSU](https://github.com/diabl0w/KernelSU/releases/tag/samsung-v2.2) —
  the `ksud` and manager this port ships and pairs with
- [tiann/KernelSU](https://github.com/tiann/KernelSU) — the root module lineage
- [DirtyFrag](https://github.com/mitschud/DirtyFrag) (CVE-2026-43284, DFRoot
  lineage) — the autorun / failed-run-interlock pattern
- [Shizuku](https://github.com/RikkaApps/Shizuku) — shell-uid execution without
  a PC

## Disclaimer

Use at your own risk. The authors take no responsibility for data loss,
bricked devices, or anything else that happens to hardware you point this at.
