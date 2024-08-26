#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>

#include "procinfo.h"
#include "xmalloc.h"
#include "xstrlcat.h"

static struct proc_info *
add_procinfo_generic(piarray_t *piarray, pid_t pid, const char *servicename,
                     const char *host, const char *user, const char *mailbox,
                     const char *cmdname)
{
    struct proc_info *pinfo;

    if (piarray->count >= piarray->alloc) {
        piarray->alloc += 100;
        piarray->data = xrealloc(piarray->data,
                                 piarray->alloc * sizeof(struct proc_info *));
    }

    pinfo = piarray->data[piarray->count++] =
        (struct proc_info *) xzmalloc(sizeof(struct proc_info));
    pinfo->pid = pid;
    pinfo->servicename = xstrdupsafe(servicename);
    pinfo->host = xstrdupsafe(host);
    pinfo->user = xstrdupsafe(user);
    pinfo->mailbox = xstrdupsafe(mailbox);
    pinfo->cmdname = xstrdupsafe(cmdname);

    return pinfo;
}

EXPORTED int sort_procinfo QSORT_R_COMPAR_ARGS(
                           const void *pa, const void *pb, void *k)
{
    int r;
    const struct proc_info **a = (const struct proc_info**)pa;
    const struct proc_info **b = (const struct proc_info**)pb;
    char *key = (char*)k;
    int rev = islower((int) *key);

    switch (toupper((int) *key)) {
    default:
    case 'P':
        r = (*a)->pid - (*b)->pid;
        break;

    case 'S':
        r = strcmp((*a)->servicename, (*b)->servicename);
        break;

    case 'Q':
        r = strcmp((*a)->state, (*b)->state);
        break;

    case 'T':
        r = (*a)->start - (*b)->start;
        break;

    case 'V':
        r = (*a)->vmsize - (*b)->vmsize;
        break;

    case 'H':
        r = strcmp((*a)->host, (*b)->host);
        break;

    case 'U':
        r = strcmp((*a)->user, (*b)->user);
        break;

    case 'R':
        r = strcmp((*a)->mailbox, (*b)->mailbox);
        break;

    case 'C':
        r = strcmp((*a)->cmdname, (*b)->cmdname);
        break;
    }

    return (rev ? -r : r);
}

EXPORTED void deinit_piarray(piarray_t *piarray)
{
    unsigned i;

    for (i = 0; i < piarray->count; i++) {
        struct proc_info *p = piarray->data[i];
        free(p->servicename);
        free(p->host);
        free(p->user);
        free(p->mailbox);
        free(p->cmdname);
        free(p);
    }
    free(piarray->data);
}

#if defined __OpenBSD__

#include <fcntl.h>
#include <sys/param.h>
#include <sys/sysctl.h>

EXPORTED void init_piarray(piarray_t *piarray)
{
    size_t size;
    static const int mib_ncpu[2] = { CTL_HW, HW_NCPU };

    piarray->count = 0;
    piarray->alloc = 0;
    piarray->data = NULL;

    size = sizeof(piarray->ncpu);
    if (sysctl(mib_ncpu, sizeof(mib_ncpu)/sizeof(mib_ncpu[0]),
               &piarray->ncpu, &size, NULL, 0) == -1) {
        piarray->ncpu = 1;
    }
}

EXPORTED int add_procinfo(pid_t pid, const char *servicename,
                          const char *host, const char *user,
                          const char *mailbox, const char *cmdname,
                          void *rock)
{
    piarray_t *piarray = (piarray_t *) rock;
    struct proc_info *pinfo;
    struct kinfo_proc kip;
    int cnt;
    size_t size;
    static const char *state_abbrev[] = {
        "", "start", "run", "sleep", "stop", "zomb", "dead", "onproc"
    };
    int mib[6] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0, sizeof(kip), 1 };

    mib[3] = pid;
    size = sizeof(kip);
    cnt = sysctl(mib, sizeof(mib)/sizeof(mib[0]), &kip, &size, NULL, 0);
    if ((cnt == -1) || ((size / sizeof(kip)) != 1)) {
        return 0;
    }

    pinfo = add_procinfo_generic(piarray, pid, servicename, host,
                                 user, mailbox, cmdname);

    pinfo->vmsize = kip.p_vm_rssize * sysconf(_SC_PAGESIZE);
    pinfo->start = kip.p_ustart_sec;

    /* based on OpenBSD's /usr/src/usr.bin/top/machine.c, rev 1.110 */
    if (kip.p_wmesg[0]) {
        snprintf(pinfo->state, sizeof(pinfo->state), "%s", kip.p_wmesg);
    } else if ((piarray->ncpu > 1) && (kip.p_cpuid != KI_NOCPU)) {
        snprintf(pinfo->state, sizeof(pinfo->state), "%s/%llu",
                 state_abbrev[kip.p_stat], kip.p_cpuid);
    } else {
        snprintf(pinfo->state, sizeof(pinfo->state), "%s",
                 state_abbrev[kip.p_stat]);
    }

    return 0;
}

#elif defined __NetBSD__

#include <fcntl.h>
#include <sys/param.h>
#include <sys/sysctl.h>

EXPORTED void init_piarray(piarray_t *piarray)
{
    size_t size;
    static const int mib_ncpu[2] = { CTL_HW, HW_NCPU };

    piarray->count = 0;
    piarray->alloc = 0;
    piarray->data = NULL;

    size = sizeof(piarray->ncpu);
    if (sysctl(mib_ncpu, sizeof(mib_ncpu)/sizeof(mib_ncpu[0]),
               &piarray->ncpu, &size, NULL, 0) == -1) {
        piarray->ncpu = 1;
    }
}

EXPORTED int add_procinfo(pid_t pid, const char *servicename,
                          const char *host, const char *user,
                          const char *mailbox, const char *cmdname,
                          void *rock)
{
    piarray_t *piarray = (piarray_t *) rock;
    struct proc_info *pinfo;
    struct kinfo_proc2 kip;
    int cnt;
    size_t size;
    static const char *state_abbrev[] = {
        "", "IDLE", "RUN", "SLEEP", "STOP", "ZOMB", "DEAD", "CPU"
    };
    int mib[6] = { CTL_KERN, KERN_PROC2, KERN_PROC_PID, 0, sizeof(kip), 1 };

    mib[3] = pid;
    size = sizeof(kip);
    cnt = sysctl(mib, sizeof(mib)/sizeof(mib[0]), &kip, &size, NULL, 0);
    if ((cnt == -1) || ((size / sizeof(kip)) != 1)) {
        return 0;
    }

    pinfo = add_procinfo_generic(piarray, pid, servicename, host,
                                 user, mailbox, cmdname);

    pinfo->vmsize = kip.p_vm_rssize * sysconf(_SC_PAGESIZE);
    pinfo->start = kip.p_ustart_sec;

    /* based on NetBSD's /usr/src/external/bsd/top/dist/machine/m_netbsd.c,
       rev 1.23 */
    if ((kip.p_cpuid != KI_NOCPU) && (piarray->ncpu > 1)) {
        if (kip.p_stat == LSSLEEP) {
            snprintf(pinfo->state, sizeof(pinfo->state), "%.6s/%lu",
                     kip.p_wmesg, kip.p_cpuid);
        } else {
            snprintf(pinfo->state, sizeof(pinfo->state), "%.6s/%lu",
                     state_abbrev[(unsigned)kip.p_stat], kip.p_cpuid);
        }
    } else if (kip.p_stat == LSSLEEP) {
        snprintf(pinfo->state, sizeof(pinfo->state), "%s", kip.p_wmesg);
    } else {
        snprintf(pinfo->state, sizeof(pinfo->state), "%s",
                 state_abbrev[(unsigned)kip.p_stat]);
    }

    return 0;
}

#elif defined __DragonFly__

#include <fcntl.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/kinfo.h>
#include <sys/thread.h>

EXPORTED void init_piarray(piarray_t *piarray)
{
    piarray->count = 0;
    piarray->alloc = 0;
    piarray->data = NULL;
}

EXPORTED int add_procinfo(pid_t pid, const char *servicename,
                          const char *host, const char *user,
                          const char *mailbox, const char *cmdname,
                          void *rock)
{
    piarray_t *piarray = (piarray_t *) rock;
    struct proc_info *pinfo;
    struct kinfo_proc kip;
    int cnt;
    size_t state, size;
    static const char *state_abbrev[] = {
        "", "START", "RUN", "SLEEP", "STOP", "ZOMB", "WAIT", "LOCK"
    };
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };

    mib[3] = pid;
    size = sizeof(kip);
    cnt = sysctl(mib, sizeof(mib)/sizeof(mib[0]), &kip, &size, NULL, 0);
    if ((cnt == -1) || ((size / sizeof(kip)) != 1)) {
        return 0;
    }

    pinfo = add_procinfo_generic(piarray, pid, servicename, host,
                                 user, mailbox, cmdname);

    pinfo->vmsize = kip.kp_vm_rssize * sysconf(_SC_PAGESIZE);
    pinfo->start = kip.kp_start.tv_sec;

    /* based on DragonFlyBSD's /usr/src/usr.bin/top/m_dragonfly.c,
       HEAD from 2020-09-06 */
    if (kip.kp_stat == SZOMB) {
        snprintf(pinfo->state, sizeof(pinfo->state), "%s", "ZOMB");
    } else {
        switch (state = kip.kp_lwp.kl_stat) {
        case LSRUN:
            if (kip.kp_lwp.kl_tdflags & TDF_RUNNING) {
                snprintf(pinfo->state, sizeof(pinfo->state),
                         "CPU%d", kip.kp_lwp.kl_cpuid);
            } else {
                snprintf(pinfo->state, sizeof(pinfo->state), "%s", "RUN");
            }
        break;
        case LSSLEEP:
            if (kip.kp_lwp.kl_wmesg != NULL) {
                snprintf(pinfo->state, sizeof(pinfo->state),
                         "%.8s", kip.kp_lwp.kl_wmesg);
                break;
            }
            /* fall through */
        default:
            if (state < sizeof(state_abbrev)/sizeof(state_abbrev[0])) {
                snprintf(pinfo->state, sizeof(pinfo->state),
                         "%.6s", state_abbrev[state]);
            } else {
                snprintf(pinfo->state, sizeof(pinfo->state), "?%5lu", state);
            }
            break;
        }
    }

    return 0;
}

#elif defined __FreeBSD__

#include <fcntl.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>

EXPORTED void init_piarray(piarray_t *piarray)
{
    size_t size;
    static const int mib_ncpu[2] = { CTL_HW, HW_NCPU };

    piarray->count = 0;
    piarray->alloc = 0;
    piarray->data = NULL;

    size = sizeof(piarray->ncpu);
    if (sysctl(mib_ncpu, sizeof(mib_ncpu)/sizeof(mib_ncpu[0]),
               &piarray->ncpu, &size, NULL, 0) == -1) {
        piarray->ncpu = 1;
    }
}

EXPORTED int add_procinfo(pid_t pid, const char *servicename,
                          const char *host, const char *user,
                          const char *mailbox, const char *cmdname,
                          void *rock)
{
    piarray_t *piarray = (piarray_t *) rock;
    struct proc_info *pinfo;
    struct kinfo_proc kip;
    int cnt;
    size_t state, size;
    static const char *state_abbrev[] = {
        "", "START", "RUN", "SLEEP", "STOP", "ZOMB", "WAIT", "LOCK"
    };
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };

    mib[3] = pid;
    size = sizeof(kip);
    cnt = sysctl(mib, sizeof(mib)/sizeof(mib[0]), &kip, &size, NULL, 0);
    if ((cnt == -1) || ((size / sizeof(kip)) != 1)) {
        return 0;
    }

    pinfo = add_procinfo_generic(piarray, pid, servicename, host,
                                 user, mailbox, cmdname);

    pinfo->vmsize = kip.ki_rssize * sysconf(_SC_PAGESIZE);
    pinfo->start = kip.ki_start.tv_sec;

    /* based on FreeBSD's /usr/src/usr.bin/top/machine.c
       from 12.1-RELEASE-p9 */
    switch (state = kip.ki_stat) {
        case SRUN:
            if (piarray->ncpu > 1 && kip.ki_oncpu != NOCPU)
                snprintf(pinfo->state, sizeof(pinfo->state),
                         "CPU%d", kip.ki_oncpu);
            else
                snprintf(pinfo->state, sizeof(pinfo->state),
                         "%s", "RUN");
            break;
        case SLOCK:
            if (kip.ki_kiflag & KI_LOCKBLOCK) {
                snprintf(pinfo->state, sizeof(pinfo->state),
                         "*%s", kip.ki_lockname);
                break;
            }
            /* fall through */
        case SSLEEP:
            snprintf(pinfo->state, sizeof(pinfo->state),
                     "%.6s", kip.ki_wmesg);
            break;
        default:
            if (state < sizeof(state_abbrev)/sizeof(state_abbrev[0])) {
                snprintf(pinfo->state, sizeof(pinfo->state),
                         "%.6s", state_abbrev[state]);
            } else {
                snprintf(pinfo->state, sizeof(pinfo->state),
                         "?%5zu", state);
            }
            break;
    }

    return 0;
}

#else /* xBSD */

EXPORTED void init_piarray(piarray_t *piarray)
{
    FILE *f;
    char buf[1024];

    piarray->count = 0;
    piarray->alloc = 0;
    piarray->data = NULL;
    piarray->boot_time = 0;

    /* Find boot time in /proc/stat (needed for calculating process start) */
    f = fopen("/proc/stat", "r");
    if (f) {
        while (fgets(buf, sizeof(buf), f)) {
            if (sscanf(buf, "btime " TIME_T_FMT "\n", &piarray->boot_time) == 1) break;
            while (buf[strlen(buf)-1] != '\n' && fgets(buf, sizeof(buf), f)) {
            }
        }
        fclose(f);
    }
}

EXPORTED int add_procinfo(pid_t pid, const char *servicename, const char *host,
                          const char *user, const char *mailbox,
                          const char *cmdname, void *rock)
{
    piarray_t *piarray = (piarray_t *) rock;
    struct proc_info *pinfo;
    char procpath[100];
    struct stat sbuf;
    FILE *f;
    int res, d;
    long ld;
    unsigned u;
    unsigned long vmsize = 0, lu;
    unsigned long long starttime = 0;
    char state = 0, *s = NULL;
    static const char *proc_states[] = {
        /* A */ "", /* B */ "", /* C */ "",
        /* D */ " (waiting)",
        /* E */ "", /* F */ "", /* G */ "", /* H */ "", /* I */ "",
        /* J */ "", /* K */ "", /* L */ "", /* M */ "", /* N */ "",
        /* O */ "", /* P */ "", /* Q */ "",
        /* R */ " (running)",
        /* S */ " (sleeping)",
        /* T */ " (stopped)",
        /* U */ "", /* V */ "",
        /* W */ " (paging)",
        /* X */ "", /* Y */ "",
        /* Z */ " (zombie)"
    };

    snprintf(procpath, sizeof(procpath), "/proc/%d", pid);
    if (stat(procpath, &sbuf)) {
        return 0;
    }

    pinfo = add_procinfo_generic(piarray, pid, servicename, host,
                                 user, mailbox, cmdname);

    strlcat(procpath, "/stat", sizeof(procpath));
    f = fopen(procpath, "r");
    if (!f) {
        return 0;
    }

    res = fscanf(f,
                 "%d %ms %c " /* 1-3 */
                 "%d %d %d %d %d %u " /* 4-9 */
                 "%lu %lu %lu %lu %lu %lu " /* 10-15 */
                 "%ld %ld %ld %ld %ld %ld " /* 16-21 */
                 "%llu %lu %ld", /* 22-24 */
                 &d, &s, &state,
                 &d, &d, &d, &d, &d, &u,
                 &lu, &lu, &lu, &lu, &lu, &lu,
                 &ld, &ld, &ld, &ld, &ld, &ld,
                 &starttime, &vmsize, &ld);

    free(s);
    fclose(f);

    if (res == EOF) {
        return 0;
    }

    snprintf(pinfo->state, sizeof(pinfo->state), "%c%s", state,
             isupper((int) state) ? proc_states[state - 'A'] : "");
    pinfo->vmsize = vmsize;

    if (piarray->boot_time) {
        pinfo->start = starttime/sysconf(_SC_CLK_TCK) + piarray->boot_time;
    }

    return 0;
}

#endif /* !xBSD */
