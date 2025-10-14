#ifndef INCLUDED_PROCINFO_H
#define INCLUDED_PROCINFO_H

#include <sys/types.h>
#include <time.h>

#include "cyr_qsort_r.h"

struct proc_info
{
    pid_t pid;
    char *servicename;
    char *user;
    char *host;
    char *mailbox;
    char *cmdname;
    char state[22];
    time_t start;
    unsigned long vmsize; /* in bytes */
};

typedef struct
{
    unsigned count;
    unsigned alloc;
    struct proc_info **data;
    time_t boot_time; /* not used on xBSD */
    int ncpu;         /* not used on Linux */
} piarray_t;

extern void init_piarray(piarray_t *piarray);
extern void deinit_piarray(piarray_t *piarray);
extern int add_procinfo(pid_t pid,
                        const char *servicename,
                        const char *host,
                        const char *user,
                        const char *mailbox,
                        const char *cmdname,
                        void *rock);
extern int sort_procinfo QSORT_R_COMPAR_ARGS(const void *pa,
                                             const void *pb,
                                             void *k);

#endif /* INCLUDED_PROCINFO_H */
