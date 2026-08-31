/* proc.c -- Server process registry */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _PROC_H
#define _PROC_H

struct proc_handle;
extern int proc_register(struct proc_handle **handlep,
                         pid_t pid,
                         const char *servicename,
                         const char *clienthost,
                         const char *userid,
                         const char *mailbox,
                         const char *cmd);
extern void proc_cleanup(struct proc_handle **handlep);
extern void proc_force_cleanup(pid_t pid);

typedef int procdata_t(pid_t pid,
                       const char *servicename, const char *clienthost,
                       const char *userid, const char *mailbox,
                       const char *cmd, void *rock);
extern int proc_foreach(procdata_t *func, void *rock);

struct proc_limits {
    const char *servicename;
    const char *clienthost;
    const char *userid;
    int user;
    int maxuser;
    int host;
    int maxhost;
};
extern int proc_checklimits(struct proc_limits *limitsp);

extern void proc_killuser(const char *userid);
extern void proc_killmbox(const char *mboxname);
extern void proc_killusercmd(const char *userid, const char *cmd, int sig);

extern void proc_settitle_init(int argc, char **argv, char **envp);
extern void proc_settitle(const char *servicename, const char *clienthost,
                          const char *userid, const char *mailbox,
                          const char *cmd);
#endif /* _PROC_H */
