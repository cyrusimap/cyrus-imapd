/* proc.c -- Server process registry
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
                       const char *servicename,
                       const char *clienthost,
                       const char *userid,
                       const char *mailbox,
                       const char *cmd,
                       void *rock);
extern int proc_foreach(procdata_t *func, void *rock);

struct proc_limits
{
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
extern void proc_settitle(const char *servicename,
                          const char *clienthost,
                          const char *userid,
                          const char *mailbox,
                          const char *cmd);
#endif /* _PROC_H */
