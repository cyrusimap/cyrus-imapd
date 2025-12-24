/* proc.c -- Server process registry */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <sysexits.h>
#include <syslog.h>
#include <string.h>
#include <sys/stat.h>

#include "assert.h"
#include "libconfig.h"
#include "proc.h"
#include "retry.h"
#include "util.h"
#include "xmalloc.h"
#include "xunlink.h"

#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif


#define FNAME_PROCDIR "/proc"

/* n.b. setproctitle might come from setproctitle.c, or might come from a
 * system library
 */
extern void setproctitle(const char *fmt, ...)
                         __attribute__((format(printf, 1, 2)));

static char *proc_getpath(pid_t pid, int isnew)
{
    struct buf buf = BUF_INITIALIZER;

    if (config_getstring(IMAPOPT_PROC_PATH)) {
        const char *procpath = config_getstring(IMAPOPT_PROC_PATH);

        if (procpath[0] != '/')
            fatal("proc path must be fully qualified", EX_CONFIG);

        if (strlen(procpath) < 2)
            fatal("proc path must not be '/'", EX_CONFIG);

        buf_setcstr(&buf, procpath);

        if (buf.s[buf.len-1] != '/')
            buf_putc(&buf, '/');
    }
    else {
        buf_setcstr(&buf, config_dir);
        buf_appendcstr(&buf, FNAME_PROCDIR);
        buf_putc(&buf, '/');
    }

    if (pid)
        buf_printf(&buf, "%u", pid);

    if (isnew)
        buf_appendcstr(&buf, ".new");

    return buf_release(&buf);
}

static char *proc_getdir(void)
{
    return proc_getpath(0, 0);
}

struct proc_handle {
    pid_t pid;
    char *fname;
};

EXPORTED int proc_register(struct proc_handle **handlep,
                           pid_t pid,
                           const char *servicename,
                           const char *clienthost,
                           const char *userid,
                           const char *mailbox,
                           const char *cmd)
{
    FILE *procfile = NULL;
    char *newfname = NULL;
    struct proc_handle *handle = NULL;
    int handle_is_new = 0;

    assert(handlep != NULL);

    if (*handlep != NULL) {
        handle = *handlep;
        pid = handle->pid;
    }
    else {
        handle = xmalloc(sizeof *handle);
        handle_is_new = 1;
        if (!pid) pid = getpid();
        handle->pid = pid;
        handle->fname = proc_getpath(pid, /*isnew*/0);
        *handlep = handle;
    }

    newfname = proc_getpath(pid, /*isnew*/1);

    procfile = fopen(newfname, "w+");
    if (!procfile) {
        if (cyrus_mkdir(newfname, 0755) == -1) {
            xsyslog(LOG_ERR, "IOERROR: failed to create proc directory",
                               "fname=<%s>", newfname);
            goto error;
        }
        else {
            syslog(LOG_NOTICE, "created proc directory");
            procfile = fopen(newfname, "w+");
            if (!procfile) {
                xsyslog(LOG_ERR, "IOERROR: failed to create proc file",
                                 "fname=<%s>", newfname);
                goto error;
            }
        }
    }

    if (!servicename) servicename = "";
    if (!clienthost) clienthost = "";
    if (!userid) userid = "";
    if (!mailbox) mailbox = "";
    if (!cmd) cmd = "";
    fprintf(procfile, "%s\t%s\t%s\t%s\t%s\n",
                      servicename, clienthost, userid, mailbox, cmd);
    fclose(procfile);

    if (cyrus_rename(newfname, handle->fname)) {
        xsyslog(LOG_ERR, "IOERROR: rename failed",
                         "source=<%s> dest=<%s>",
                         newfname, handle->fname);
        xunlink(newfname);
        goto error;
    }

    free(newfname);
    return 0;

error:
    if (handle_is_new) {
        xunlink(handle->fname);
        free(handle->fname);
        free(handle);
        *handlep = NULL;
    }
    free(newfname);
    return -1;
}

EXPORTED void proc_cleanup(struct proc_handle **handlep)
{
    struct proc_handle *handle;

    assert(handlep != NULL);

    handle = *handlep;
    *handlep = NULL;

    if (handle) {
        xunlink(handle->fname);
        free(handle->fname);
        free(handle);
    }
}

/* used by master to remove proc files after service processes crash */
EXPORTED void proc_force_cleanup(pid_t pid)
{
    char *fname = proc_getpath(pid, /*isnew*/0);

    if (fname)
        xunlink(fname);
    free(fname);
}

static int proc_foreach_helper(pid_t pid, procdata_t *func, void *rock)
{
    int r = 0;
    char *buf = NULL;
    char *path = NULL;
    int fd = -1;

    path = proc_getpath(pid, /*isnew*/0);

    fd = open(path, O_RDONLY, 0);
    if (fd != -1) {
        /* yay, got a file */
        int n;
        struct stat sbuf;
        char *p;
        char *service = NULL;
        char *host = NULL;
        char *user = NULL;
        char *mailbox = NULL;
        char *cmd = NULL;

        if (fstat(fd, &sbuf))
            goto done;
        if (!S_ISREG(sbuf.st_mode))
            goto done;

        /* grab a copy of the file contents */
        buf = xmalloc(sbuf.st_size+1);
        n = retry_read(fd, buf, sbuf.st_size);
        if (n != sbuf.st_size)
            goto done;

        buf[sbuf.st_size] = '\0';

        /* remove any endline characters */
        p = strchr(buf, '\r');
        if (p) *p = '\0';
        p = strchr(buf, '\n');
        if (p) *p = '\0';

        /* parse the fields */
        service = buf;
        host = strchr(service, '\t');
        if (!host) goto done;
        *host++ = '\0';
        user = strchr(host, '\t');
        if (user) {
            *user++ = '\0';
            mailbox = strchr(user, '\t');
        }
        if (mailbox) {
            *mailbox++ = '\0';
            cmd = strchr(mailbox, '\t');
        }
        if (cmd) {
            *cmd++ = '\0';
        }

        (*func)(pid, service, host, user, mailbox, cmd, rock);
    }

done:
    xclose(fd);
    free(buf);
    free(path);
    return r;
}

EXPORTED int proc_foreach(procdata_t *func, void *rock)
{
    DIR *dirp;
    struct dirent *dirent;
    char *path;
    const char *p;
    pid_t pid;
    char *end = NULL;
    size_t len;
    int r = 0;

    path = proc_getdir();
    dirp = opendir(path);

    if (dirp) {
        while ((dirent = readdir(dirp)) != NULL) {
            p = dirent->d_name;
            if (*p == '.') continue; /* dot files */
            len = strlen(p);
            if (len > 4 && !strcmp(p + len - 4, ".new")) continue; /* temporary new file */
            pid = strtoul(p, &end, 10);
            if (pid == 0 || end == NULL || *end || end == p) {
                syslog(LOG_ERR, "IOERROR: bogus filename \"%s/%s\" in proc_foreach",
                                path, p);
                continue;
            }
            r = proc_foreach_helper(pid, func, rock);
            if (r) break;
        }
        closedir(dirp);
    }

    free(path);
    return r;
}

static int procusage_cb(pid_t pid __attribute__((unused)),
                        const char *servicename,
                        const char *clienthost,
                        const char *userid,
                        const char *mboxname __attribute__((unused)),
                        const char *cmd __attribute__((unused)),
                        void *rock)
{
    struct proc_limits *limitsp = (struct proc_limits *)rock;

    /* we only count logged in sessions */
    if (!userid) return 0;

    /* only check for logins to the particular protocol */
    if (limitsp->servicename && strcmp(servicename, limitsp->servicename))
        return 0;

    if (limitsp->clienthost && !strcmp(clienthost, limitsp->clienthost))
        limitsp->host++;
    if (limitsp->userid && !strcmp(userid, limitsp->userid))
        limitsp->user++;

    return 0;
}

EXPORTED int proc_checklimits(struct proc_limits *limitsp)
{
    limitsp->maxhost = config_getint(IMAPOPT_MAXLOGINS_PER_HOST);
    limitsp->maxuser = config_getint(IMAPOPT_MAXLOGINS_PER_USER);

    if (!limitsp->maxuser && !limitsp->maxhost)
        return 0;

    limitsp->host = 0;
    limitsp->user = 0;
    proc_foreach(procusage_cb, limitsp);

    if (limitsp->maxhost && limitsp->host >= limitsp->maxhost) return 1;
    if (limitsp->maxuser && limitsp->user >= limitsp->maxuser) return 1;

    return 0;
}

struct prockill_data {
    const char *servicename;
    const char *clienthost;
    const char *userid;
    const char *mboxname;
    const char *cmd;
    int sig;
};

#define PROCKILL_INIT { NULL, NULL, NULL, NULL, NULL, 0 }

static int prockill_cb(pid_t pid,
                       const char *servicename,
                       const char *clienthost,
                       const char *userid,
                       const char *mboxname,
                       const char *cmd,
                       void *rock)
{
    struct prockill_data *dat = (struct prockill_data *)rock;
    pid_t mypid = getpid();

    /* don't kill myself */
    if (mypid == pid)
        return 0;

    if (dat->servicename && strcmpsafe(servicename, dat->servicename))
        return 0;

    if (dat->clienthost && strcmpsafe(clienthost, dat->clienthost))
        return 0;

    if (dat->userid && strcmpsafe(userid, dat->userid))
        return 0;

    if (dat->mboxname && strcmpsafe(mboxname, dat->mboxname))
        return 0;

    if (dat->cmd && strcmpsafe(cmd, dat->cmd))
        return 0;

    if (dat->sig)
        kill(pid, dat->sig);
    else
        kill(pid, SIGTERM);

    return 0;
}


EXPORTED void proc_killuser(const char *userid)
{
    struct prockill_data rock = PROCKILL_INIT;

    /* can't kill all non-connected, that's evil */
    assert(userid && userid[0]);

    rock.userid = userid;

    proc_foreach(prockill_cb, &rock);
}

EXPORTED void proc_killmbox(const char *mboxname)
{
    struct prockill_data rock = PROCKILL_INIT;

    /* can't kill all non-selected, that's evil */;
    assert(mboxname && mboxname[0]);

    rock.mboxname = mboxname;

    proc_foreach(prockill_cb, &rock);
}

EXPORTED void proc_killusercmd(const char *userid, const char *cmd, int sig)
{
    struct prockill_data rock = PROCKILL_INIT;

    /* can't kill all non-selected, that's evil */;
    assert(userid && userid[0]);
    /* or all cmd either... use proc_killuser if you want that */
    assert(cmd && cmd[0]);

    rock.userid = userid;
    rock.cmd = cmd;
    rock.sig = sig;

    proc_foreach(prockill_cb, &rock);
}

/* n.b. proc_settitle_init() is defined in setproctitle.c */

EXPORTED void proc_settitle(const char *servicename, const char *clienthost,
                            const char *userid, const char *mailbox,
                            const char *cmd)
{
    if (!servicename) servicename = "";
    if (!clienthost) clienthost = "";
    if (!userid) userid = "";
    if (!mailbox) mailbox = "";
    if (!cmd) cmd = "";

    setproctitle("%s: %s %s %s %s",
                 servicename, clienthost, userid, mailbox, cmd);
}
