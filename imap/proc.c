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

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <sys/stat.h>

#include "assert.h"
#include "exitcodes.h"
#include "global.h"
#include "proc.h"
#include "retry.h"
#include "util.h"
#include "xmalloc.h"

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

static char *procfname = 0;

static char *proc_getpath(pid_t pid, int isnew)
{
    struct buf buf = BUF_INITIALIZER;

    if (config_getstring(IMAPOPT_PROC_PATH)) {
	const char *procpath = config_getstring(IMAPOPT_PROC_PATH);

	if (procpath[0] != '/')
	    fatal("proc path must be fully qualified", EC_CONFIG);

	if (strlen(procpath) < 2)
	    fatal("proc path must not be '/'", EC_CONFIG);

	buf_setcstr(&buf, procpath);

	if (buf.s[buf.len-1] != '/')
	    buf_putc(&buf, '/');
    }
    else {
	buf_setcstr(&buf, config_dir);
	buf_appendcstr(&buf, FNAME_PROCDIR);
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

EXPORTED int proc_register(const char *servicename, const char *clienthost,
		  const char *userid, const char *mailbox, const char *cmd)
{
    pid_t pid = getpid();
    FILE *procfile = NULL;
    char *newfname = NULL;

    if (!procfname)
	procfname = proc_getpath(pid, /*isnew*/0);

    newfname = proc_getpath(pid, /*isnew*/1);

    procfile = fopen(newfname, "w+");
    if (!procfile) {
	if (cyrus_mkdir(newfname, 0755) == -1) {
	    fatal("couldn't create proc directory", EC_IOERR);
	}
	else {
	    syslog(LOG_NOTICE, "created proc directory");
	    procfile = fopen(newfname, "w+");
	    if (!procfile) {
		syslog(LOG_ERR, "IOERROR: creating %s: %m", newfname);
		fatal("can't write proc file", EC_IOERR);
	    }
	}
    }

    if (!servicename) servicename = "";
    if (!clienthost) clienthost = "";
    if (!userid) userid = "";
    if (!mailbox) mailbox = "";
    if (!cmd) cmd = "";
    fprintf(procfile, "%s\t%s\t%s\t%s\t%s\n", servicename, clienthost, userid, mailbox, cmd);
    fclose(procfile);

    if (rename(newfname, procfname)) {
	syslog(LOG_ERR, "IOERROR: renaming %s to %s: %m", newfname, procfname);
	unlink(newfname);
	fatal("can't write proc file", EC_IOERR);
    }

    setproctitle("%s: %s %s %s %s", servicename, clienthost, userid, mailbox, cmd);

    free(newfname);
    return 0;
}

EXPORTED void proc_cleanup(void)
{
    if (procfname) {
	unlink(procfname);
	free(procfname);
	procfname = NULL;
    }
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
    int r = 0;

    path = proc_getdir();
    dirp = opendir(path);

    if (dirp) {
	while ((dirent = readdir(dirp)) != NULL) {
	    p = dirent->d_name;
	    if (*p == '.') continue; /* dot files */
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
			const char *servicename __attribute__((unused)),
			const char *clienthost,
			const char *userid,
			const char *mboxname __attribute__((unused)),
			const char *cmd __attribute__((unused)),
			void *rock)
{
    struct proc_limits *limitsp = (struct proc_limits *)rock;

    /* we only count logged in sessions */
    if (!userid) return 0;

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
