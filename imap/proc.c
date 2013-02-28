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
 *
 * $Id: proc.c,v 1.27 2010/01/06 17:01:38 murch Exp $
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

static char *proc_getdir(void)
{
    return strconcat(config_dir, FNAME_PROCDIR, (char *)NULL);
}

static char *proc_getpath(pid_t pid, int isnew)
{
    char *path;

    assert(pid > 0);
    path = xmalloc(strlen(config_dir)+sizeof(FNAME_PROCDIR)+16);
    sprintf(path, "%s%s/%s%u%s",
		config_dir,
		FNAME_PROCDIR,
		(isnew ? "." : ""),
		(unsigned)pid,
		(isnew ? ".new" : ""));
    return path;
}

EXPORTED int proc_register(const char *servicename, const char *clienthost,
		  const char *userid, const char *mailbox)
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

    fprintf(procfile, "%s\t%s", servicename, clienthost);
    if (userid) {
	fprintf(procfile, "\t%s", userid);
	if (mailbox) {
	    fprintf(procfile, "\t%s", mailbox);
	}
    }
    putc('\n', procfile);
    fclose(procfile);

    if (rename(newfname, procfname)) {
	syslog(LOG_ERR, "IOERROR: renaming %s to %s: %m", newfname, procfname);
	unlink(newfname);
	fatal("can't write proc file", EC_IOERR);
    }

    setproctitle("%s: %s %s %s", servicename, clienthost,
		 userid ? userid : "",
		 mailbox ? mailbox : "");

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
	    if (mailbox) *mailbox++ = '\0';
	}

	(*func)(pid, service, host, user, mailbox, rock);
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

static int killuser_cb(pid_t pid,
		       const char *servicename __attribute__((unused)),
		       const char *clienthost  __attribute__((unused)),
		       const char *userid,
		       const char *mboxname __attribute__((unused)),
		       void *rock)
{
    pid_t mypid = getpid();
    const char *test = (const char *)rock;

    /* don't kill myself */
    if (mypid == pid)
	return 0;

    if (!strcmpsafe(userid, test))
	kill(pid, SIGTERM);

    return 0;
}

static int killmbox_cb(pid_t pid,
		       const char *servicename __attribute__((unused)),
		       const char *clienthost  __attribute__((unused)),
		       const char *userid __attribute__((unused)),
		       const char *mboxname,
		       void *rock)
{
    pid_t mypid = getpid();
    const char *test = (const char *)rock;

    /* don't kill myself */
    if (mypid == pid)
	return 0;

    if (!strcmpsafe(mboxname, test))
	kill(pid, SIGTERM);

    return 0;
}

EXPORTED void proc_killuser(const char *userid)
{
    /* can't kill all non-connected, that's evil */
    assert(userid && userid[0]);

    proc_foreach(killuser_cb, (void *)userid);
}

EXPORTED void proc_killmbox(const char *mboxname)
{
    /* can't kill all non-selected, that's evil */;
    assert(mboxname && mboxname[0]);

    proc_foreach(killmbox_cb, (void *)mboxname);
}
