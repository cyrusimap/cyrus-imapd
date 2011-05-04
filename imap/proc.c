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
#include <syslog.h>
#include <string.h>

#include "exitcodes.h"
#include "global.h"
#include "proc.h"
#include "retry.h"
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
static FILE *procfile = 0;

static char *proc_getpath(unsigned pid) {
    char *path;
    path = xmalloc(strlen(config_dir)+sizeof(FNAME_PROCDIR)+11);
    if (pid)
	sprintf(path, "%s%s/%u", config_dir, FNAME_PROCDIR, pid);
    else 
	sprintf(path, "%s%s", config_dir, FNAME_PROCDIR);
    return path;
}

int proc_register(const char *progname, const char *clienthost,
		  const char *userid, const char *mailbox)
{
    unsigned pid;
    int pos;

    if (!procfname) {
	pid = getpid();
	procfname = proc_getpath(pid);

	procfile = fopen(procfname, "w+");
	if (!procfile) {
	    if (cyrus_mkdir(procfname, 0755) == -1) {
		fatal("couldn't create proc directory", EC_IOERR);
	    }
	    else {
		syslog(LOG_NOTICE, "created proc directory");
		procfile = fopen(procfname, "w+");
		if (!procfile) {
		    syslog(LOG_ERR, "IOERROR: creating %s: %m", procfname);
		    fatal("can't write proc file", EC_IOERR);
		}
	    }
	}
    }

    rewind(procfile);
    fprintf(procfile, "%s", clienthost);
    if (userid) {
	fprintf(procfile, "\t%s", userid);
	if (mailbox) {
	    fprintf(procfile, "\t%s", mailbox);
	}
    }
    putc('\n', procfile);
    fflush(procfile);
    pos = ftell(procfile);
    if (pos < 0 || ftruncate(fileno(procfile), pos)) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", procfname);
	fatal("can't write proc file", EC_IOERR);
    }
	

    setproctitle("%s: %s %s %s", progname, clienthost, 
		 userid ? userid : "",
		 mailbox ? mailbox : "");

    return 0;
}

void proc_cleanup(void)
{
    if (procfname) {
	fclose(procfile);
	unlink(procfname);
	free(procfname);
	procfname = NULL;
    }
}

static int proc_foreach_helper(unsigned pid, procdata_t *func, void *rock)
{
    int r = 0;
    char *buf = NULL;
    char *path = NULL;
    int fd = -1;

    path = proc_getpath(pid);

    fd = open(path, O_RDONLY, 0);
    if (fd != -1) {
	/* yay, got a file */
	int n;
	struct stat sbuf;
	char *p;
	char *host = NULL;
	char *user = NULL;
	char *mailbox = NULL;

	if (fstat(fd, &sbuf))
	    goto done;

	/* grab a copy of the file contents */
	buf = xmalloc(sbuf.st_size+1);
	n = retry_read(fd, buf, sbuf.st_size);
	close(fd);
	if (n != sbuf.st_size)
	    goto done;

	buf[sbuf.st_size] = '\0';

	/* remove any endline characters */
	p = strchr(buf, '\r');
	if (p) *p = '\0';
	p = strchr(buf, '\n');
	if (p) *p = '\0';

	/* parse the fields */
	host = buf;
	user = strchr(host, '\t');
	if (user) {
	    *user++ = '\0';
	    mailbox = strchr(user, '\t');
	    if (mailbox) *mailbox++ = '\0';
	}

	(*func)(pid, host, user, mailbox, rock);
    }

done:
    free(buf);
    free(path);
    return r;
}

int proc_foreach(procdata_t *func, void *rock)
{
    DIR *dirp;
    struct dirent *dirent;
    char *path;
    const char *p;
    unsigned pid;
    int r = 0;

    path = proc_getpath(0);
    dirp = opendir(path);
    free(path);

    if (dirp) {
	while ((dirent = readdir(dirp)) != NULL) {
	    p = dirent->d_name;
	    if (*p == '.') continue; /* dot files */
	    pid = strtoul(p, NULL, 10);
	    r = proc_foreach_helper(pid, func, rock);
	    if (r) break;
	}
	closedir(dirp);
    }

    return r;
}
