/* proc.c -- Server process registry
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */
#include <stdio.h>
#include <syslog.h>

#include "config.h"
#include "sysexits.h"
#include "xmalloc.h"

#define FNAME_PROCDIR "/proc/"

static char *procfname = 0;
static FILE *procfile = 0;

proc_register(progname, clienthost, userid, mailbox)
char *progname;
char *clienthost;
char *userid;
char *mailbox;
{
    unsigned pid;

    if (!procfname) {
	pid = getpid();
    
	procfname = xmalloc(strlen(config_dir)+sizeof(FNAME_PROCDIR)+10);
	sprintf(procfname, "%s%s%u", config_dir, FNAME_PROCDIR, pid);

	procfile = fopen(procfname, "w+");
	if (!procfile) {
	    syslog(LOG_ERR, "IOERROR: creating %s: %m", procfname);
	    fatal("can't write proc file", EX_IOERR);
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
    ftruncate(fileno(procfile), ftell(procfile));

    setproctitle("%s: %s %s %s", progname, clienthost, userid ? userid : "",
		 mailbox ? mailbox : "");

    return 0;
}

proc_cleanup()
{
    if (procfname) {
	fclose(procfile);
	unlink(procfname);
	procfname = 0;
    }
}
