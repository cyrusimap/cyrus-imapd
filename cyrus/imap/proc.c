/* proc.c -- Server process registry
 $Id: proc.c,v 1.11 1998/05/15 21:49:40 neplokh Exp $
 
 # Copyright 1998 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
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
