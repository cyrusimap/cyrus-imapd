/*
 * Server process registry
 */
#include <stdio.h>
#include <sysexits.h>
#include "config.h"
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
    char *val;
    int pid;

    if (!procfname) {
	pid = getpid();
    
	val = config_getstring("configdirectory", "");
	procfname = xmalloc(strlen(val)+sizeof(FNAME_PROCDIR)+10);
	sprintf(procfname, "%s%s%d", val, FNAME_PROCDIR, pid);

	procfile = fopen(procfname, "w+");
	if (!procfile) fatal("can't write proc file", EX_IOERR);
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
