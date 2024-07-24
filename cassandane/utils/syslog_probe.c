/* syslog_probe.c
 *
 * A tiny little tool that just syslogs the magic word with the
 * given string as ident prefix
 */

#include <sys/wait.h>

#include <stdio.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

/* straight outta cyrus */
#define SYSLOG_FACILITY LOG_LOCAL6

int main(int argc, char **argv)
{
    char ident[1024];
    int pid;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s prefix\n", argv[0]);
        return EX_USAGE;
    }

    snprintf(ident, sizeof(ident), "%s/syslog_probe", argv[1]);

    /* Fork, and log the magic word from the child, in case LD_PRELOAD
     * is discarded during fork.
     * XXX This doesn't necessarily tell us much. To do this properly,
     * XXX we probably need to mimick certain details of Cyrus master's
     * XXX spawn code (capabilities, setuid, etc).
     */
    pid = fork();
    if (pid == 0) {
        /* child */
        openlog(ident, LOG_PID, SYSLOG_FACILITY);
        syslog(LOG_NOTICE, "the magic word");
        closelog();

        return 0;
    }
    else if (pid > 0) {
        /* parent */
        int wstatus;

        if (wait(&wstatus) && WIFEXITED(wstatus)) {
            return WEXITSTATUS(wstatus);
        }

        return EX_SOFTWARE;
    }
    else {
        /* fork failed */
        perror("fork");
        return EX_OSERR;
    }
}
