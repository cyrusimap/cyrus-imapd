/* syslog_probe.c
 *
 * A tiny little tool that just syslogs the magic word with the
 * given string as ident prefix
 */

#include <sys/wait.h>

#include <stdio.h>
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
        return 1;
    }

    snprintf(ident, sizeof(ident), "%s/syslog_probe", argv[1]);

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

        return -1;
    }
    else {
        /* fork failed */
        perror("fork");
        return -1;
    }
}
