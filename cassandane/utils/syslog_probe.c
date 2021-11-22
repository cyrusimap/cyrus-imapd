/* syslog_probe.c
 *
 * A tiny little tool that just syslogs the magic word with the
 * given string as ident prefix
 */

#include <stdio.h>
#include <syslog.h>

/* straight outta cyrus */
#define SYSLOG_FACILITY LOG_LOCAL6

int main(int argc, char **argv)
{
    char ident[1024];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s prefix\n", argv[0]);
        return 1;
    }

    snprintf(ident, sizeof(ident), "%s/syslog_probe", argv[1]);

    openlog(ident, LOG_PID, SYSLOG_FACILITY);
    syslog(LOG_NOTICE, "the magic word");
    closelog();

    return 0;
}
