/*
 * Handle assertion failures
 */
#include <sysexits.h>

assertionfailed(file, line, expr)
char *file;
char *line;
char *expr;
{
    char buf[1024];

    sprintf(buf, "Internal error: assertion failed: %s: %d%s%s",
	    file, line, expr ? ": " : "", expr ? expr : "");
    fatal(buf, EX_SOFTWARE);
}
