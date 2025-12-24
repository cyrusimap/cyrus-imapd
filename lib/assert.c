/* assert.c -- handle assertion failures */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <stdio.h>
#include <sysexits.h>
#include <syslog.h>

#include "xmalloc.h"
#include "assert.h"

extern int config_fatals_abort;

EXPORTED void
assertionfailed(const char *file, int line, const char *expr)
{
    char buf[1024];

    snprintf(buf, sizeof(buf), "Internal error: assertion failed%s: %s: %d%s%s",
             config_fatals_abort ? " (aborting)" : "",
             file, line, expr ? ": " : "", expr ? expr : "");

    if (config_fatals_abort) {
        /* usually the program's fatal function is responsible for handling
         * the error message, but if we're aborting it won't get called
         */
        syslog(LOG_ERR, "%s", buf);
        abort();
    }
    fatal(buf, EX_SOFTWARE);
}
