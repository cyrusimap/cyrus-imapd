/* cli_fatal.c - Provide a generic fatal() for the command line utilities */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <sysexits.h>

#include "global.h"
#include "xmalloc.h"

/* generic fatal() routine for command line utilities */
EXPORTED void fatal(const char *message, int code)
{
    static int recurse_code = 0;

    if (recurse_code) {
        exit(code);
    }

    recurse_code = code;
    fprintf(stderr, "fatal error: %s\n", message);
    cyrus_done();

    if (code != EX_PROTOCOL && config_fatals_abort) abort();

    exit(code);
}
