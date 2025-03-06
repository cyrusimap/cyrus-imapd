/*
 * flags.c
 *
 *  Created on: Oct 6, 2014
 *      Author: James Cassell
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "flags.h"
#include "imparse.h"
#include "strarray.h"
#include "util.h"
#include "xmalloc.h"

static int verify_flag(char *f)
{
    if (f[0] == '\\') {
        lcase(f);
        if (strcmp(f, "\\seen") && strcmp(f, "\\answered") &&
            strcmp(f, "\\flagged") && strcmp(f, "\\draft") &&
            strcmp(f, "\\deleted")) {
            return 0;
        }
        return 1;
    }
    if (!imparse_isatom(f)) {
        return 0;
    }
    return 1;
}

int verify_flaglist(strarray_t *sl)
{
    int i;
    char *joined;
    strarray_t *resplit;
    // Join all the flags, putting spaces between them
    joined = strarray_join(sl, " ");
    // Clear out the sl for reuse
    strarray_truncate(sl, 0);
    // Split the joined flag list at spaces
    resplit = strarray_split(joined, " ", STRARRAY_TRIM);

    // Perform duplicate elimination and flag verification
    for (i = 0; i < resplit->count ; i++) {
        // has the side effect of lower-casing system flags
        if (!verify_flag(resplit->data[i])) {
            /*  [IMAP4FLAGS] Section 2 "General Requirements for Flag
             *  Handling" says "If a flag validity check fails, the
             *  flag MUST be ignored", which for us means that we
             *  simply remove the invalid flag from the list.
             */
            continue;
        }
        strarray_add_case(sl, resplit->data[i]);
    }
    strarray_free(resplit);
    free(joined);
    return sl->count;
}
