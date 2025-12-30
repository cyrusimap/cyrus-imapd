/* convert_code.c: Convert IMAP_* error to sysexits.h exit status */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/* Same old convert_code function moved into one place instead of being
 * redundant in every file.
 * tjs 23-jul-1998
 */

#include <config.h>

#include <sysexits.h>

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

EXPORTED int convert_code(int r)
{
    switch (r) {
    case 0:
        return 0;

    case IMAP_IOERROR:
        return EX_IOERR;

    case IMAP_PERMISSION_DENIED:
        return EX_NOPERM;

    case IMAP_QUOTA_EXCEEDED:
        return EX_TEMPFAIL;

    case IMAP_MAILBOX_NOTSUPPORTED:
        return EX_DATAERR;

    case IMAP_MAILBOX_NONEXISTENT:
        return EX_UNAVAILABLE;
    }

    /* Some error we're not expecting. */
    return EX_SOFTWARE;
}
