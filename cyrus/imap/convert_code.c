/* convert_code.c: Convert IMAP_* error to exitcodes.h exit status
 * Copyright 1998 Carnegie Mellon University
 * 
 * No warranties, either expressed or implied, are made regarding the
 * operation, use, or results of the software.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted for non-commercial purposes only
 * provided that this copyright notice appears in all copies and in
 * supporting documentation.
 *
 * Permission is also granted to Internet Service Providers and others
 * entities to use the software for internal purposes.
 *
 * The distribution, modification or sale of a product which uses or is
 * based on the software, in whole or in part, for commercial purposes or
 * benefits requires specific, additional permission from:
 *
 *  Office of Technology Transfer
 *  Carnegie Mellon University
 *  5000 Forbes Avenue
 *  Pittsburgh, PA  15213-3890
 *  (412) 268-4387, fax: (412) 268-7395
 *  tech-transfer@andrew.cmu.edu
 */

/* $Id: convert_code.c,v 1.2 1999/04/08 21:04:22 tjs Exp $ */

/* Same old convert_code function moved into one place instead of being
 * redundant in every file.
 * tjs 23-jul-1998
 */

#include "imap_err.h"
#include "exitcodes.h"

int convert_code(r)
int r;
{
    switch (r) {
    case 0:
        return 0;
        
    case IMAP_IOERROR:
        return EC_IOERR;

    case IMAP_PERMISSION_DENIED:
        return EC_NOPERM;

    case IMAP_QUOTA_EXCEEDED:
        return EC_TEMPFAIL;

    case IMAP_MAILBOX_NOTSUPPORTED:
        return EC_DATAERR;

    case IMAP_MAILBOX_NONEXISTENT:
        return EC_UNAVAILABLE;
    }
        
    /* Some error we're not expecting. */
    return EC_SOFTWARE;
}       
