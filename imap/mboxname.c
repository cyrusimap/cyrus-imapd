/* mboxname.c -- Mailbox list manipulation routines
 $Id: mboxname.c,v 1.20 2001/01/05 06:00:18 leg Exp $

 * Copyright (c)1998-2000 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <com_err.h>

#include "assert.h"
#include "glob.h"
#include "imapconf.h"
#include "mailbox.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "xmalloc.h"

#include "mboxname.h"

/* Mailbox patterns which the design of the server prohibits */
static char *badmboxpatterns[] = {
    "",
    "*\t*",
    "*\n*",
    "*/*",
    ".*",
    "*.",
    "*..*",
    "user",
};
#define NUM_BADMBOXPATTERNS (sizeof(badmboxpatterns)/sizeof(*badmboxpatterns))

#define XX 127
/*
 * Table for decoding modified base64 for IMAP UTF-7 mailbox names
 */
static const char index_mod64[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, 63,XX,XX,XX,
    52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,XX,XX,XX,
    XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
    XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};
#define CHARMOD64(c)  (index_mod64[(unsigned char)(c)])

/*
 * Convert the external mailbox 'name' to an internal name.
 * If 'userid' is non-null, it is the name of the current user.
 * On success, results are placed in the buffer pointed to by
 * 'result', the buffer must be of size MAX_MAILBOX_NAME+1.
 */
int mboxname_tointernal(const char *name, const char *userid, char *result)
{
    if ((name[0] == 'i' || name[0] == 'I') &&
	!strncasecmp(name, "inbox", 5) &&
	(name[5] == '\0' || name[5] == '.')) {

	if (!userid || strchr(userid, '.')) {
	    return IMAP_MAILBOX_BADNAME;
	}

	if (strlen(name)+strlen(userid)+5 > MAX_MAILBOX_NAME) {
	    return IMAP_MAILBOX_BADNAME;
	}

	strcpy(result, "user.");
	strcat(result, userid);
	strcat(result, name+5);
	return 0;
    }
	    
    if (strlen(name) > MAX_MAILBOX_NAME) {
	return IMAP_MAILBOX_BADNAME;
    }
    strcpy(result, name);
    return 0;
}

/*
 * Return nonzero if 'userid' owns the (internal) mailbox 'name'.
 */
int mboxname_userownsmailbox(char *userid, char *name)
{
    if (!strchr(userid, '.') && !strncmp(name, "user.", 5) &&
	!strncmp(name+5, userid, strlen(userid)) &&
	name[5+strlen(userid)] == '.') {
	return 1;
    }
    return 0;
}

/*
 * Apply additional restrictions on netnews mailbox names.
 * Cannot have all-numeric name components.
 */
int mboxname_netnewscheck(char *name)
{
    int c;
    int sawnonnumeric = 0;

    while ((c = *name++)!=0) {
	switch (c) {
	case '.':
	    if (!sawnonnumeric) return IMAP_MAILBOX_BADNAME;
	    sawnonnumeric = 0;
	    break;

	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	    break;

	default:
	    sawnonnumeric = 1;
	    break;
	}
    }
    if (!sawnonnumeric) return IMAP_MAILBOX_BADNAME;
    return 0;
}
	    

/*
 * Apply site policy restrictions on mailbox names.
 * Restrictions are hardwired for now.
 */
#define GOODCHARS " +,-.0123456789:=@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
int mboxname_policycheck(char *name)
{
    int i;
    struct glob *g;
    int sawutf7 = 0;
    unsigned c1, c2, c3, c4, c5, c6, c7, c8;
    int ucs4;

    if (strlen(name) > MAX_MAILBOX_NAME) return IMAP_MAILBOX_BADNAME;
    for (i = 0; i < NUM_BADMBOXPATTERNS; i++) {
	g = glob_init(badmboxpatterns[i], 0);
	if (GLOB_TEST(g, name) != -1) {
	    glob_free(&g);
	    return IMAP_MAILBOX_BADNAME;
	}
	glob_free(&g);
    }

    if (*name == '~') return IMAP_MAILBOX_BADNAME;
    while (*name) {
	if (*name == '&') {
	    /* Modified UTF-7 */
	    name++;
	    while (*name != '-') {
		if (sawutf7) {
		    /* Two adjacent utf7 sequences */
		    return IMAP_MAILBOX_BADNAME;
		}

		if ((c1 = CHARMOD64(*name++)) == XX ||
		    (c2 = CHARMOD64(*name++)) == XX ||
		    (c3 = CHARMOD64(*name++)) == XX) {
		    /* Non-base64 character */
		    return IMAP_MAILBOX_BADNAME;
		}
		ucs4 = (c1 << 10) | (c2 << 4) | (c3 >> 2);
		if ((ucs4 & 0xff80) == 0 || (ucs4 & 0xf800) == 0xd800) {
		    /* US-ASCII or multi-word character */
		    return IMAP_MAILBOX_BADNAME;
		}
		if (*name == '-') {
		    /* Trailing bits not zero */
		    if (c3 & 0x03) return IMAP_MAILBOX_BADNAME;

		    /* End of UTF-7 sequence */
		    break;
		}

		if ((c4 = CHARMOD64(*name++)) == XX ||
		    (c5 = CHARMOD64(*name++)) == XX ||
		    (c6 = CHARMOD64(*name++)) == XX) {
		    /* Non-base64 character */
		    return IMAP_MAILBOX_BADNAME;
		}
		ucs4 = ((c3 & 0x03) << 14) | (c4 << 8) | (c5 << 2) | (c6 >> 4);
		if ((ucs4 & 0xff80) == 0 || (ucs4 & 0xf800) == 0xd800) {
		    /* US-ASCII or multi-word character */
		    return IMAP_MAILBOX_BADNAME;
		}
		if (*name == '-') {
		    /* Trailing bits not zero */
		    if (c6 & 0x0f) return IMAP_MAILBOX_BADNAME;

		    /* End of UTF-7 sequence */
		    break;
		}

		if ((c7 = CHARMOD64(*name++)) == XX ||
		    (c8 = CHARMOD64(*name++)) == XX) {
		    /* Non-base64 character */
		    return IMAP_MAILBOX_BADNAME;
		}
		ucs4 = ((c6 & 0x0f) << 12) | (c7 << 6) | c8;
		if ((ucs4 & 0xff80) == 0 || (ucs4 & 0xf800) == 0xd800) {
		    /* US-ASCII or multi-word character */
		    return IMAP_MAILBOX_BADNAME;
		}
	    }

	    if (name[-1] == '&') sawutf7 = 0; /* '&-' is sequence for '&' */
	    else sawutf7 = 1;

	    name++;		/* Skip over terminating '-' */
	}
	else {
	    if (!strchr(GOODCHARS, *name++)) return IMAP_MAILBOX_BADNAME;
	    sawutf7 = 0;
	}
    }
    return 0;
}

