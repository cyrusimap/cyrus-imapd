/* mboxname.c -- Mailbox list manipulation routines
 *
 *	(C) Copyright 1995 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <com_err.h>

#include "assert.h"
#include "glob.h"
#include "config.h"
#include "mailbox.h"
#include "sysexits.h"
#include "imap_err.h"
#include "xmalloc.h"

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

/*
 * Convert the external mailbox 'name' to an internal name.
 * If 'userid' is non-null, it is the name of the current user.
 * On success, results are placed in the buffer pointed to by
 * 'result', the buffer must be of size MAX_MAILBOX_LEN+1.
 */
int
mboxname_tointernal(name, userid, result)
char *name;
char *userid;
char *result;
{
    if ((name[0] == 'i' || name[0] == 'I') &&
	!strncasecmp(name, "inbox", 5) &&
	(name[5] == '\0' || name[5] == '.')) {

	if (!userid || strchr(userid, '.')) {
	    return IMAP_MAILBOX_BADNAME;
	}

	if (strlen(name)+strlen(userid) > MAX_MAILBOX_NAME) {
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
int
mboxname_userownsmailbox(userid, name)
char *userid;
char *name;
{
    if (!strchr(userid, '.') && !strncmp(name, "user.", 5) &&
	!strncmp(name+5, userid, strlen(userid)) &&
	name[5+strlen(userid)] == '.') {
	return 1;
    }
    return 0;
}

/*
 * Apply site policy restrictions on mailbox names.
 * Restrictions are hardwired for now.
 */
#define GOODCHARS "+,-.0123456789:=@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
int
mboxname_policycheck(name)
char *name;
{
    int i;
    struct glob *g;

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
	if (!strchr(GOODCHARS, *name++)) return IMAP_MAILBOX_BADNAME;
    }
    return 0;
}

