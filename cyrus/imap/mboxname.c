/* mboxname.c -- Mailbox list manipulation routines
 *
 *	(C) Copyright 1995 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <com_err.h>

#include "assert.h"
#include "config.h"
#include "mailbox.h"
#include "sysexits.h"
#include "imap_err.h"
#include "xmalloc.h"

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
    if (*name == '~') return IMAP_MAILBOX_BADNAME;
    while (*name) {
	if (!strchr(GOODCHARS, *name++)) return IMAP_MAILBOX_BADNAME;
    }
    return 0;
}

