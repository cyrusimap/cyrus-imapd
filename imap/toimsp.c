/* drop.c -- Drop off information to be sent to IMSP server
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
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
#include <ctype.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <com_err.h>

#include "config.h"
#include "mailbox.h"
#include "imap_err.h"
#include "xmalloc.h"

#define FNAME_DROPDIR "/dropoff/"

static int dodropoff = -1;

/*
 * Drop off a request to send an IMSP LAST command stating the highest
 * uid for mailbox 'name' is 'uid'
 */
int
drop_last(name, uid)
char *name;
unsigned long uid;
{
    char fnamebuf[MAX_MAILBOX_PATH];
    FILE *f;

    if (dodropoff == -1) {
	if (config_getstring("imspservers", 0)) {
	    dodropoff = 1;
	}
	else dodropoff = 0;
    }

    if (!dodropoff) return 0;

    sprintf(fnamebuf, "%s%slast.%lu.%s", config_dir, FNAME_DROPDIR,
	    uid, name);
    f = fopen(fnamebuf, "w");
    if (!f) {
	syslog(LOG_ERR, "IOERROR: creating dropoff file %s: %m",
	       fnamebuf);
	return IMAP_IOERROR;
    }
    fclose(f);
    return 0;
}
      
/*
 * Drop off a request to send an IMSP SEEN command stating that
 * mailbox 'name' has been seen by 'user' up to and including the
 * message 'uid'.
 */
int
drop_seen(name, userid, uid)
char *name;
char *userid;
unsigned long uid;
{
    char fnamebuf[MAX_MAILBOX_PATH];
    FILE *f;

    if (strchr(userid, '.')) return 0;

    if (dodropoff == -1) {
	if (config_getstring("imspservers", 0)) {
	    dodropoff = 1;
	}
	else dodropoff = 0;
    }

    if (!dodropoff) return 0;

    sprintf(fnamebuf, "%s%sseen.%lu.%s.%s", config_dir, FNAME_DROPDIR,
	    uid, userid, name);
    f = fopen(fnamebuf, "w");
    if (!f) {
	syslog(LOG_ERR, "IOERROR: creating dropoff file %s: %m",
	       fnamebuf);
	return IMAP_IOERROR;
    }
    fclose(f);
    return 0;
}
      
