/* drop.c -- Drop off information to be sent to IMSP server
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
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
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <com_err.h>

#include "config.h"
#include "mailbox.h"
#include "sysexits.h"
#include "util.h"
#include "imap_err.h"
#include "xmalloc.h"

extern int errno;

#define FNAME_DROPDIR "/dropoff/"

static int dodropoff = -1;

static drop_to64();

/*
 * Drop off a request to send an IMSP LAST command stating the highest
 * uid for mailbox 'name' is 'uid' and has 'exists' messages.
 */
int
drop_last(name, uid, exists)
char *name;
unsigned long uid;
unsigned long exists;
{
    int last_change = time(0);
    bit32 intbuf[3];
    char fnamebuf[MAX_MAILBOX_PATH];
    char *p;
    FILE *f;

    if (dodropoff == -1) {
	if (config_getstring("imspservers", 0)) {
	    dodropoff = 1;
	}
	else dodropoff = 0;
    }

    if (!dodropoff) return 0;

    intbuf[0] = htonl(uid);
    intbuf[1] = htonl(last_change);
    intbuf[2] = htonl(exists);
    
    sprintf(fnamebuf, "%s%sL", config_dir, FNAME_DROPDIR);
    drop_to64(fnamebuf+strlen(fnamebuf), (unsigned char *)intbuf,
	      sizeof(intbuf));

    p = fnamebuf + strlen(fnamebuf);

    if ((p - fnamebuf) + strlen(name) >= sizeof(fnamebuf)) return 0;
    strcpy(p, name);
    lcase(p);

    while (p = strchr(p, '=')) *p = 'B';

    f = fopen(fnamebuf, "w");
    if (!f) {
	if (errno == ENOENT) return 0;
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
drop_seen(name, userid, uid, last_change)
char *name;
char *userid;
unsigned long uid;
time_t last_change;
{
    bit32 intbuf[2];
    char fnamebuf[MAX_MAILBOX_PATH];
    char *p;
    FILE *f;

    if (dodropoff == -1) {
	if (config_getstring("imspservers", 0)) {
	    dodropoff = 1;
	}
	else dodropoff = 0;
    }

    if (!dodropoff) return 0;

    intbuf[0] = htonl(uid);
    intbuf[1] = htonl(last_change);
    
    sprintf(fnamebuf, "%s%sS", config_dir, FNAME_DROPDIR);
    drop_to64(fnamebuf+strlen(fnamebuf), (unsigned char *)intbuf,
	      sizeof(intbuf));

    p = fnamebuf + strlen(fnamebuf);

    if ((p - fnamebuf) + strlen(name) >= sizeof(fnamebuf)) return 0;
    strcpy(p, name);
    lcase(p);
    while (*p) {
	if (*p == '=') *p = 'B';
	p++;
    }

    if ((p - fnamebuf) + strlen(userid) + 1 >= sizeof(fnamebuf)) return 0;
    *p++ = '=';
    strcpy(p, userid);
    lcase(p);
    while (*p) {
	if (*p == '/') *p = 'A';
	if (*p == '=') *p = 'B';
	p++;
    }

    f = fopen(fnamebuf, "w");
    if (!f) {
	if (errno == ENOENT) return 0;
	syslog(LOG_ERR, "IOERROR: creating dropoff file %s: %m",
	       fnamebuf);
	return IMAP_IOERROR;
    }
    fclose(f);
    return 0;
}
      
static char drop_basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+:";

static drop_to64(to, from, len)
char *to;
unsigned char *from;
int len;
{
    int c1, c2, c3;

    while (len) {
	c1 = *from++;
	len--;
	*to++ = drop_basis_64[c1>>2];
	if (len == 0) c2 = 0;
	else c2 = *from++;
	*to++ = drop_basis_64[((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)];
	if (len == 0) {
	    break;
	}

	if (--len == 0) c3 = 0;
	else c3 = *from++;
        *to++ = drop_basis_64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)];
	if (len == 0) {
	    break;
	}
	
	--len;
        *to++ = drop_basis_64[c3 & 0x3F];
    }
    *to++ = '=';
    *to = '\0';
}
