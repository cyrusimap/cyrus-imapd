/* toimsp.c -- Drop off information to be sent to IMSP server
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
#include <sys/uio.h>
#include <netinet/in.h>
#include <com_err.h>

#include "config.h"
#include "mailbox.h"
#include "sysexits.h"
#include "util.h"
#include "imap_err.h"
#include "xmalloc.h"

#define FNAME_TOIMSPFILE "/toimsp"

static char toimsp_nul[] = {0, 0, 0, 0};

#define MKTAG(a,b,size) htonl((a)<<24|(b)<<16|(size))

/*
 * Drop off a request to send an IMSP LAST command stating the highest
 * uid for mailbox 'name' is 'uid' and has 'exists' messages.
 */
int
toimsp_mboxinfo(name, uidvalidity, uid_next, acl, acl_time, renameto)
char *name;
bit32 uidvalidity;
bit32 uid_next;
char *acl;
bit32 acl_time;
char *renameto;
{
    int fd;
    struct iovec iov[15];
    int num_iov = 0;
    bit32 untag, actag, rntag;
    
    fd = toimsp_open();
    if (fd == -1) return;

    /* Start with 4 nuls */
    iov[num_iov].iov_base = toimsp_nul;
    iov[num_iov++].iov_len = 4;

    iov[num_iov].iov_base = name;
    iov[num_iov].iov_len = strlen(name) + 1;
    /* Pad to 4-octet boundary */
    iov[num_iov+1].iov_base = toimsp_nul;
    iov[num_iov+1].iov_len = (-iov[num_iov].iov_len) & 3;
    num_iov += 2;

    uidvalidity = htonl(uidvalidity);
    iov[num_iov].iov_base = (char *)&uidvalidity;
    iov[num_iov++].iov_len = 4;

    if (uid_next) {
	untag = MKTAG('U', 'N', 4);
	iov[num_iov].iov_base = (char *)&untag;
	iov[num_iov++].iov_len = 4;

	uid_next = htonl(uid_next);
	iov[num_iov].iov_base = (char *)&uid_next;
	iov[num_iov++].iov_len = 4;
    }	

    if (acl) {
	iov[num_iov+1].iov_base = acl;
	iov[num_iov+1].iov_len = strlen(acl) + 1;
	/* Pad to 4-octet boundary */
	iov[num_iov+2].iov_base = toimsp_nul;
	iov[num_iov+2].iov_len = (-iov[num_iov+1].iov_len) & 3;
	acl_time = htonl(acl_time);
	iov[num_iov+3].iov_base = (char *)&acl_time;
	iov[num_iov+3].iov_len = 4;
	actag = MKTAG('A', 'C', iov[num_iov+1].iov_len +
		      iov[num_iov+2].iov_len + 4);
	iov[num_iov].iov_base = (char *)&actag;
	iov[num_iov].iov_len = 4;
	num_iov += 4;
    }

    if (renameto) {
	iov[num_iov+1].iov_base = renameto;
	iov[num_iov+1].iov_len = strlen(renameto) + 1;
	/* Pad to 4-octet boundary */
	iov[num_iov+2].iov_base = toimsp_nul;
	iov[num_iov+2].iov_len = (-iov[num_iov+1].iov_len) & 3;
	rntag = MKTAG('R', 'N', iov[num_iov+1].iov_len +
		      iov[num_iov+2].iov_len);
	iov[num_iov].iov_base = (char *)&rntag;
	iov[num_iov].iov_len = 4;
	num_iov += 3;
    }

    n = retry_writev(fd, iov, num_iov);
    fclose(fd);
    
    return 0;
}
      
/*
 * Drop off a request to send an IMSP SEEN command stating that
 * mailbox 'name' has been seen by 'user' up to and including the
 * message 'uid'.
 */
int
toimsp_seen(name, uidvalidity, userid, uid, last_change)
char *name;
bit32 uidvalidity;
char *userid;
bit32 uid;
bit32 last_change;
{
    int fd;
    struct iovec iov[15];
    int num_iov = 0;
    bit32 sntag;
    
    fd = toimsp_open();
    if (fd == -1) return;

    /* Start with 4 nuls */
    iov[num_iov].iov_base = toimsp_nul;
    iov[num_iov++].iov_len = 4;

    iov[num_iov].iov_base = name;
    iov[num_iov].iov_len = strlen(name) + 1;
    /* Pad to 4-octet boundary */
    iov[num_iov+1].iov_base = toimsp_nul;
    iov[num_iov+1].iov_len = (-iov[num_iov].iov_len) & 3;
    num_iov += 2;

    uidvalidity = htonl(uidvalidity);
    iov[num_iov].iov_base = (char *)&uidvalidity;
    iov[num_iov++].iov_len = 4;

    untag = MKTAG('S', 'N', 4);
    iov[num_iov].iov_base = (char *)&untag;
    iov[num_iov].iov_len = 4;

    iov[num_iov+1].iov_base = userid;
    iov[num_iov+1].iov_len = strlen(userid) + 1;
    /* Pad to 4-octet boundary */
    iov[num_iov+2].iov_base = toimsp_nul;
    iov[num_iov+2].iov_len = (-iov[num_iov+1].iov_len) & 3;
    last_change = htonl(last_change);
    iov[num_iov+3].iov_base = (char *)&last_change;
    iov[num_iov+3].iov_len = 4;
    sntag = MKTAG('S', 'N', iov[num_iov+1].iov_len +
		  iov[num_iov+2].iov_len+4);
    iov[num_iov].iov_base = (char *)&sntag;
    iov[num_iov].iov_len = 4;
    num_iov += 4;

    if (renameto) {
	iov[num_iov+1].iov_base = acl;
	iov[num_iov+1].iov_len = strlen(renameto) + 1;
	/* Pad to 4-octet boundary */
	iov[num_iov+2].iov_base = toimsp_nul;
	iov[num_iov+2].iov_len = (-iov[num_iov+1].iov_len) & 3;
	iov[num_iov].iov_base = MKTAG('R', 'N', iov[num_iov+1].iov_len+
				                iov[num_iov+2].iov_len);
	iov[num_iov].iov_len = 4;
    }

    /* Terminate with 4 nuls */
    iov[num_iov].iov_base = toimsp_nul;
    iov[num_iov++].iov_len = 4;

    n = retry_writev(fd, iov, num_iov);
    fclose(fd);
    
    return 0;
}
      
static int toimsp_open()
{
    int fd, r;
    char fnamebuf[MAX_MAILBOX_PATH];
    char *lockfailaction;

    sprintf(fnamebuf, "%s%s", config_dir, FNAME_TOIMSPFILE);
    fd = open(fnamebuf, O_WRONLY, 0666);

    if (fd == -1) return -1;

    r = lock_reopen(fd, fnamebuf, (struct stat *)0, &lockfailaction);
    if (r == -1) {
	syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, fnamebuf);
	return -1;
    }

    lseek(fd, 0L, SEEK_END);
    return fd;
}
	
    
