/* notify_zephyr.c -- Module to notify of new mail via zephyr
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
#include <netdb.h>
#ifdef HAVE_SASL_KRB
#include <krb.h>
#endif
#include <zephyr/zephyr.h>
#include <syslog.h>

#include "sysexits.h"
#include "xmalloc.h"

#ifndef MAIL_CLASS
#define MAIL_CLASS "MAIL"
#endif

extern int errno;

/* This code is mostly stolen from zpopnotify, from the Zephyr dist. */

notify_wantheader()
{
    return 1;
}

notify(user, mailbox, header)
char *user;
char *mailbox;
char *header;
{
    ZNotice_t notice;
    struct hostent *hent;
    int retval;
    register int i;
    char *whoami,myhost[256],mysender[BUFSIZ];
    char *msgbody;
    char *lines[2];
    char *mykrbhost = 0;
  
    if ((retval = ZInitialize()) != ZERR_NONE) {
	syslog(LOG_ERR, "IOERROR: cannot initialize zephyr: %m");
	return;
    }
  
    if (gethostname(myhost,sizeof(myhost)) == -1) {
	syslog(LOG_ERR, "IOERROR: cannot get hostname: %m");
	return;
    }
    myhost[sizeof(myhost)-1] = '\0';
  
#ifdef HAVE_SASL_KRB
    mykrbhost = krb_get_phost(myhost);
#endif
  
    lines[0] = myhost;
    msgbody = xmalloc(1000 + strlen(header));
    lines[1] = msgbody;
    
    if (!strcmp(mailbox, "INBOX")) {
	strcpy(msgbody, "You have new mail.\n\n");
    }
    else {
	sprintf(msgbody, "You have new mail in %s.\n\n", mailbox);
    }
    strcat(msgbody, header);

    (void) sprintf(mysender, "imap%s%s@%s",
		   mykrbhost ? "." : "",
		   mykrbhost ? mykrbhost : "",
		   ZGetRealm());

    memset((char *)&notice, 0, sizeof(notice));
    notice.z_kind = UNSAFE;
    notice.z_class = MAIL_CLASS;
    notice.z_class_inst = mailbox;

    notice.z_opcode = "";
    notice.z_sender = mysender;
    notice.z_default_format = "From Post Office $1:\n$2";
  
    notice.z_recipient = user;

    retval = ZSendList(&notice,lines,2,ZNOAUTH);
    free(msgbody);
    
    if (retval != ZERR_NONE) {
	syslog(LOG_ERR, "IOERROR: cannot send zephyr notice: %m");
	return;
    } 
}
