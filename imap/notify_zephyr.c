/* notify_zephyr.c -- Module to notify of new mail via zephyr
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
#include <netdb.h>
#include <krb.h>
#include <zephyr/zephyr.h>
#include <syslog.h>
#include "sysexits.h"

#ifndef MAIL_CLASS
#define MAIL_CLASS "MAIL"
#endif

extern int errno;

/* This code is mostly stolen from zpopnotify, from the Zephyr dist. */

notify(user, mailbox)
char *user;
char *mailbox;
{
    ZNotice_t notice;
    struct hostent *hent;
    int retval;
    register int i;
    char *whoami,myhost[256],mysender[BUFSIZ];
    char msgbody[1024];
    char *lines[2],*mykrbhost;
  
    if ((retval = ZInitialize()) != ZERR_NONE) {
	syslog(LOG_ERR, "IOERROR: cannot initialize zephyr: %m");
	return;
    }
  
    if (gethostname(myhost,sizeof(myhost)) == -1) {
	syslog(LOG_ERR, "IOERROR: cannot get hostname: %m");
	return;
    }
    myhost[sizeof(myhost)-1] = '\0';
  
    mykrbhost = krb_get_phost(myhost);
  
    lines[0] = myhost;
    if (mailbox[0]) {
	sprintf(msgbody,"user.%s.%s has new mail.", user, mailbox);
	lines[1] = msgbody;
    }
    else {
	lines[1] = "You have new mail.";
    }
  
    (void) sprintf(mysender,"imap.%s@%s", mykrbhost, ZGetRealm());

    memset((char *)&notice, 0, sizeof(notice));
    notice.z_kind = UNSAFE;
    notice.z_class = MAIL_CLASS;
    notice.z_class_inst = mailbox;

    notice.z_opcode = "";
    notice.z_sender = mysender;
    notice.z_default_format = "From Post Office $1:\n$2";
  
    notice.z_recipient = user;

    if ((retval = ZSendList(&notice,lines,2,ZNOAUTH)) != ZERR_NONE) {
	syslog(LOG_ERR, "IOERROR: cannot send zephyr notice: %m");
	return;
    } 
}
