/* notify_zephyr.c -- Module to notify of new mail via zephyr
 $Id: notify_zephyr.c,v 1.24 2001/01/01 21:21:17 leg Exp $ 

 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#ifdef HAVE_LIBKRB
#include <netinet/in.h>
#include <krb.h>
#endif
#include <zephyr/zephyr.h>
#include <syslog.h>

#include "exitcodes.h"
#include "xmalloc.h"

#ifndef MAIL_CLASS
#define MAIL_CLASS "MAIL"
#endif

#include "notify.h"

extern int errno;

/* This code is mostly stolen from zpopnotify, from the Zephyr dist. */

int notify_wantheader()
{
    return 1;
}

void notify(const char *class,
	    const char *instance,
	    const char *user,
	    const char *mailbox,
	    const char *message)
{
    ZNotice_t notice;
    int retval;
    char myhost[256],mysender[BUFSIZ];
    char *msgbody;
    char *lines[2];
    char *mykrbhost = 0;

    if (!instance) instance = "INBOX";
  
    if ((retval = ZInitialize()) != ZERR_NONE) {
	syslog(LOG_ERR, "IOERROR: cannot initialize zephyr: %m");
	return;
    }
  
    if (gethostname(myhost,sizeof(myhost)) == -1) {
	syslog(LOG_ERR, "IOERROR: cannot get hostname: %m");
	return;
    }
    myhost[sizeof(myhost)-1] = '\0';
  
#ifdef HAVE_LIBKRB
    mykrbhost = krb_get_phost(myhost);
#endif
  
    lines[0] = myhost;
    msgbody = xmalloc(1000 + strlen(message));
    lines[1] = msgbody;

    strcpy(msgbody,"");

    if (mailbox) {
	snprintf(msgbody,900, "You have new mail in %s.\n\n", mailbox);
    }

    if (message) {
	strcat(msgbody, message);
	strcat(msgbody, "\n");
    }

    (void) sprintf(mysender, "imap%s%s@%s",
		   mykrbhost ? "." : "",
		   mykrbhost ? mykrbhost : "",
		   ZGetRealm());

    memset((char *)&notice, 0, sizeof(notice));
    notice.z_kind = UNSAFE;
    notice.z_class = class ? class : MAIL_CLASS;
    notice.z_class_inst = (char *) instance;

    notice.z_opcode = "";
    notice.z_sender = mysender;
    notice.z_default_format = "From Post Office $1:\n$2";
  
    notice.z_recipient = (char *) user;

    retval = ZSendList(&notice,lines,2,ZNOAUTH);
    free(msgbody);
    
    if (retval != ZERR_NONE) {
	syslog(LOG_ERR, "IOERROR: cannot send zephyr notice: %m");
	return;
    } 
}
