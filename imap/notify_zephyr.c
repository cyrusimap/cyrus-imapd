/* notify_zephyr.c -- Module to notify of new mail via zephyr
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
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
