/* notify_zephyr.c -- Module to notify of new mail via zephyr
 $Id: notify_zephyr.c,v 1.17 2000/01/28 22:09:49 leg Exp $
 
 # Copyright 1998 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
 *
 */

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

extern int errno;

/* This code is mostly stolen from zpopnotify, from the Zephyr dist. */

int notify_wantheader()
{
    return 1;
}

void notify(char *priority,
	    char *user,
	    char *message,
	    char **headers,
	    char *actions_taken)

{
    ZNotice_t notice;
    int retval;
    char myhost[256],mysender[BUFSIZ];
    char *msgbody;
    char *lines[2];
    char *mykrbhost = 0;
    int lup;
  
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
    
    if (message)
	sprintf(msgbody,"--> %s <--\n\n",message);

    if (headers)
    {
	for (lup=0; headers[lup]!=NULL;lup+=2)
	{
	    headers[lup][0] = toupper(headers[lup][0]);
	    strcat(msgbody,headers[lup]);
	    strcat(msgbody,": ");
	    strcat(msgbody,headers[lup+1]);
	    strcat(msgbody,"\n");
	}
    }

    if (actions_taken)
    {
	strcat(msgbody,"\nAction(s) taken for this message:\n");
	strcat(msgbody,actions_taken);
    }
    
    (void) sprintf(mysender, "imap%s%s@%s",
		   mykrbhost ? "." : "",
		   mykrbhost ? mykrbhost : "",
		   ZGetRealm());

    memset((char *)&notice, 0, sizeof(notice));
    notice.z_kind = UNSAFE;
    notice.z_class = MAIL_CLASS;
    notice.z_class_inst = priority;

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
