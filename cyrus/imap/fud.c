/* fud.c -- long-lived finger information provider
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

/* $Id: fud.c,v 1.22.6.1 2002/12/03 19:26:08 rjs3 Exp $ */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <com_err.h>
#include <pwd.h>

#include "assert.h"
#include "mboxlist.h"
#include "imapconf.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "acl.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"

#define REQ_OK		0
#define REQ_DENY	1
#define REQ_UNK		2

extern int errno;
extern int optind;
extern char *optarg;

/* forward decls */
int handle_request(const char *who, const char *name, 
		   struct sockaddr_in sfrom);

void send_reply(struct sockaddr_in sfrom, int status,
		const char *user, const char *mbox, 
		int numrecent, time_t lastread, time_t lastarrived);

int soc;

char who[16];

int init_network(int port)
{
    soc = 0;	/* inetd has handed us the port as stdin */
    return(0);
}

#define MAXLOGNAME 16		/* should find out for real */

int begin_handling(void)
{
        struct sockaddr_in  sfrom;
        socklen_t sfromsiz = sizeof(sfrom);
        int r;
        char    buf[MAXLOGNAME + MAX_MAILBOX_NAME + 1];
        char    username[MAXLOGNAME];
        char    mbox[MAX_MAILBOX_NAME+1];
        char    *q;
        int     off;
        
        while(1) {
            /* For safety */
            memset(username,'\0',MAXLOGNAME);	
            memset(mbox,'\0',MAX_MAILBOX_NAME+1);
            memset(buf, '\0', MAXLOGNAME + MAX_MAILBOX_NAME + 1);

	    signals_poll();
            r = recvfrom(soc, buf, 511, 0, 
			 (struct sockaddr *) &sfrom, &sfromsiz);
            if (r == -1) {
		return(errno);
	    }
            for(off = 0; buf[off] != '|' && off < MAXLOGNAME; off++);
            if(off < MAXLOGNAME) {
		strncpy(username,buf,off);
            } else {
		continue;
            }
            q = buf + off + 1;
            strlcpy(mbox, q, sizeof(mbox));

            handle_request(username,mbox,sfrom);
        }
}

void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    seen_done();
    mboxlist_close();
    mboxlist_done();
    exit(code);
}


int main(int argc, char **argv)
{
    int port = 0;
    int r;
    int opt;
    char *alt_config = NULL;
   
    r = 0; /* to shut up lint/gcc */

    if(geteuid() == 0)
        fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "C:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;
	default:
	    break;
	}
    }

    config_init(alt_config, "fud");

    signals_set_shutdown(&shut_down);
    signals_add_handlers();

    mboxlist_init(0);
    mboxlist_open(NULL);
    mailbox_initialize();

    r = init_network(port);
    if (r) {
        fatal("unable to configure network port", EC_OSERR);
    }
    
    begin_handling();

    shut_down(0);
}

int handle_request(const char *who, const char *name,
		   struct sockaddr_in sfrom)
{
    int r;
    struct mailbox mailbox;
    struct seen *seendb;
    time_t lastread;
    time_t lastarrived;
    unsigned recentuid;
    char *seenuids;
    unsigned numrecent;
    char mboxname[MAX_MAILBOX_NAME+1];

    numrecent = 0;
    lastread = 0;
    lastarrived = 0;

    r = mboxname_tointernal(name,who,mboxname);
    if (r) return r; 

    /*
     * Open/lock header 
     */
    r = mailbox_open_header(mboxname, NULL, &mailbox);
    if (r) {
        send_reply(sfrom, REQ_UNK, who, name, 0, 0, 0);
	return r; 
    }

    r = mailbox_open_index(&mailbox);
    if (r) {
	mailbox_close(&mailbox);
        send_reply(sfrom, REQ_UNK, who, name, 0, 0, 0);
	return r;
    }

    if(!(strncmp(mboxname,"user.",5)) && !(mailbox.myrights & ACL_USER0)) {
	mailbox_close(&mailbox);
        send_reply(sfrom, REQ_DENY, who, name, 0, 0, 0);
	return 0;
    }
   
    r = seen_open(&mailbox, who, &seendb);
    if (r) {
	mailbox_close(&mailbox);
        send_reply(sfrom, REQ_UNK, who, name, 0, 0, 0);
	return r;
    }

    seenuids = NULL;
    r = seen_read(seendb, &lastread, &recentuid, &lastarrived, &seenuids);
    if (seenuids) free(seenuids);
    seen_close(seendb);
    if (r) {
	mailbox_close(&mailbox);
        send_reply(sfrom, REQ_UNK, who, name, 0, 0, 0);
	return r;
    }
    
    lastarrived = mailbox.last_appenddate;
    {
	const char *base;
	unsigned long len = 0;
	int msg;
	unsigned uid;
	
	map_refresh(mailbox.index_fd, 0, &base, &len,
		    mailbox.start_offset +
		    mailbox.exists * mailbox.record_size,
		    "index", mailbox.name);
	for (msg = 0; msg < mailbox.exists; msg++) {
	    uid = ntohl(*((bit32 *)(base + mailbox.start_offset +
				    msg * mailbox.record_size +
				    OFFSET_UID)));
	    if (uid > recentuid) numrecent++;
	}
	map_free(&base, &len);
    }

    mailbox_close(&mailbox);
    
    send_reply(sfrom, REQ_OK, who, name, numrecent, lastread, lastarrived);
    
    return(0);
}

void
send_reply(struct sockaddr_in sfrom, int status, 
	   const char *user, const char *mbox,
	   int numrecent, time_t lastread, time_t lastarrived)
{
    char buf[MAX_MAILBOX_PATH + 16 + 9];
    int siz;

    switch(status) {
        case REQ_DENY:
            sendto(soc,"PERMDENY",9,0,(struct sockaddr *) &sfrom, sizeof(sfrom));       
            break;
        case REQ_OK:
            siz = sprintf(buf,"%s|%s|%d|%d|%d",user,mbox,numrecent,(int) lastread,(int) lastarrived);
            sendto(soc,buf,siz,0,(struct sockaddr *) &sfrom, sizeof(sfrom));       
            break;
        case REQ_UNK:
            sendto(soc,"UNKNOWN",8,0,(struct sockaddr *) &sfrom, sizeof(sfrom));       
            break;
    } 
}

void fatal(const char* s, int code)
{
    fprintf(stderr, "fud: %s\n", s);
    exit(code);
}
