/* fud.c -- long-lived finger information provider
 *
 * Copyright 1998 Carnegie Mellon University
 * 
 * No warranties, either expressed or implied, are made regarding the
 * operation, use, or results of the software.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted for non-commercial purposes only
 * provided that this copyright notice appears in all copies and in
 * supporting documentation.
 *
 * Permission is also granted to Internet Service Providers and others
 * entities to use the software for internal purposes.
 *
 * The distribution, modification or sale of a product which uses or is
 * based on the software, in whole or in part, for commercial purposes
 * or
 * benefits requires specific, additional permission from:
 *
 *  Office of Technology Transfer
 *  Carnegie Mellon University
 *  5000 Forbes Avenue
 *  Pittsburgh, PA  15213-3890
 *  (412) 268-4387, fax: (412) 268-7395
 *  tech-transfer@andrew.cmu.edu
 *
 */

/* $Id: fud.c,v 1.2 1998/06/23 23:07:06 dar Exp $ */

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
#include "config.h"
#include "sysexits.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "acl.h"

extern int errno;
extern int optind;
extern char *optarg;

void send_reply(struct sockaddr_in sfrom, int status, char *user, char *mbox, int numrecent, time_t lastread, time_t lastarrived);

int code = 0;
int soc;

char who[16];

int
main(argc, argv)
int argc; 
char **argv;
{
    struct passwd *pw;
    int cyrus_uid, cyrus_gid;
    int port, r;
   

    r = 0; /* to shut up lint/gcc */

    config_init("fud");
    port = config_getint("fud-port", 4201);

    if (port < IPPORT_RESERVED) {
	if(geteuid() != 0)
            fatal("must run as root when fud-port is restricted", EX_USAGE);
        pw = getpwnam(CYRUS_USER);    
        if(!pw) 
            fatal("unable to determine the cyrus user's uid", EX_USAGE);
        cyrus_uid = pw->pw_uid;
        cyrus_gid = pw->pw_gid;
        endpwent(); /* just in case */

        r = init_network(port);
        
        syslog(LOG_ERR,"RENOUNCE: renouncing root privledges in favor of %d,%d",cyrus_uid,cyrus_gid);
        if(setgid(cyrus_gid) || setuid(cyrus_uid))  {
            close(soc);
            fatal("unable to renounce root privledges", EX_OSERR);
        }
    } else {
        if (geteuid() == 0) 
            fatal("must run as the Cyrus user", EX_USAGE);
        r = init_network(port);
    }
    signal(SIGHUP,SIG_IGN);

    if (r)
        fatal("unable to configure network port", EX_OSERR);
    
    begin_handling();

    exit(code);
}


int
init_network(port)
int port;
{
    int r;
    struct sockaddr_in sin;

    soc = socket(PF_INET,SOCK_DGRAM,0);   
    if(soc == -1) {
        return(errno);
    }
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(port);
    
    r = bind(soc, (struct sockaddr *) &sin, sizeof(sin));
    if(soc) {
        return(errno);
    }
    return(0);
}

#define MAXLOGNAME 16		/* should find out for real */

int
begin_handling()
{
        struct sockaddr_in  sfrom;
        int sfromsiz = sizeof(sfrom);
        int r;
        char    buf[MAXLOGNAME + MAX_MAILBOX_NAME + 1];
        char    username[MAXLOGNAME];
        char    mbox[MAX_MAILBOX_NAME+1];
        char    *q;
        int     off;
        
        while(1) {
            r = recvfrom(soc, buf, 511, 0, (struct sockaddr *) &sfrom, &sfromsiz);
            if(r == -1)
                    return(errno);
            for(off = 0; buf[off] != '|' && off < MAXLOGNAME; off++);
            if(off < MAXLOGNAME) {
                    strncpy(username,buf,off);
            } else {
                    continue;
            }
            q = buf + off + 1;
            strncpy(mbox,q,(r - (off + 1)  < MAX_MAILBOX_NAME) ? r - (off + 1) : MAX_MAILBOX_NAME);

            handle_request(username,mbox,sfrom);
        }
}

int 
handle_request(who,name,sfrom)
char *who;
char *name;
struct sockaddr_in sfrom;
{
    int r;
    struct mailbox mailbox;
    struct seen *seendb;
    time_t lastread;
    time_t lastarrived;
    unsigned lastuid;
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
    r = mailbox_open_header(mboxname, 0, &mailbox);
    if (r) return r; 
    r = mailbox_open_index(&mailbox);

    if (r) {
	mailbox_close(&mailbox);
	return r;
    }

    if(!(strncmp(mboxname,"user.",5)) && !(mailbox.myrights & ACL_USER0)) {
        send_reply(sfrom, 0, who, name, 0, 0, 0);
    }
   

    r = seen_open(&mailbox, who, &seendb);
    if (r) return r;
    r = seen_lockread(seendb, &lastread, &lastuid, &lastarrived, &seenuids);
    seen_close(seendb);
    if (r) return r;
    
    lastarrived = mailbox.last_appenddate;
    {
        const char *base;
        unsigned long len = 0;
        int msg;
        unsigned uid;
         
        map_refresh(mailbox.index_fd, 0, &base, &len,
                    mailbox.start_offset + mailbox.exists * 
                    mailbox.record_size,  "index",
                    mailbox.name);

        for (msg = 0; msg < mailbox.exists; msg++) {
                uid = ntohl(*((bit32 *)(base + mailbox.start_offset +
                                        msg * mailbox.record_size +
                                        OFFSET_UID)));
                if (uid > lastuid) numrecent++;
	}
        map_free(&base,&len);
        free(seenuids);
    }

    mailbox_close(&mailbox);
    
    send_reply(sfrom, 1, who, name, numrecent, lastread, lastarrived);
    
    return(0);
}

void
send_reply(sfrom, status, user, mbox, numrecent, lastread, lastarrived)
struct sockaddr_in sfrom;
int status; 
char *user; 
char *mbox; 
int numrecent; 
time_t lastread; 
time_t lastarrived;
{
    char buf[MAX_MAILBOX_PATH + 16 + 9];
    int siz;

    if(!status) {
        sendto(soc,"PERMDENY",9,0,(struct sockaddr *) &sfrom, sizeof(sfrom));       
    }
    siz = sprintf(buf,"%s|%s|%d|%d|%d",user,mbox,numrecent,(int) lastread,(int) lastarrived);
    sendto(soc,buf,siz,0,(struct sockaddr *) &sfrom, sizeof(sfrom));       
}

int convert_code(r)
int r;
{
    switch (r) {
    case 0:
	return 0;

    case IMAP_IOERROR:
	return EX_IOERR;

    case IMAP_PERMISSION_DENIED:
	return EX_NOPERM;

    case IMAP_QUOTA_EXCEEDED:
	return EX_TEMPFAIL;

    case IMAP_MAILBOX_NOTSUPPORTED:
	return EX_DATAERR;

    case IMAP_MAILBOX_NONEXISTENT:
	return EX_UNAVAILABLE;
    }

    /*
     * Some error we're not expecting. 
     */
    return EX_SOFTWARE;
}

int
fatal(s, code)
char *s;
int code;
{
    fprintf(stderr, "fud: %s\n", s);
    exit(code);
}
