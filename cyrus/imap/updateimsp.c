/* updateimsp.c -- program to send mailbox updates to IMSP.
 $Id: updateimsp.c,v 1.14 1998/05/15 21:50:08 neplokh Exp $
 
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
#include <ctype.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <com_err.h>

#include "sasl.h"
#include "imclient.h"
#include "sysexits.h"
#include "xmalloc.h"
#include "map.h"
#include "lock.h"
#include "retry.h"
#include "imap_err.h"
#include "config.h"
#include "mailbox.h"

#ifdef HAVE_SASL_KRB
extern struct sasl_client krb_sasl_client;
#endif

struct sasl_client *login_sasl_client[] = {
#ifdef HAVE_SASL_KRB
    &krb_sasl_client,
#endif
    NULL
};

FILE *failedfp;
int commands_pending;

struct imclient *connecttoimsp();


main()
{
    const char *val;

    config_init("updateimsp");

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);

    if (chdir(config_dir)) {
	syslog(LOG_ERR, "IOERROR: changing directory to config directory: %m");
	fatal("cannot change directory to config directory", EX_TEMPFAIL);
    }
    
#ifdef HAVE_SASL_KRB
    if (val = config_getstring("srvtab", 0)) {
	kerberos_set_srvtab(val);
    }
#endif

    for (;;) {
	doupdate();
	sleep(15*60);
    }
}

doupdate()
{
    const char *imsphost;
    char hostbuf[256];
    char *p;
    struct imclient *imspconn;
    int workfd, retryfd, newfd;
    const char *work_base, *retry_base;
    unsigned long work_size = 0, retry_size = 0;
    struct stat work_sbuf, retry_sbuf;
    const char *failaction;

    imsphost = config_getstring("imspservers", 0);
    if (!imsphost) {
	syslog(LOG_ERR, "Missing required imsphost configuration option");
	fatal("Missing required imsphost configuration option", EX_CONFIG);
    }
    while (isspace(*imsphost)) imsphost++;
    strncpy(hostbuf, imsphost, sizeof(hostbuf)-1);
    hostbuf[sizeof(hostbuf)-1] = '\0';
    p = hostbuf;
    while (*p && !isspace(*p)) p++;
    *p = '\0';

    imspconn = connecttoimsp(hostbuf);
	
    failedfp = fopen("toimsp.failed", "w");
    if (!failedfp) {
	syslog(LOG_ERR, "Can't create toimsp.failed: %m");
	return;
    }

    (void) link("toimsp", "toimsp.work");
    
    workfd = open("toimsp.work", O_RDWR, 0666);
    if (workfd == -1) {
	syslog(LOG_ERR, "IOERROR: opening toimsp.work: %m", failaction);
	return;
    }	
    if (lock_reopen(workfd, "toimsp.work", &work_sbuf, &failaction)) {
	syslog(LOG_ERR, "IOERROR: %s toimsp.work: %m", failaction);
	close(workfd);
	return;
    }

    newfd = open("toimsp.new", O_RDWR|O_CREAT|O_TRUNC, 0666);
    if (newfd == -1) {
	syslog(LOG_ERR, "IOERROR: creating toimsp.new: %m");
	close(workfd);
	return;
    }
    close(newfd);

    if (rename("toimsp.new", "toimsp") == -1) {
	syslog(LOG_ERR, "IOERROR: renaming toimsp.new: %m");
	close(workfd);
	return;
    }

    lock_unlock(newfd);

    retryfd = open("toimsp.retry", O_RDWR, 0666);
    if (retryfd != -1) {
	if (fstat(retryfd, &retry_sbuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: fstat on toimsp.retry: %m");
	    close(workfd);
	    close(retryfd);
	    return;
	}
	map_refresh(retryfd, 1, &retry_base, &retry_size,
		    retry_sbuf.st_size, "toimsp.retry", 0);
	processfile(imspconn, retry_base, retry_size);
    }

    map_refresh(workfd, 1, &work_base, &work_size, work_sbuf.st_size,
		"toimsp.work", 0);
    processfile(imspconn, work_base, work_size);

    while (commands_pending) {
	imclient_processoneevent(imspconn);
    }
    imclient_close(imspconn);

    map_free(&work_base, &work_size);
    close(workfd);
    if (retryfd != -1) {
	map_free(&retry_base, &retry_size);
	close(retryfd);
    }

    fclose(failedfp);
    if (rename("toimsp.failed", "toimsp.retry") != -1) {
	(void) unlink("toimsp.work");
    }
}

struct imclient *
connecttoimsp(hostname)
char *hostname;
{
    static time_t cred_expire, curtime, life;
    int i, gotcred = 0;
    struct imclient *imspconn;
    int r;
    const char *err;

    curtime = time(0);
    if (cred_expire < curtime+5*60) {
	for (i = 0; login_sasl_client[i]; i++) {
/* XXX look for authmech (or similar) config option */
	    err = login_sasl_client[i]->new_cred("imap", &life);
	    if (!err) {
		if (!gotcred++ || curtime + life < cred_expire) {
		    cred_expire = curtime + life;
		}
	    }
	    else {
		syslog(LOG_WARNING, "Error getting %s credential: %s",
		       login_sasl_client[i]->auth_type, err);
/*debug*/printf("cannot get %s credential: %s", 
		login_sasl_client[i]->auth_type, err);
	    }
	}
    }

    r = imclient_connect(&imspconn, hostname, "406");
    if (r) {
	if (r == -1) {	
	    err = "unknown host";
	}
	else if (r == -2) {
	    err = "unknown service";
	}
	else {
	    err = error_message(r);
	}
	
	syslog(LOG_WARNING, "Error connecting to IMSP server: %s", err);
/*debug*/ printf("cannot connect to IMSP: %s\n", err);
	return 0;
    }

    r = imclient_authenticate(imspconn, login_sasl_client, "imap", (char *)0,
			      SASL_PROT_ANY);
    if (r) {
	syslog(LOG_WARNING, "Error authenticating to IMSP server");
/*debug*/printf("cannot authenticate to imsp\n");
	imclient_close(imspconn);
	return 0;
    }

    commands_pending = 0;

    return imspconn;
}

void
callback_retryonfail(imspconn, rock, reply)
struct imclient *imspconn;
void *rock;
struct imclient_reply *reply;
{
    char *cmd = (char *)rock;
    char *cmdend;

    commands_pending--;
/*debug*/ printf("%u %s %s %s\n", commands_pending, reply->keyword, reply->text, cmd + 1);

    if (strcmp(reply->keyword, "OK") != 0) {
	cmdend = memchr(cmd+1, '\n', 1024*1024);
	fwrite(cmd, cmdend - cmd + 1, 1, failedfp);
    }
}

#define MAXARGS 20

processfile(imspconn, base, size)
struct imclient *imspconn;
char *base;
int size;
{
    char *endline;
    char *p, *endp;
    char *mailbox, *uidvalidity;
    char *arg[MAXARGS];
    int nargs;

    while (p = memchr(base, '\n', size)) {
	size -= p - base;
	while (size && p[1] == '\n') {
	    p++;
	    size--;
	}
	base = p+1;
	size--;

	endline = memchr(base, '\n', size);
	if (!endline) break;
	if (endline - base < size && endline[1] != '\n') continue;

	nargs = 0;
	p = base;
	while (p < endline) {
	    arg[nargs++] = p;
	    if (nargs == MAXARGS) continue;
	    endp = memchr(p, '\0', endline - p);
	    if (!endp) continue;
	    p = endp + 1;
	}

	arg[nargs] = 0;

	imclient_send(imspconn, callback_retryonfail, (void *)(base-1),
			  "X-CYRUS-MBINFO %v", arg);
	commands_pending++;
    }
}

fatal(msg, code)
char *msg;
int code;
{
    fprintf(stderr, "updateimsp: %s\n", msg);
    exit(code);
}
