/* updateimsp.c -- program to send mailbox updates to IMSP.
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
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
#include <ctype.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <com_err.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
/* unistd.h defines _POSIX_VERSION on POSIX.1 systems. */
#if defined(DIRENT) || defined(_POSIX_VERSION)
#include <dirent.h>
#else /* not (DIRENT or _POSIX_VERSION) */
#define dirent direct
#ifdef SYSNDIR
#include <sys/ndir.h>
#endif /* SYSNDIR */
#ifdef SYSDIR
#include <sys/dir.h>
#endif /* SYSDIR */
#ifdef NDIR
#include <ndir.n>
#endif /* NDIR */
#endif /* not (DIRENT or _POSIX_VERSION) */

#include "acte.h"
#include "imclient.h"
#include "sysexits.h"
#include "xmalloc.h"
#include "imap_err.h"
#include "config.h"
#include "mailbox.h"

#ifdef HAVE_ACTE_KRB
extern struct acte_client krb_acte_client;
#endif

struct acte_client *login_acte_client[] = {
#ifdef HAVE_ACTE_KRB
    &krb_acte_client,
#endif
    NULL
};

#define FNAME_DROPDIR "/dropoff/"

struct dropfile {
    struct dropfile *next;
    unsigned int uid;
    time_t last_change;
    unsigned int exists;
    char fname[1];
};

struct dropfile *getdroplist();

main()
{
    char fnamebuf[MAX_MAILBOX_PATH];
    char *val;

    config_init("updateimsp");

    strcpy(fnamebuf, config_dir);
    strcat(fnamebuf, FNAME_DROPDIR);
    
    if (chdir(fnamebuf)) {
	syslog(LOG_ERR, "IOERROR: changing directory to dropoff directory: %m");
	fatal("cannot change directory to dropoff directory", EX_TEMPFAIL);
    }
    
#ifdef HAVE_ACTE_KRB
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
    struct dropfile *droplist;
    char *imsphost;
    char hostbuf[256];
    char *p;

    imsphost = config_getstring("imspservers", 0);
    if (!imsphost) {
	syslog(LOG_ERR, "Missing required imsphost configuration option");
	fatal("Missing required imsphost configuration option", EX_CONFIG);
    }
	
    droplist = getdroplist();
    if (!droplist) return;

    sortdroplist(&droplist);
    if (!droplist) return;

    while (isspace(*imsphost)) imsphost++;
    strncpy(hostbuf, imsphost, sizeof(hostbuf)-1);
    hostbuf[sizeof(hostbuf)-1] = '\0';
    p = hostbuf;
    while (*p && !isspace(*p)) p++;
    *p = '\0';

    sendtoimsp(droplist, hostbuf);
}

struct dropfile *
getdroplist()
{
    struct dropfile *droplist = 0, *newfile;
    DIR *dirp;
    struct dirent *f;

    dirp = opendir(".");
    if (!dirp) {
	syslog(LOG_ERR, "IOERROR: reading dropoff directory: %m");
	return 0;
    }

    while (f = readdir(dirp)) {
	if (f->d_name[0] == '.') continue;
	newfile = (struct dropfile *)
	    xmalloc(sizeof(struct dropfile) + strlen(f->d_name));
	strcpy (newfile->fname, f->d_name);
	if (!parsefname(newfile)) {
/*debug*/ printf("unparsable filename %s\n", newfile->fname);
	    unlink(newfile->fname);
	    free((char *)newfile);
	    continue;
	}
	newfile->next = droplist;
	droplist = newfile;
    }
	
    closedir(dirp);
    return droplist;
}

#define XX 127
/*
 * Table for decoding base64, with ':' replacing '/'
 */
static const char drop_index_64[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, XX,XX,XX,XX,
    52,53,54,55, 56,57,58,59, 60,61,63,XX, XX,XX,XX,XX,
    XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
    XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};
#define CHAR64(c)  (drop_index_64[(unsigned char)(c)])

int
parsefname(newfile)
struct dropfile *newfile;
{
    unsigned char decodebuf[3*4];
    int c1, c2, c3, c4;
    char *from;
    unsigned char *to;
    int len;
    char *p;

    if (newfile->fname[0] != 'S' && newfile->fname[0] != 'L') return 0;

    from = newfile->fname + 1;
    to = decodebuf;
    len = 0;
    for (;;) {
	c1 = *from++;
	if (c1 == '=') break;
	if (CHAR64(c1) == XX) return 0;
	
	c2 = *from++;
	if (CHAR64(c2) == XX) return 0;

	c3 = *from++;
	if (c3 != '=' && CHAR64(c3) == XX) return 0;

	c4 = *from++;
	if (c4 != '=' && CHAR64(c4) == XX) return 0;

	if (len >= sizeof(decodebuf)) return 0;
	to[len++] = ((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
	if (c3 == '=') {
	    break;
	}
	if (len >= sizeof(decodebuf)) return 0;
	to[len++] = (((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
	if (c4 == '=') {
	    break;
	}
	if (len >= sizeof(decodebuf)) return 0;
	to[len++] = (((CHAR64(c3)&0x3)<<6) | CHAR64(c4));
    }

    if (len < 8) return 0;

    newfile->uid = ntohl(*(bit32 *)decodebuf);
    newfile->last_change = ntohl(*(bit32 *)(decodebuf+4));

    if (newfile->fname[0] == 'S') {
	if (len != 2*4) return 0;
	from = strchr(from, '=');
	if (!from) return 0;
	from++;
    }
    else {
	if (len != 3*4) return 0;
	newfile->exists = ntohl(*(bit32 *)(decodebuf+8));
    }

    if (strchr(from, '=')) return 0;

    return 1;
}

sortdroplist(listp)
struct dropfile **listp;
{
    struct dropfile *mid, *tail;
    struct dropfile *suba, *subb;
    struct dropfile **next;
    int cmp;

    /* Split into two sublists */
    mid = tail = *listp;
    if (!tail) return;
    tail = tail->next;
    if (!tail) return;
    while (tail) {
	tail = tail->next;
	if (tail) {
	    mid = mid->next;
	    tail = tail->next;
	}
    }
    tail = mid;
    mid = mid->next;
    tail->next = 0;
    
    /* Recursively sort the sublists */
    sortdroplist(listp);
    sortdroplist(&mid);

    /* Merge the two sublists */
    next = listp;
    suba = *listp;
    subb = mid;
    for (;;) {
	if (!suba) {
	    *next = subb;
	    return;
	}
	if (!subb) {
	    *next = suba;
	    return;
	}
	cmp = (subb->fname[0] - suba->fname[0]);
	if (!cmp) {
	    cmp = strcmp(strchr(suba->fname, '='),
			 strchr(subb->fname, '='));
	}
	if (!cmp) {
	    if (suba->last_change < subb->last_change ||
		(suba->last_change == subb->last_change &&
		 suba->uid < subb->uid)) {
		tail = suba;
		suba = suba->next;
	    }
	    else {
		tail = subb;
		subb = subb->next;
	    }
/*debug*/ printf("older file %s\n", tail->fname);
	    unlink(tail->fname);
	    free((char *)tail);
	    continue;
	}

	if (cmp < 0) {
	    *next = suba;
	    next = &suba->next;
	    suba = *next;
	}
	else {
	    *next = subb;
	    next = &subb->next;
	    subb = *next;
	}
    }
}

int commands_pending;

void
callback_dropfile(imspconn, rock, reply)
struct imclient *imspconn;
void *rock;
struct imclient_reply *reply;
{
    struct dropfile *dropfile = (struct dropfile *)rock;

    commands_pending--;
/*debug*/ printf("%5d %s %s %s\n", commands_pending, reply->keyword, reply->text, dropfile->fname);
    if (!strcmp(reply->keyword, "OK")) {
	unlink(dropfile->fname);
    }
    free((char *)dropfile);
}

sendtoimsp(droplist, hostname)
struct dropfile *droplist;
char *hostname;
{
    static time_t cred_expire, curtime, life;
    int i, gotcred = 0;
    struct imclient *imspconn;
    int r;
    const char *err;
    char mailboxname[MAX_MAILBOX_PATH];
    char *username = 0;
    char *p;
    struct dropfile *tmp;

    curtime = time(0);
    if (cred_expire < curtime+5*60) {
	for (i = 0; login_acte_client[i]; i++) {
/* XXX look for authmech (or similar) config option */
	    err = login_acte_client[i]->new_cred("imap", &life);
	    if (!err) {
		if (!gotcred++ || curtime + life < cred_expire) {
		    cred_expire = curtime + life;
		}
	    }
	    else {
		syslog(LOG_WARNING, "Error getting %s credential: %s",
		       login_acte_client[i]->auth_type, err);
/*debug*/printf("cannot get %s credential: %s", 
		login_acte_client[i]->auth_type, err);
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
	goto freelist;
    }

    r = imclient_authenticate(imspconn, login_acte_client, (char *)0,
			      ACTE_PROT_ANY);
    if (r) {
	syslog(LOG_WARNING, "Error authenticating to IMSP server");
/*debug*/printf("cannot authenticate to imsp\n");
	imclient_close(imspconn);
	goto freelist;
    }

    commands_pending = 0;
    while (droplist) {
	if (strlen(droplist->fname) >= MAX_MAILBOX_PATH) {
/*debug*/ printf("too long %s\n", droplist->fname);
	    unlink(droplist->fname);
	    tmp = droplist;
	    droplist = droplist->next;
	    free((char *)tmp);
	    continue;
	}
	strcpy(mailboxname, strchr(droplist->fname, '=')+1);
	if (p = strchr(mailboxname, '=')) {
	    *p++ = '\0';
	    username = p;
	    while (*p) {
		if (*p == 'A') *p = '/';
		if (*p == 'B') *p = '=';
		p++;
	    }
	}
	p = mailboxname;
	while (*p) {
	    if (*p == 'B') *p = '=';
	    p++;
	}
	
	commands_pending++;
	if (droplist->fname[0] == 'L') {
	    imclient_send(imspconn, callback_dropfile, (void *)droplist,
			  "LAST %s %u %u", mailboxname, droplist->uid,
			  droplist->exists);
	}
	else {
	    imclient_send(imspconn, callback_dropfile, (void *)droplist,
			  "SEEN %s %s %u", mailboxname, username,
			  droplist->uid/*, droplist->last_change*/);
	}
	droplist = droplist->next;
    }
    
    while (commands_pending) {
	imclient_processoneevent(imspconn);
    }
    imclient_close(imspconn);
    return;

  freelist:
    while (droplist) {
	tmp = droplist;
	droplist = droplist->next;
	free((char *)tmp);
    }
}

fatal(msg, code)
char *msg;
int code;
{
    fprintf(stderr, "%s\n", msg);
    exit(code);
}
