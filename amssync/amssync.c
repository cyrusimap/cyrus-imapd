/* amssync.c -- synchronize AMS bboard into IMAP
 *
 *	(C) Copyright 1996 by Carnegie Mellon University
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

#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/time.h>
#include <string.h>
#include <sysexits.h>
#include <errno.h>

#include <sys/ioctl.h>
#ifndef _IOW
#include <sys/ioccom.h>
#endif
#include <afs/vice.h>

#include <netinet/in.h>
#include <afs/stds.h>
#include <afs/afs.h>
#include <afs/param.h>
#include <afs/prs_fs.h>
#include <afs/venus.h>

/* AFS Kludge */
#define V 'V'

#define MAXSIZE 2048
#define BBHASH_SIZE 30341 /* prime */

#include "acte.h"
#include "imclient.h"
#include "xmalloc.h"
#include "amssync.h"
#include "hash.h" /* tjs -- for bboard deletion stuff */

struct cbdata {
    int done;
    char *error;
    char *text;
};

struct acldata {
    char *object;
};

extern struct acte_client krb_acte_client;
struct acte_client *login_acte_client[] = {
    &krb_acte_client,
    NULL
};

struct cbdata cb;
struct acldata acldata;
int content_mode, acl_mode, blast_mode, aclro_mode, verbose, debug, noncommit;
char *cfgname, *principal, *server, *port;
char *dir, *rexp, *bbd, *amsdir;
char buf[2048], buf2[2048], submap[2048];
FILE *cfgfile, *subfile, *logfile;
int pos, neg; /* how many positive and negative AMS ACLs in current dir */
char *posacl[256], *negacl[256]; /* fixed list thereof, dirty hack */
int posval[256], negval[256];
int n_imap_acl = 0; /* how many IMAP ACL entries we have */
char *imapkey[1024], *imapval[1024];
struct imclient *imclient;
ht_table *bb_hash; /* tjs */


/* tjs */
/* This is a hash function
 */
unsigned long h_string(void* s) {
    unsigned long r = 0;

    while (*(char*)s != '\0') {
        r = (r*255) + *(unsigned char*) s;
        s = ((char*) s) + 1;
    }

    return r;
}

/* tjs */
/* bbh_add: callback to add bboard in imclient->reply to hash table
   in rock
 */
void bbh_add(struct imclient* imclient, void* ht,
	     struct imclient_reply *reply) {
    char* c, *cc;

    /* XXX ok, so this is gross */
    c = strrchr(reply->text, ' ') + 1; /* skip to last space plus one
					 to grab bboard name */

    if (c==NULL) {
	if (verbose) {
	    fprintf(logfile, "bbh_add: confused -- strrchr returned \
NULL on reply set!");
	}
	return ;
    }

    if (verbose) {
	fprintf(logfile, "found mailbox on imap server: %s\n",
		c);
    }

    cc = xstrdup(c);

    /* and do a ht_add to ht */
    ht_add((ht_table*) ht, (void*) cc, (void*) cc);
}

/* tjs */
/* delete bboard from server on global var imclient
 */
void bbdelete(void* bboard) {
    if (verbose) {
	fprintf(logfile, "Deleting mailbox %s\n", bboard);
    }
    if (noncommit == 1) {
	imclient_send(imclient, (void(*)()) 0, (void *)0,
		      "DELETE %s", (char*) bboard);
    }
    /* don't wait around */
}


void usage(void)
{
    fprintf(stderr,"\
Usage: syncams [-A | -a] [-b] [-d] [-h] [-m]\n\
               [-u principal] [-v] -c file server [port]\n\
(old options, not all supported yet)\n\
\t-a\tSynchronize ACL's (read-only), create any new bboards\n\
\t-A\tSynchronize ACL's, create any new bboards\n\
\t-b\tDelete dead bboards\n\
\t-m\tSynchronize content (messages)\n\
\t-c\tSpecify a config file name\n\
\t-d\tPrint debugging info\n\
\t-h\tPrint this message\n\
\t-u\tGive principal full perms on all acls (for testing only)\n\
\t-v\tList ams groups as they are processed\n\
\t-n\tOnly show changes, don't commit anything\n");
    exit(1);
} /* usage */

void fatal(char *msg, int exitvalue)
{
    fputs("amssync: ",stderr);
    fputs(msg,stderr);
    fflush(stderr);
    printf("Aborted\n");    
    exit(exitvalue);
} /* fatal */

/* needed by ams and imap modules */
int cmpmsg(const message *m1, const message *m2)
{
    return (m1 -> stamp - m2 -> stamp);
}

/* Determine if bbd matches rexp (fixed prefix)
   Returns zero for success. */
int match(char *bbd, char *rexp)
{
    if (!(rexp[0])) { return 0; }
    if (rexp[0] == '^') { rexp++; }
    return strncmp(bbd,rexp,strlen(rexp));
} /* match */

/* Connect and authenticate */
void cyr_connect(void)
{
    int code, errs;

    if (verbose) {
	fprintf(logfile,"Connecting to Cyrus server...\n");
    }
    code = imclient_connect(&imclient,server,port);
    while (code) {
	switch (code) {
	case -1:
	    fprintf(stderr,"Couldn't find server!\n");
	    exit(1);
	    break;
	case -2:
	    fprintf(stderr,"Unknown service or port %s\n",port);
	    exit(1);
	    break;
	case ECONNREFUSED:
	    if (errs++ >= 5) {
		fprintf(stderr,"Connection refused by server!\n");
		exit(1);
	    }
	    sleep(5);
	    break;
	default:
	    fprintf(stderr,"Unknown error %d from imclient_connect\n",code);
	    exit(1);
	}
	code = imclient_connect(&imclient,server,port);
    }
    if (imclient_authenticate(imclient,login_acte_client,NULL,ACTE_PROT_ANY)) {
	fprintf(stderr,"Couldn't authenticate to server!\n");
	exit(1);
    }

    /* We know we're talking to a Cyrus IMAP server */
    imclient_setflags(imclient, IMCLIENT_CONN_NONSYNCLITERAL);
} /* cyr_connect */

/* IMAP command completion callback */
static void
callback_finish(struct imclient *imclient, void *rock,
                struct imclient_reply *reply)
{
    struct cbdata *cb = (struct cbdata *) rock;

    cb->done++;
    if (!strcmp(reply -> keyword,"OK")) {
	return; /* success */
    }
    cb->error = xstrdup(reply->keyword);
    cb->text = xstrdup(reply->text);
} /* callback_finish */

/* Callback for untagged ACL data */
static void
callback_acl(struct imclient *imclient, void *rock,
             struct imclient_reply *reply)
{
    struct acldata *acldata = (struct acldata *) rock;
    char *s, *val, *identifier, *rights;
    int c;

    s = reply -> text;
    c = imparse_word(&s,&val);
    if ((c != ' ') || strcasecmp(val,"MAILBOX")) { return; }
    c = imparse_astring(&s,&val);
    if ((c != ' ') || strcasecmp(val,acldata -> object)) { return; }
    c = imparse_astring(&s,&identifier);
    if (c != ' ') { return; }
    c = imparse_astring(&s,&rights);
    if (c != '\0') { return; }
    imapkey[n_imap_acl] = xstrdup(identifier);
    imapval[n_imap_acl] = xstrdup(rights);
    n_imap_acl++;
} /* callback_acl */

/* Wait for previous IMAP command to finish */
void
cbwait(void)
{
    while (!(cb.done)) {
	imclient_processoneevent(imclient);
    }
} /* cbwait */

/* Clear results of previous command */
void
cbclear(void)
{
    if (cb.error) free(cb.error);
    if (cb.text) free(cb.text);
    cb.error = cb.text = 0;
    cb.done = 0;
} /* cbclear */

/* Returns the index (into posacl[] and posval[]) of the specified positive
   ACL entry, or -1 on failure. */
int
findpos(char *w)
{
    int i;
    
    if (!w) { return -1; }
    for (i = 0; i < pos; i++) {
	if (posacl[i] && (!strcmp(posacl[i],w))) {
	    return i;
	}
    }
    return -1; /* failure */
} /* findpos */

/* Returns the index (into negacl[] and negval[]) of the specified negative
   ACL entry, or -1 on failure. */
int
findneg(char *w)
{
    int i;

    if (!w) { return -1; }
    for (i = 0; i < neg; i++) {
	if (negacl[i] && (!strcmp(negacl[i],w))) {
	    return i;
	}
    }
    return -1; /* failure */
} /* findneg */

/* Returns the index (into imapkey[] and imapval[]) of the specified IMAP
   ACL entry, or -1 on failure. */
int
findimap(char *w)
{
    int i;

    if (!w) { return -1; }
    for (i = 0; i < n_imap_acl; i++) {
	if (imapkey[i] && (!strcmp(imapkey[i],w))) {
	    return i;
	}
    }
    return -1; /* failure */
} /* findimap */

/* Returns the index (into imapkey[] and imapval[]) of the negative of the
   specified IMAP ACL entry ("-" prepended), or -1 on failure. */
int
findimap2(char *w)
{
    int i;

    if (!w) { return -1; }
    for (i = 0; i < n_imap_acl; i++) {
	if (imapkey[i] && (imapkey[i][0] == '-') &&
	    (!strcmp(imapkey[i] + 1,w))) {
	    return i;
	}
    }
    return -1; /* failure */
} /* findimap2 */

/* Converts a AMS integer ACL value to a IMAP ACL string (in static space) */
char *
amstoimap(int ams)
{
    static char ret[256];

    ret[0] = 0;
    if (ams & PRSFS_LOOKUP) { strcat(ret,"l"); } /* PRSFS_LOOKUP */
    if (ams & PRSFS_READ) { strcat(ret,"rs"); }
    if (ams & PRSFS_WRITE) { strcat(ret,"w"); }
    if (ams & PRSFS_INSERT) { strcat(ret,"i"); }
    if ((ams & (PRSFS_WRITE | PRSFS_INSERT)) ==
	(PRSFS_WRITE | PRSFS_INSERT)) { strcat(ret,"c"); }
    if (ams & PRSFS_DELETE) { strcat(ret,"d"); }
    if (ams & PRSFS_ADMINISTER) { strcat(ret,"a"); }
    return &(ret[0]);
} /* amstoimap */

/* deleteaclmailbox from cyradm */
void
del_acl(char *bbd, char *user)
{
    imclient_send(imclient,(void(*)()) 0, (void *)0,
		  "DELETEACL %s %s",bbd,user);
    /* don't even wait around... */
} /* del_acl */

/* setaclmailbox from cyradm
   neg==1 for negative ACL, 0 for positive */
void
set_acl(char *bbd, char *user, char *acl, int neg)
{
    char *p;

    /* Don't set ACL if no rights */
    if (!*acl) return;

    if (neg) {
	p = (char *) malloc(strlen(user) + 2);
	if (!p) { exit(9); }
	strcpy(p,"-");
	strcat(p,user);
	imclient_send(imclient,(void(*)()) 0, (void *)0,
		      "SETACL %s %s %s", bbd, p, acl);
	free(p);
	return;
    }
    imclient_send(imclient,(void(*)()) 0, (void *)0,
		  "SETACL %s %s %s",bbd,user,acl);
} /* set_acl */

/* taken from amssynctree.pl and cyradm.c
   converted to not rely on a pipe to cyradm */
int
do_acl(char *amsdir, char *bbd)
{
    char space[MAXSIZE], *p, *q, *at;
    struct ViceIoctl blob;
    struct AclEntry *te;
    struct Acl *ta;
    int i, j, k;
    const char *dirs[4] = {
	"system:anyuser",
	"system:authuser",
	"system:campusnet",
	"system:friendlynet"
    };

    /* Create mailbox */
    imclient_send(imclient, (void(*)()) 0, (void *)0,
		  "CREATE %s ams",bbd);
    /* List ACL for mailbox */
    acldata.object = bbd;
    while (n_imap_acl > 0) {
	--n_imap_acl;
	free(imapkey[n_imap_acl]);
	free(imapval[n_imap_acl]);
    }
    imclient_addcallback(imclient, "ACL", 0, callback_acl,
			 (void *)(&acldata), (char *) 0);
    cbclear();
    imclient_send(imclient, callback_finish, (void *)(&cb),
		  "GETACL MAILBOX %s", bbd);
    cbwait();
    if (cb.error) {
	fprintf(stderr,"GETACL result: %s %s\n", cb.error, cb.text);
    }
    /* de-register callback */
    imclient_addcallback(imclient,"ACL",0,(void (*)()) 0,(void *) 0,(char *) 0);
    /*
      fprintf(stderr,"%d IMAP ACL entries:\n",imap);
      for (i = 0; i < imap; i++) {
      fprintf(stderr,"\t%s\t%s\n",imapkey[i],imapval[i]);
      }
      */
    /* this pioctl code borrowed from afs-srv */
    blob.out_size = MAXSIZE;
    blob.in_size = 0;
    blob.out = &(space[0]);
    if (i = pioctl(amsdir,VIOCGETAL,&blob,1)) {
	fprintf(stderr,"VIOCGETAL returned %d\n",i);
	return 1;
    }
    p = blob.out;
    strcat(p,"\n"); /* just in case */
    pos = atoi(p);
    p = strchr(p,'\n') + 1;
    neg = atoi(p);
    p = strchr(p,'\n') + 1;
    for (i = 0; i < pos; i++) {
	*(q = strchr(p,'\n')) = 0;
	posacl[i] = xstrdup(p);
	p = q + 1;
	q = strchr(posacl[i],'\t') + 1;
	posval[i] = atoi(q);
	*(q - 1) = 0;
	if (at = strchr(posacl[i], '@')) ucase(at);
    }
    for (i = 0; i < neg; i++) {
	*(q = strchr(p,'\n')) = 0;
	negacl[i] = xstrdup(p);
	p = q + 1;
	q = strchr(negacl[i],'\t') + 1;
	negval[i] = atoi(q);
	*(q - 1) = 0;
	if (at = strchr(negacl[i], '@')) ucase(at);
    }
    negacl[neg] = "anonymous";
    negval[neg] = 127;
    neg++;
    /* massage the ACLs in various arcane ways */
    /* merge system:anyuser, system:authuser,
       system:campusnet, and system:friendlynet */
    for (k = 0; k < 4; k++) {
	p = (char *) (dirs[k]);
	if ((i = findpos(p)) != -1) {
	    if ((j = findpos("anyone")) != -1) {
		posval[j] |= posval[i];
	    } else { /* create posacl "anyone" if not found */
		posacl[pos] = "anyone";
		posval[pos] = posval[i];
		pos++;
	    }
	    posacl[i] = (char *) NULL; /* delete merged posacl */
	}
    }
    if (principal) { /* -u specified */
	if ((j = findpos(principal)) != -1) {
	    posval[j] = 127;
	} else { /* create posacl for principal if not found */
	    posacl[pos] = principal;
	    posval[pos] = 127;
	    pos++;
	}
    }
    if (aclro_mode) {
	if ((j = findpos("postman")) != -1) {
	    posval[j] = 127;
	} else { /* create posacl for "postman" if not found */
	    posacl[pos] = "postman";
	    posval[pos] = 127;
	    pos++;
	}
	for (i = 0; i < pos; i++) {
	    if (posacl[i] && strcmp(posacl[i],"postman") &&
		(!principal || strcmp(posacl[i],principal))) {
		posval[i] &= (PRSFS_READ | PRSFS_LOOKUP);
	    }
	}
	for (i = 0; i < neg; i++) {
	    if (negacl[i] && strcmp(negacl[i],"postman") &&
		(!principal || strcmp(negacl[i],principal))) {
		negval[i] &= (PRSFS_READ | PRSFS_LOOKUP);
	    }
	}
    }
    for (i = 0; i < n_imap_acl; i++) {
	if (!(imapkey[i])) { continue; }
	if ((findpos(imapkey[i]) == -1) &&
	    (findneg(imapkey[i] + 1) == -1)) {
	    del_acl(bbd,imapkey[i]);
	    imapkey[i] = (char *) NULL;
	}
    }
    for (i = 0; i < pos; i++) {
	if (!(posacl[i])) { continue; }
	if ((posacl[i][0] == '-') || isdigit(posacl[i][0])) { continue; }
	p = amstoimap(posval[i]);
	j = findimap(posacl[i]);
	if (j >= 0 && !strcmp(p,imapval[j])) { continue; }
	set_acl(bbd,posacl[i],p,0); /* positive */
    }
    for (i = 0; i < neg; i++) {
	if (!(negacl[i])) { continue; }
	if ((negacl[i][0] == '-') || isdigit(negacl[i][0])) { continue; }
	p = amstoimap(negval[i]);
	j = findimap2(negacl[i]);
	if (j >= 0 && !strcmp(p,imapval[j])) { continue; }
	set_acl(bbd,negacl[i],p,1); /* negative */
    }
    return 0; /* success */
} /* do_acl */

int imap_bboard_error; /* global, how annoying */

/* taken from amssync.c, formerly called as $syncbbcontents */
int
do_content(char *amsname, char *imapname)
{
    bboard amsbbd, imapbbd;
    int amsidx, imapidx, done;
    register message *amsmsg, *imapmsg;
    time_t timediff;
    int deleted = 0;
    
    if (getams(amsname,&amsbbd)) { return 1; }
    if (getimap(imclient,imapname,&imapbbd)) { return 1; }
    amsidx = imapidx = imap_bboard_error = done = 0;
    while ((!done) && (!imap_bboard_error)) {
	amsmsg = &amsbbd.msgs[amsidx];
	imapmsg = &imapbbd.msgs[imapidx];
	timediff = amsmsg -> stamp - imapmsg -> stamp;
	if (timediff == 0) {
	    amsidx++;
	    imapidx++;
	} else if (timediff > 0) {
	    /* IMAP not in AMS, delete and advance */
	    if (imapmsg -> stamp != 0x7fffffff) {
		DeleteIMAP(imclient,imapname,imapmsg);
		deleted++;
		if (verbose) {
		    fprintf(logfile,"Deleted %d:%s\n",imapidx,imapmsg -> name);
		}
		imapidx++;
	    } else {
		fprintf(stderr,"Tried to delete IMAP Sentinel %d\n",imapidx);
	    }
	} else { /* timediff < 0 */
	    /* AMS not in IMAP, upload and advance */
	    if (amsmsg -> stamp != 0x7fffffff) {
		if (UploadAMS(imclient,imapname,amsname,amsmsg)) {
		    free(amsbbd.msgs);
		    free(imapbbd.msgs);
		    amsbbd.alloced = 0;
		    amsbbd.inuse = 0;
		    imapbbd.alloced = 0;
		    imapbbd.inuse = 0;
		    return 1;
		}
		if (verbose) {
		    fprintf(logfile,"Uploaded %d:%s\n",amsidx,amsmsg -> name);
		}
		amsidx++;
	    } else {
		fprintf(stderr,"Tried to upload AMS Sentinel %d\n",amsidx);
	    }
	} /* done with timediff */
	if ((amsidx > amsbbd.inuse) && (imapidx > imapbbd.inuse)) {
	    done = 1; /* finished both lists */
	    continue;
	}
	if (amsidx > amsbbd.inuse) {
	    /* finished AMS first, remove remaining IMAP */
	    while ((imapidx <= imapbbd.inuse) && (!imap_bboard_error)) {
		if (imapbbd.msgs[imapidx].stamp != 0x7fffffff) {
		    DeleteIMAP(imclient,imapname,imapbbd.msgs[imapidx]);
		    deleted++;
		    if (verbose) {
			fprintf(logfile,"Deleted %d:%s\n",
				imapidx,imapbbd.msgs[imapidx].name);
		    }
		    imapidx++;
		} else {
		    fprintf(stderr,"Tried to delete IMAP Sentinel %d\n",imapidx);
		}
	    }
	    done = 1;
	} else if (imapidx > imapbbd.inuse) {
	    /* finished IMAP first, upload remaining AMS */
	    while ((amsidx <= amsbbd.inuse) && (!imap_bboard_error)) {
		if (amsbbd.msgs[amsidx].stamp != 0x7fffffff) {
		    if (verbose) {
			fprintf(logfile,"Uploaded %d:%s\n",amsidx,amsbbd.msgs[amsidx].name);
		    }
		    if (UploadAMS(imclient,imapname,amsname,amsbbd.msgs + amsidx)) { 
			free(amsbbd.msgs);
			free(imapbbd.msgs);
			amsbbd.alloced = 0;
			amsbbd.inuse = 0;
			imapbbd.alloced = 0;
			imapbbd.inuse = 0;
			return 1;
		    }                    
		    amsidx++;
		} else {
		    fprintf(stderr,"Tried uploading AMS Sentinel %d\n",amsidx);
		}
	    }
	    done = 1;
	}
    } /* main loop for do_content */
    free(amsbbd.msgs);
    free(imapbbd.msgs);
    amsbbd.alloced = 0;
    amsbbd.inuse = 0;
    imapbbd.alloced = 0;
    imapbbd.inuse = 0;
    if (deleted) do_imap_close(imclient);
    return imap_bboard_error; /* 0 = success */
} /* do_content */

int main(int argc, char **argv)
{
    char *p1;
    int err, cnt;

    setbuf(stderr,(char *) NULL);

    content_mode = acl_mode = aclro_mode = blast_mode =
	verbose = debug = noncommit = 0;
    cfgname = principal = server = port = (char *) NULL;
    /* Parse command line */
    while (--argc && *++argv) {
	if (!strcmp(*argv,"-a")) {
	    acl_mode = 1;
	    aclro_mode = 1;
	} else if (!strcmp(*argv,"-A")) {
	    acl_mode = 1;
	} else if (!strcmp(*argv,"-b")) {
	    blast_mode = 1;
	} else if (!strcmp(*argv,"-c")) {
	    if (argc <= 1) { usage(); }
	    cfgname = xstrdup(*++argv);
	    if (!(--argc)) { break; }
	} else if (!strcmp(*argv,"-d")) {
	    debug = 1;
	} else if (!strcmp(*argv,"-h")) {
	    usage();
	} else if (!strcmp(*argv,"-m")) {
	    content_mode = 1;
	} else if (!strcmp(*argv,"-n")) {
	    noncommit = 1;
	} else if (!strcmp(*argv,"-u")) {
	    if (argc <= 1) { usage(); }
	    principal = xstrdup(*++argv);
	    if (!(--argc)) { break; }
	} else if (!strcmp(*argv,"-v")) {
	    verbose = 1;
	} else if (!server) {
	    server = xstrdup(*argv);
	} else if (!port) {
	    port = xstrdup(*argv);
	} else {
	    usage();
	}
    }
    if (!(content_mode || acl_mode || blast_mode || verbose)) {
	fprintf(stderr,"-a, -A, -v, -b, and/or -m required\n");
	usage();
    }
    if (!server) {
	fprintf(stderr,"server name required\n");
	usage();
    }
    if (!port) {
	port = "143"; /* default */
    }
    if (!cfgname) {
	fprintf(stderr, "-c configfile required\n");
	usage();
    }
    if (verbose) {
	logfile = fopen("/tmp/Log","w");
	setbuf(logfile,(char *) NULL);
    }
    /* Report status */
    if (verbose) {
	fprintf(logfile,"\
Server: %s\n\
Port: %s\n\
  Mode: %s%s%s\n",server,port,
		acl_mode ? "Update ACLs" : "No ACLs",
		aclro_mode ? " (read-only)" : "",
		content_mode ? ", Update Content" : ", No Content",
		blast_mode ? ", blast old bboards" : ", keep old bboards");
    }
    /* Connect to Cyrus server once, no matter what */
    cyr_connect();

    /* Open configuration file */
    if (!strcmp(cfgname,"-")) {
	cfgfile = fdopen(fileno(stdin),"r");
    } else {
	cfgfile = fopen(cfgname,"r");
    }
    if (!cfgfile) {
	fprintf(stderr,"Couldn't read configuration file '%s'\n",cfgname);
	exit(1);
    }


    /* Main processing loop */
    err = cnt = 0;
    fgets(buf,256,cfgfile);
    buf[255] = 0;
    while (!feof(cfgfile)) {
	if (buf[0] == '#') { continue; }
	if ((p1 = strchr(buf,':')) == (char *) NULL) { /* invalid pattern */
	    fprintf(stderr,"Invalid pattern '%s' in configuration\n",buf);
	    exit(1);
	}
	*(p1++) = 0;
	dir = buf;
	rexp = p1;
	if (p1 = strchr(rexp,'\n')) { *p1 = 0; } /* chop newline */
	if (verbose)  {
	    fprintf(logfile,"Working on '%s:%s'\n",dir,rexp);
	}

	/* tjs */
	if (blast_mode) {
	    bb_hash = ht_create(h_string, 
				BBHASH_SIZE /* size; a magic number */,
				sizeof(char*), /* size of member (useless,
						  really */
				strcmp, /* compare fn */
				free /* free fn */);
	    
	    /* tjs: add list callback */
	    imclient_addcallback(imclient,
				  "LIST", CALLBACK_NOLITERAL,
				  bbh_add, bb_hash,
				  NULL) ;
	    
	    /* tjs: LIST bboards from config file into hash table */
	    cbclear();

	    /* XXX THIS IS REALLY BRAINDEAD
	     * this code doesn't actually interpret regular expressons
	     * it just looks and sees if the first char is ^; if so,
	     * it skips it; if not, it doesn't.  This is what match()
	     * does anyway...
	     */
	    if (verbose)
		fprintf(logfile, "listing bboards (LIST NIL \
%s.*)...\n",
			rexp+(*rexp == '^'));
	    imclient_send(imclient, callback_finish, (void*) &cb,
			  "LIST NIL %s.*", rexp+(*rexp=='^'));
	    cbwait();
	}

	sprintf(submap,"%s/.MESSAGES/.SubscriptionMap",dir);
	subfile = fopen(submap,"r");
	if (!subfile) {
	    fprintf(stderr,"Couldn't open '%s'!\n",submap);
	    exit(1);
	}
	fgets(buf2,2048,subfile);
	buf2[2047] = 0;
	while (!feof(subfile)) {
	    if ((p1 = strchr(buf2,':')) == (char *) NULL) {
		fprintf(stderr,"Couldn't parse '%s'\n",buf2);
		exit(1);
	    }
	    *(p1++) = 0;
	    bbd = buf2;
	    amsdir = p1;
	    if (p1 = strchr(amsdir,'\n')) { *p1 = 0; } /* chop newline */
	    if (verbose)  {
		fprintf(logfile,"\t'%s:%s'\n",bbd,amsdir);
	    }
	    if (!match(bbd,rexp)) {
		if (acl_mode) {
		    if (verbose) { fprintf(logfile,"ACLs...\n"); }
		    if (do_acl(amsdir,bbd)) { err++; }
		}
		if (content_mode) {
		    if (verbose) { fprintf(logfile,"Content...\n"); }
		    if (do_content(amsdir,bbd)) { err++; }
		}

		/* tjs */
		/* if we're in blast mode, remove it from hash table */
		if (blast_mode) {
		    if (verbose) {
			fprintf(logfile, "removing bboard from list \
of bboards to be blasted ...\n");
		    }
		    /* remove from hash table */
		    ht_remove(bb_hash, (void*) bbd);
		}
		cnt++;
	    }
	    fgets(buf2,2048,subfile);
	    buf2[2047] = 0;
	}
	fgets(buf,256,cfgfile);
	buf[255] = 0;
    }

    /* tjs */
    /* for any bboard left in the hash table,
       blast it. */
    if (blast_mode) {
	ht_foreach(bb_hash, (void*) bbdelete);
    }

    do_imap_noop(imclient);	/* Flush & wait for pending commands */
    imclient_close(imclient);
    if (verbose) {
	fprintf(logfile,"Done!\n");
	fclose(logfile);
    }
    fprintf(stderr,"%d errors in %d bboards\n",err,cnt);
    exit(EX_OK);
} /* main */

