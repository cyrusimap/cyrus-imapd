/* imap.c -- read/write IMAP bboards
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

#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/time.h>
#include <string.h>
#include <sysexits.h>

#include <atk/unscribe.h>
#include "xmalloc.h"
#include "acte.h"
#include "imclient.h"
#include "amssync.h"

extern struct acte_client krb_acte_client;
extern int debug,verbose;

struct acte_client *login_acte_client[] = {
    &krb_acte_client,
    NULL
};

/* Parse an IMAP date/time specification. Stolen from cyrus/imapd/imapd.c
 * (getdatetime())
 */
static char *monthname[] = {
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec"
};


time_t parsefetchdate(char *buf)
{
    int c;
    struct tm tm, *ltm;
    int old_format = 0;
    static struct tm zerotm;
    char month[4], zone[4], *p;
    int zone_off;
    time_t date;

    tm = zerotm;
    
    c = *buf++;
    if (c != '\"') goto baddate;
    
    /* Day of month */
    c = *buf++;
    if (c == ' ') c = '0';
    if (!isdigit(c)) goto baddate;
    tm.tm_mday = c - '0';
    c = *buf++;
    if (isdigit(c)) {
	tm.tm_mday = tm.tm_mday * 10 + c - '0';
	c = *buf++;
    }
    
    if (c != '-') goto baddate;
    c = *buf++;

    /* Month name */
    if (!isalpha(c)) goto baddate;
    month[0] = c;
    c = *buf++;
    if (!isalpha(c)) goto baddate;
    month[1] = c;
    c = *buf++;
    if (!isalpha(c)) goto baddate;
    month[2] = c;
    c = *buf++;
    month[3] = '\0';
    lcase(month);

    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!strcmp(month, monthname[tm.tm_mon])) break;
    }
    if (tm.tm_mon == 12) goto baddate;

    if (c != '-') goto baddate;
    c = *buf++;

    /* Year */
    if (!isdigit(c)) goto baddate;
    tm.tm_year = c - '0';
    c = *buf++;
    if (!isdigit(c)) goto baddate;
    tm.tm_year = tm.tm_year * 10 + c - '0';
    c = *buf++;
    if (isdigit(c)) {
	if (tm.tm_year < 19) goto baddate;
	tm.tm_year -= 19;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = *buf++;
	if (!isdigit(c)) goto baddate;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = *buf++;
    }
    else old_format++;

    /* Hour */
    if (c != ' ') goto baddate;
    c = *buf++;
    if (!isdigit(c)) goto baddate;
    tm.tm_hour = c - '0';
    c = *buf++;
    if (!isdigit(c)) goto baddate;
    tm.tm_hour = tm.tm_hour * 10 + c - '0';
    c = *buf++;
    if (tm.tm_hour > 23) goto baddate;

    /* Minute */
    if (c != ':') goto baddate;
    c = *buf++;
    if (!isdigit(c)) goto baddate;
    tm.tm_min = c - '0';
    c = *buf++;
    if (!isdigit(c)) goto baddate;
    tm.tm_min = tm.tm_min * 10 + c - '0';
    c = *buf++;
    if (tm.tm_min > 59) goto baddate;

    /* Second */
    if (c != ':') goto baddate;
    c = *buf++;
    if (!isdigit(c)) goto baddate;
    tm.tm_sec = c - '0';
    c = *buf++;
    if (!isdigit(c)) goto baddate;
    tm.tm_sec = tm.tm_sec * 10 + c - '0';
    c = *buf++;
    if (tm.tm_min > 60) goto baddate;

    /* Time zone */
    if (old_format) {
	if (c != '-') goto baddate;
	c = *buf++;

	if (!isalpha(c)) goto baddate;
	zone[0] = c;
	c = *buf++;

	if (c == '\"') {
	    /* Military (single-char) zones */
	    zone[1] = '\0';
	    lcase(zone);
	    if (zone[0] <= 'm') {
		zone_off = (zone[0] - 'a' + 1)*60;
	    }
	    else if (zone[0] < 'z') {
		zone_off = ('m' - zone[0])*60;
	    }
	    else zone_off = 0;
	}
	else {
	    /* UT (universal time) */
	    zone[1] = c;
	    c = *buf++;
	    if (c == '\"') {
		zone[2] = '\0';
		lcase(zone);
		if (!strcmp(zone, "ut")) goto baddate;
		zone_off = 0;
	    }
	    else {
		/* 3-char time zone */
		zone[2] = c;
		c = *buf++;
		if (c != '\"') goto baddate;
		zone[3] = '\0';
		lcase(zone);
		p = strchr("aecmpyhb", zone[0]);
		if (c != '\"' || zone[2] != 't' || !p) goto baddate;
		zone_off = (strlen(p) - 12)*60;
		if (zone[1] == 'd') zone_off -= 60;
		else if (zone[1] != 's') goto baddate;
	    }
	}
    }
    else {
	if (c != ' ') goto baddate;
	c = *buf++;

	if (c != '+' && c != '-') goto baddate;
	zone[0] = c;

	c = *buf++;
	if (!isdigit(c)) goto baddate;
	zone_off = c - '0';
	c = *buf++;
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 10 + c - '0';
	c = *buf++;
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 6 + c - '0';
	c = *buf++;
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 10 + c - '0';

	if (zone[0] == '-') zone_off = -zone_off;

	c = *buf++;
	if (c != '\"') goto baddate;

    }

    c = *buf++;

    tm.tm_isdst = -1;
    date = mktime(&tm);
    ltm = localtime(&date);
    date += gmtoff_of(ltm, date) - zone_off*60;

    return date;

 baddate:
    return -1;
}

/*
 * write a NULL at the first CR or NL in the message, so that the
 * string represents one line
 */
char *getonerespline(char *text)
{
    char *p, *q;

    p=strchr(text, '\r');
    q=strchr(text, '\n');

    if (q && (!p || p > q)) {
	*q='\0';
    }
    else if (p) {
	*p='\0';
    }

    return text;
}

/*
 * Callback for the EXISTS untagged response. allocates the correct
 * number of message structures.
 */
void processexists(struct imclient *conn, bboard *bbd, struct
                 imclient_reply *inmsg)
{
    bbd->alloced=inmsg->msgno;
    bbd->inuse=-1;
    bbd->msgs=(message *)xmalloc((bbd->alloced+1) * sizeof (message));
}

/*
 * Callback for the FETCH untagged response. Parses the INTERNALDATE
 * and UID fields (UID is used for message->name)
 */
void processfetch(struct imclient *conn, bboard *bbd, struct
                 imclient_reply *inmsg)
{
    char *p;
  
    if (bbd->inuse == -2) {
	fatal("FETCH before EXISTS!\n", EX_PROTOCOL);
    }

#if 0
    /* This should never happen. So far it hasn't */
    if (++bbd->inuse == bbd->alloced) {
	fprintf(stderr, "imapuse == imapsz. This shouldn't have happened\n");
	bbd->alloced *= 2;
	bbd->msgs=(message *)xrealloc(bbd->msgs, bbd->alloced * sizeof (message));
    }
#else
    bbd->inuse++;
#endif
    getonerespline(inmsg->text);
    p=strstr(inmsg->text, "INTERNALDATE ");
    if (p) {
	p=&p[strlen("INTERNALDATE ")];
	bbd->msgs[bbd->inuse].stamp=parsefetchdate(p);
	if (bbd->msgs[bbd->inuse].stamp == -1) {
	    printf ("Date parse of (%ld) %s failed\n", inmsg->msgno, p);
	    printf("Full text was \n%s\n",inmsg->text);
	}  
    } else {
	printf("No INTERNALDATE in %ld\n", inmsg->msgno);
	printf("Full text was \n%s\n",inmsg->text);
    }
    p=strstr(inmsg->text, "UID ");
    if (p) {
	p=&p[strlen("UID ")];
	if (isdigit(p[0])) {
	    sprintf(bbd->msgs[bbd->inuse].name,"%ld", atol(p));
	} else {
	    printf("UID parse of (%ld) %s failed\n", inmsg->msgno, p);
	    printf("Full text was \n%s\n",inmsg->text);
	}
    } else {
	printf("No UID in %ld\n", inmsg->msgno);
	printf("Full text was \n%s\n",inmsg->text);
    }
}

/*
 * Command callback for something we wait for. Sets passed rock to 1
 * or 2 depending on the success or failure of the command
 */

void markdone(struct imclient *conn, char *rock, struct
                 imclient_reply *inmsg)
{
    if (!strncmp(inmsg->keyword, "OK", 2)) {
	*(int *)rock=1;
	if (debug) {
	    printf("cmdfinished: %s\n", inmsg->text);
	}
    } else {
	if (debug) {
	    printf("Command FAILED: %s %s\n", inmsg->keyword, inmsg->text);
	}
	*(int *)rock=2;
    }
}

/*
 * Command callback for something we don't wait for. Prints an error
 * message and continues if the problem is message related, otherwise,
 * prints the message and exits
 */
void errcheck(struct imclient *conn, char *rock, struct
                 imclient_reply *inmsg)
{
    char buf[1050];
  
    if (!strncmp(inmsg->keyword, "OK", 2)) {
	if (debug) {
	    printf("cmdfinished: %s %s\n", inmsg->keyword, inmsg->text);
	}
    }
    else {
	if (rock) {
	    sprintf(buf, "%s failed: %s\n", (char *)rock, inmsg->text);
	}
	else {
	    sprintf(buf, "A command failed: %s %s\n", inmsg->keyword,
		    inmsg->text);
	}
	if (!strstr(inmsg->text, "Message")) {
	    fatal(buf, EX_PROTOCOL);
	}
	else {
	    fputs(buf,stderr);
	}
    }
    if (rock) {
	free(rock);
    }
}

/*
 * Free callback for an IMAP mailbox. closes the open mailbox and
 * terminates the server connection
 */
void do_imap_close(struct imclient *imclient)
{
    int waitforcomplete;

    waitforcomplete=0;
    imclient_send(imclient, markdone, &waitforcomplete, "CLOSE");
    while (!waitforcomplete) {
	imclient_processoneevent(imclient);
    }
    imclient_close(imclient);
}

/*
 * allows main program to set imap server and port to use in
 * subsequent getimap() calls . the interface of this system (in
 * general) isn't very good
 */
static char imapser[MAXHOSTNAMELEN]="cyrus.andrew.cmu.edu";
static char *imapport=NULL;

int setimapser(char *server, char  *port)
{
    static char xport[6]="";

    strcpy(imapser,server);
    if (port) {
	strcpy(xport,port);
	imapport=xport;
    }
    else {
	imapport=NULL;
    }
    return 0;
}

/*
 * Allocate and build a bboard struct for the named IMAP mailbox.
 * Creates a new IMAP copnnection to the server, fetches name and date
 * information and builds a sorted message list. the inuse and alloced
 * members do not take the sentinel into account.
 */
bboard *getimap(char *bbd)
{
    int waitforcomplete,i;
    bboard *imapbbd;
    struct imclient *imclient;

    if (imclient_connect(&imclient,imapser,imapport)) {
	fatal("couldn't find server\n", EX_NOHOST);
    }
    if (imclient_authenticate(imclient,login_acte_client,NULL,ACTE_PROT_ANY)) {
	fatal("couldn't auth to server\n", EX_UNAVAILABLE);
    }
    imapbbd=(bboard *)xmalloc(sizeof(bboard));
    strcpy(imapbbd->name, bbd);
    imapbbd->alloced=0;
    imapbbd->inuse=-2;
    imapbbd->internaldata=imclient;
    imapbbd->internalfreeproc=do_imap_close;
    imclient_addcallback(imclient,
			 "EXISTS", CALLBACK_NUMBERED , processexists, imapbbd,
			 "FETCH", CALLBACK_NUMBERED, processfetch, imapbbd,
			 NULL);

    waitforcomplete=0;
    imclient_send(imclient, markdone, &waitforcomplete, "SELECT %s", bbd);
    while (!waitforcomplete) {
	imclient_processoneevent(imclient);
    }

    if (imapbbd->inuse == -2) {
	fatal("Select did not elicit EXISTS response; does bboard exist?\n", EX_PROTOCOL);
    }

    waitforcomplete=0;
    imclient_send(imclient, markdone, &waitforcomplete,
		  "FETCH 1:%d (internaldate uid)", imapbbd->alloced);
    while (!waitforcomplete) {
	imclient_processoneevent(imclient);
    }

    imclient_addcallback(imclient,
			 "EXISTS", CALLBACK_NUMBERED , NULL, NULL,
			 "FETCH", CALLBACK_NUMBERED, NULL, NULL,
			 NULL);
    
    waitforcomplete=0;
    if (debug) {
	printf("There are %d messages in %s (should be %d)\n",
	       imapbbd->inuse+1, bbd, imapbbd->alloced);
    }
    else if (verbose) {
	printf("There are %d messages in %s\n",
	       imapbbd->inuse+1, bbd);
    }
    if (imapbbd->inuse >= 0) {
	qsort(imapbbd->msgs, imapbbd->inuse+1, sizeof (message), cmpmsg);
	if (debug) {
	    for (i=0;i<=imapbbd->inuse;i++) {
		printf("message %s was submitted at %ld\n",
		       imapbbd->msgs[i].name, (long)imapbbd->msgs[i].stamp);
	    }
	}
    }
    imapbbd->msgs[imapbbd->inuse+1].stamp=0x7fffffff;
    
    return imapbbd;
}

/*
 * Extract the imclient from the bbd->internaldata member and return
 * it (This exists mostly because of typing/casting issues and
 * convenience)
 */
struct imclient *bboard_imclient(bboard *bbd)
{
    return (struct imclient *)bbd->internaldata;
}

/*
 * Marks the passed message deleted. This sends a command to
 * the imap server, but does not wait for a response. the passed
 * buffer is so that errcheck can print useful error messages
 */
void DeleteIMAP(bboard *bbd, message *msg)
{
    struct imclient *imclient;
    char *buf;
    imclient=bboard_imclient(bbd);
    if (verbose) printf("D");
  
    buf=xmalloc(256);
    sprintf(buf, "Delete %s in %s", msg->name,bbd->name);
  
    imclient_send(imclient, errcheck, buf,
		  "uid store %a +flags.silent (\\Deleted)", msg->name);
}

/*
 * Unscribe and append the AMS message to the IMAP mailbox
 */
void UploadAMS(bboard *imapdest, bboard *amssrc, message *msg)
{
    char *fname;
    FILE *msgf, *tmpf;
    char *allmsg, *withcrnl, buf[1025], *descbuf, *tmpfil, *p, *q, *r;
    int len, rc, gmtnegative, scribeval, done, unscribe;
    int gmtoff, line;
    struct tm *tm;
    struct stat statbuf;
    struct ScribeState *scribestate;

    tmpf=NULL;
    scribeval=0;
    tmpfil=NULL;
    len=0; 
    if (verbose) printf("A");

    /* First, allocate a buffer large enough to hold the entire message */
    fname=getfilename(amssrc, msg);
    msgf=fopen(fname,"r");
    if (!msgf) {
	fprintf(stderr, "Couldn't open message\n");
	perror(fname);
	exit(EX_NOINPUT);
    }
    if (fstat(fileno(msgf), &statbuf) == -1) {
	fprintf(stderr, "Couldn't stat message\n");
	perror(fname);
	fclose(msgf);
	exit(EX_NOINPUT); 
    }
    allmsg=xmalloc(statbuf.st_size+1);
    memset(allmsg, 0, statbuf.st_size+1);
    allmsg[0]='\0';
    done=0;
    unscribe=0;

    /* Read header lines , and try to find any Content-Type headers */
    while (!done) {
	if (fgets(&buf[0], 1024, msgf) == 0) {
	    fprintf(stderr, "Couldn't read message\n");
	    perror(fname);
	    fclose(msgf);
	    exit(EX_NOINPUT);
	}
	/* If a BE2 message, pass the version number into UnScribeInit */
	if (!strncmp(buf, "Content-Type: X-BE2", 19)) {
	    r=&buf[strlen(buf)-2];
	    buf[strlen(buf)-1]=0;
	    if ((scribeval = UnScribeInit(&buf[20], &scribestate)) < 0) {
		fprintf(stderr, "Unknown scribe version \"%s\"\n",
			&buf[20]);
		fprintf(stderr, "Not Unscribing %s\n", fname);
		strcat(buf,"\n");
	    } else {
		strcpy(buf,"Content-Type: text/plain\n");
		unscribe=1;
	    }
	}
	/* Add the (possibly modified) header to the message buffer */
	strcat(allmsg, buf);
      
	if (*buf == '\n') {
	    /* header/body seperarator. Done with the headers */
	    done=1;
	    len=strlen(allmsg);
	}
    }
    if (unscribe) {
	/* Since unscribe sends it's output to a FILE *, create a temp
	 * file, and write the headers to it.
	 */
	tmpfil=tmpnam(NULL);
	close(creat(tmpfil,0700));
	if ((tmpf=fopen(tmpfil,"r+")) == NULL) {
	    fprintf(stderr, "Couldn't create temp file\n");
	    perror(tmpfil);
	    exit(EX_OSERR);
	}
	rc=fwrite(allmsg, 1, len, tmpf);
	if (rc == -1) {
	    fprintf(stderr, "Couldn't write headers to temp file\n");
	    perror(tmpfil);
	    fclose(tmpf);
	    unlink(tmpfil);
	    fclose(msgf);
	    exit(EX_OSERR);
	}
	if (rc < len) {
	    fprintf(stderr, "Short write of headers to temp file %s\n",
		    tmpfil);
	}
	/* Read the formatted body into the buffer. It will fit. */
	rc=fread(allmsg,1, statbuf.st_size - len+1, msgf);
	if (rc == -1) {
	    fprintf(stderr, "Couldn't read message\n");
	    perror(fname);
	    fclose(msgf);
	    fclose(tmpf);
	    unlink(tmpfil);
	    exit(EX_NOINPUT);
	}      
	if (rc < statbuf.st_size - len) {
	    fprintf(stderr, "Short read (%d/%ld) of message %s\n",rc ,
		    statbuf.st_size - len, fname); 
	}
	fclose(msgf);
	/* Call UnScribe and UnScribeFlush */
	rc=UnScribe(scribeval, &scribestate, allmsg, rc, tmpf);
	if (rc == -1) {
	    fprintf(stderr, "Unable to write UnScribed message\n");
	    perror(tmpfil);
	    fclose(tmpf);
	    unlink(tmpfil);
	    exit(EX_OSERR);
	}      
	if (rc < 0) {
	    fprintf(stderr, "UnScribe failed!\n");
	    fclose(tmpf);
	    unlink(tmpfil);
	    exit(EX_UNAVAILABLE);
	}
	rc=UnScribeFlush(scribeval, &scribestate, tmpf);
	if (rc == -1) {
	    fprintf(stderr, "Unable to flush UnScribed message\n");
	    perror(tmpfil);
	    fclose(tmpf);
	    unlink(tmpfil);
	    exit(EX_OSERR);
	}      
	if (rc < 0) {
	    fprintf(stderr, "UnScribeFlush failed!\n");
	    fclose(tmpf);
	    unlink(tmpfil);
	    exit(EX_UNAVAILABLE);
	}
	/* Reallocate message buffer and read whole unformatted message in */
	rewind(tmpf);
	free(allmsg);
	if (fstat(fileno(tmpf), &statbuf) == -1) {
	    fprintf(stderr, "Couldn't stat temp file\n");
	    perror(tmpfil);
	    fclose(tmpf);
	    unlink(tmpfil);
	    exit(EX_OSERR);
	}
	allmsg=xmalloc(statbuf.st_size+1);
	memset(allmsg, 0, statbuf.st_size+1);
    
	rc=fread(allmsg,1, statbuf.st_size, tmpf);
	if (rc == -1) {
	    fprintf(stderr, "Couldn't read temp file\n");
	    perror(tmpfil);
	    fclose(tmpf);
	    unlink(tmpfil);
	    exit(EX_OSERR);
	}      
	if (rc < statbuf.st_size) {
	    fprintf(stderr, "Short read (%d/%d) of temp file\n",rc ,
		    (int) statbuf.st_size); 
	}
	fclose(tmpf);
	unlink(tmpfil);
    }
    else {
	/* Not BE2, just read the whole thing in. */
	rewind(msgf);
	rc=fread(allmsg,1, statbuf.st_size, msgf);
	if (rc == -1) {
	    fprintf(stderr, "Couldn't read message file\n");
	    perror(tmpfil);
	    fclose(tmpf);
	    unlink(tmpfil);
	    exit(EX_OSERR);
	}      
	if (rc < statbuf.st_size) {
	    fprintf(stderr, "Short read (%d/%d) of message file\n",rc ,
		    (int) statbuf.st_size); 
	}
	fclose(msgf);
    }

    /*
     * Now copy each line of the message into a new buffer, adding CR's
     * where neccesarry for RFC822 compliance.
     */
    withcrnl=xmalloc(1);
    withcrnl[0]='\0';
    q=allmsg;
    line=0;
    while ((p=strchr(q,'\n'))) {
	line++;
	withcrnl=xrealloc(withcrnl, strlen(withcrnl)+ (int)(p-q) +3);
	strncat(withcrnl, q, (int)(p-q));
	r=&withcrnl[strlen(withcrnl)-1];
	if (*r != '\r') {
	    r++;
	    *r++='\r';
	    *r++='\n';
	    *r='\0';
	}
	q=p+1;
    }
#if 0                           /* this code sucks. It's supposed to */
                                /* deal with an all-header no body */
                                /* message without a trailing LF, but */
                                /* it doesn't work. purify is cool or */
                                /* something. */
    if (q && *q){
	p=&q[strlen(q)];
	withcrnl=xrealloc(withcrnl, (int)(p-q) +3);
	strcat(withcrnl,q);
	strcat(withcrnl,"\r\n");
    }
#endif
    /* Generate timestamp string for IMAP internaldate */
    gmtoff = gmtoff_of((tm=localtime(&msg->stamp)), msg->stamp);
    gmtnegative = 0;
    if (tm->tm_year < 80) {
	fprintf(stderr, "Invalid time stamp %ld in message %s\n",
		msg->stamp, msg->name);
	free(withcrnl);
	free(allmsg);
	free(fname);
	return;
    }
    if (gmtoff < 0) {
	gmtoff = -gmtoff;
	gmtnegative = 1;
    }
    gmtoff /= 60;
    sprintf(buf, "%2u-%s-%u %.2u:%.2u:%.2u %c%.2u%.2u",
	    tm->tm_mday, monthname[tm->tm_mon], tm->tm_year+1900,
	    tm->tm_hour, tm->tm_min, tm->tm_sec,
	    gmtnegative ? '-' : '+', gmtoff/60, gmtoff%60);
    
    /* informative message for errcheck */
    descbuf=xmalloc(1024);
    sprintf(descbuf, "Append of %s%s", unscribe ? "unscribed " : "",
	    fname);
    
    imclient_send(bboard_imclient(imapdest), errcheck, descbuf,
		  "APPEND %s \"%a\" %s", imapdest->name, buf, withcrnl);
    
    free(withcrnl);
    
    free(allmsg);
    free(fname);
}
