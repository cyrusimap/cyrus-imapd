/* imap.c -- read/write IMAP bboards
 *
 *	(C) Copyright 1995 by Carnegie Mellon University
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

extern int debug,verbose, imap_bboard_error;
extern FILE *logfile;



/* Parse an IMAP date/time specification. Stolen from cyrus/imapd/imapd.c
 * (getdatetime())
 */
static char *monthname[] = {
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec"
};


time_t parsefetchdate(char **bufx)
{
    int c;
    struct tm tm, *ltm;
    int old_format = 0;
    static struct tm zerotm;
    char month[4], zone[4], *p;
    int zone_off;
    time_t date;
    char *buf;
    

    tm = zerotm;
    buf=*bufx;
    
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
    bufx=&buf;
    
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
}

/*
 * Callback for the FETCH untagged response. Parses the INTERNALDATE
 * and UID fields (UID is used for message->name)
 *
 * NOTE: this is a horrible example of a FETCH callback function.
 * It makes broad assumptions about how the Cyrus IMAPd generates
 * FETCH responses; it does not parse them according to the IMAP
 * protocol specificiation.
 */
void processfetch(struct imclient *conn, bboard *bbd, struct
                 imclient_reply *inmsg)
{
    char *p,*q;
    int parenlvl,ifound,ufound;;
    
    if (bbd->inuse == -2) {
	fatal("FETCH before EXISTS!\n", EX_PROTOCOL);
    }
    bbd->inuse++;
    getonerespline(inmsg->text);
    q=inmsg->text;
    parenlvl=0;
    ifound=0;
    ufound=0;
    
    
    while (q && *q && (!ifound || !ufound)) {
        if (*q=='(') parenlvl++;
        if (parenlvl) {
            if (*q==')') parenlvl--;
        }
        if (parenlvl == 1) {
            if (*q=='I' && !strncmp(q,"INTERNALDATE ",strlen("INTERNALDATE ")))
                {
                    p=&q[strlen("INTERNALDATE ")];
                    if (debug > 2)
                       printf("Date is %s\n", p);
                    bbd->msgs[bbd->inuse].stamp=parsefetchdate(&p);
                    if (bbd->msgs[bbd->inuse].stamp == -1) {
                        printf ("Date parse of (%ld) %s failed\n",
                                inmsg->msgno, p); 
                        printf("Full text was \n%s\n",inmsg->text);
                    }
                    ifound=1;
                    q=p;
                }
            if (*q=='U' && !strncmp(q,"UID ",strlen("UID ")))
                {
                    p=&q[strlen("UID ")];
                    if (isdigit(p[0])) {
                        sprintf(bbd->msgs[bbd->inuse].name,"%ld", atol(p));
                    } else {
                        printf("UID parse of (%ld) %s failed\n", inmsg->msgno,
                               p); 
                        printf("Full text was \n%s\n",inmsg->text);
                    }
                    ufound=1;
                    q=p;
                }
        }
        q++;
    }
    if (!ifound) {
        printf("No INTERNALDATE in %ld\n", inmsg->msgno);
        printf("Full text was \n%s\n",inmsg->text);
    }
    if (!ufound)    {
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
  
    if (!strncmp(inmsg->keyword, "OK", 2)) {
	if (debug) {
	    printf("cmdfinished: %s %s\n", inmsg->keyword, inmsg->text);
	}
    }
    else {
	if (rock) {
	    fprintf(stderr, "%s failed: %s\n", (char *)rock, inmsg->text);
	}
	else {
	    fprintf(stderr, "A command failed: %s %s\n", inmsg->keyword,
		    inmsg->text);
	}
	if (!strstr(inmsg->text, "Message")) {
	   imap_bboard_error=1;
	}
    }
    if (rock) {
	free(rock);
    }
}

/*
 * Closes any open mailbox on the imap server connection.
 */
void do_imap_close(struct imclient *imclient)
{
    imclient_send(imclient, (void(*)()) 0, (void *)0, "CLOSE");
}

void do_imap_noop(struct imclient *imclient)
{
    int waitforcomplete;

    waitforcomplete=0;
    imclient_send(imclient, markdone, &waitforcomplete, "NOOP");
    while (!waitforcomplete) {
	imclient_processoneevent(imclient);
    }
}

/*
 * Allocate and build a bboard struct for the named IMAP mailbox.
 * Creates a new IMAP copnnection to the server, fetches name and date
 * information and builds a sorted message list. the inuse and alloced
 * members do not take the sentinel into account.
 */
int getimap( struct imclient *imclient, char *bbd,bboard *imapbbd)
{
    int waitforcomplete,i;

    strcpy(imapbbd->name, bbd);
    imapbbd->alloced=-1;
    imapbbd->inuse=-2;
    imclient_addcallback(imclient,
			 "EXISTS", CALLBACK_NUMBERED , processexists, imapbbd,
			 "FETCH", CALLBACK_NUMBERED, processfetch, imapbbd,
			 NULL);

    waitforcomplete=0;
    imclient_send(imclient, markdone, &waitforcomplete, "SELECT %s", bbd);
    while (!waitforcomplete) {
	imclient_processoneevent(imclient);
    }

    if (waitforcomplete != 1) {
	fprintf(stderr,"Select of %s failed\n",bbd);
	return 1;
    }

    if (imapbbd->alloced == -1) {
	fprintf(stderr,"Select of %s did not elicit EXISTS response,",bbd);
	fprintf(stderr," does bboard exist?\n");
	return 1;      
    }

    imapbbd->inuse=-1;
    imapbbd->msgs=(message *)xmalloc((imapbbd->alloced+1) * sizeof (message));

    if (imapbbd->alloced > 0) {
	waitforcomplete=0;
	imclient_send(imclient, markdone, &waitforcomplete,
		      "FETCH 1:%d (internaldate uid)", imapbbd->alloced);
	while (!waitforcomplete) {
	    imclient_processoneevent(imclient);
	}
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
	fprintf(logfile,"There are %d messages in %s\n",
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
    return 0;
}

/*
 * Marks the passed message deleted. This sends a command to
 * the imap server, but does not wait for a response. the passed
 * buffer is so that errcheck can print useful error messages
 */
void DeleteIMAP(struct imclient * imclient, char *name, message *msg)
{
    char *buf;
    if (verbose) fprintf(logfile,"Delete\n");
  
    buf=xmalloc(256);
    sprintf(buf, "Delete %s in %s", msg->name,name);
  
    imclient_send(imclient, errcheck, buf,
		  "uid store %a +flags.silent (\\Deleted)", msg->name);
}

/*
 * Unscribe and append the AMS message to the IMAP mailbox
 */
#define ALLOCSLOP 4096
int UploadAMS(struct imclient *imclient, char *name, char *amsdir, message
               *msg)  
{
    FILE *msgf, *tmpf;
    char *allmsg, *withcrnl, buf[1025], amsfile[MAXPATHLEN], *descbuf;
    char *startline, *p, *q, *r; 
    int withcrnllen, withcrnlsize;
    int len, rc, gmtnegative, scribeval, done, unscribe;
    int gmtoff, inheaders;
    struct tm *tm;
    struct stat statbuf;
    struct ScribeState *scribestate;

    strcpy(amsfile,amsdir);
    strcat(amsfile,"/");
    strcat(amsfile,msg->name);
    
    tmpf=NULL;
    scribeval=0;
    len=0; 
    if (verbose) fprintf(logfile,"Add\n");

    /* First, allocate a buffer large enough to hold the entire message */
    
    msgf=fopen(amsfile,"r");
    if (!msgf) {
	perror(amsfile);
        fprintf(stderr, "Couldn't open message\n");
        return 1;
        
    }
    if (fstat(fileno(msgf), &statbuf) == -1) {
	perror(amsfile);
	fclose(msgf);
        fprintf(stderr, "Couldn't stat message\n");
        return 1;        
    }
    allmsg=xmalloc(statbuf.st_size+1);
    memset(allmsg, 0, statbuf.st_size+1);
    allmsg[0]='\0';
    done=0;
    unscribe=0;

    /* Read header lines , and try to find any Content-Type headers */
    while (!done) {
	if (fgets(&buf[0], 1024, msgf) == 0) {
	    /* No body, add separator */
	    len=strlen(allmsg);
	    allmsg[len++] = '\n';
	    allmsg[len] = '\0';
	    break;
        }
	/* If a BE2 message, pass the version number into UnScribeInit */
	if (!strncmp(buf, "Content-Type: X-BE2", 19)) {
	    r=&buf[strlen(buf)-2];
	    buf[strlen(buf)-1]=0;
	    if ((scribeval = UnScribeInit(&buf[20], &scribestate)) < 0) {
		fprintf(stderr, "Unknown scribe version \"%s\"\n",
			&buf[20]);
		fprintf(stderr, "Not Unscribing %s\n", amsfile);
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
	tmpf=tmpfile();
	if (tmpf == NULL) {
	    fprintf(stderr, "Can't open temporary file\n");
	    return 1;
	}
	rc=fwrite(allmsg, 1, len, tmpf);
	if (rc == -1) {
	    fclose(tmpf);
	    fclose(msgf);
	    fprintf(stderr, "Couldn't write headers to temp file\n");
	    return 1;
	}
	if (rc < len) {
	    fprintf(stderr, "Short write of headers to temp file\n");
	    return 1;
	}
	/* Read the formatted body into the buffer. It will fit. */
	rc=fread(allmsg,1, statbuf.st_size - len+1, msgf);
	if (rc == -1) {
	    perror(amsfile);
	    fclose(msgf);
	    fclose(tmpf);
	    fprintf(stderr, "Couldn't read message\n");
	    return 1;
	}      
	if (rc < statbuf.st_size - len) {
	    fprintf(stderr, "Short read (%d/%ld) of message %s\n",rc ,
		    statbuf.st_size - len, amsfile);
	    return 1;
	}
	fclose(msgf);
	/* Call UnScribe and UnScribeFlush */
	rc=UnScribe(scribeval, &scribestate, allmsg, rc, tmpf);
	if (rc == -1) {
	    fclose(tmpf);
	    fprintf(stderr, "Unable to write UnScribed message\n");
	    return 1;
	}      
	if (rc < 0) {
	    fclose(tmpf);
	    fprintf(stderr,"UnScribe failed!\n");
            return 1;            
	}
	rc=UnScribeFlush(scribeval, &scribestate, tmpf);
	if (rc < 0) {
	    fclose(tmpf);
            fprintf(stderr, "UnScribeFlush failed!\n");
            return 1;           
	}
	/* Reallocate message buffer and read whole unformatted message in */
	rewind(tmpf);
	free(allmsg);
	if (fstat(fileno(tmpf), &statbuf) == -1) {
	    fclose(tmpf);
	    fprintf(stderr, "Couldn't stat temp file\n");
	    return 1;
	}
	allmsg=xmalloc(statbuf.st_size+1);
	memset(allmsg, 0, statbuf.st_size+1);
    
	rc=fread(allmsg,1, statbuf.st_size, tmpf);
	if (rc == -1) {
	    fclose(tmpf);
	    fprintf(stderr, "Couldn't read temp file\n");
	    return 1;
	}      
	if (rc < statbuf.st_size) {
	    fprintf(stderr, "Short read (%d/%d) of temp file\n",rc ,
		    (int) statbuf.st_size); 
	}
	fclose(tmpf);
    }
    else {
	/* Not BE2, just read the whole thing in. */
	rewind(msgf);
	rc=fread(allmsg,1, statbuf.st_size, msgf);
	if (rc == -1) {
	    fclose(tmpf);
	    fprintf(stderr, "Couldn't read message file\n");
	    return 1;
	}      
	if (rc < statbuf.st_size) {
	    fprintf(stderr, "Short read (%d/%d) of message file\n",rc ,
		    (int) statbuf.st_size);
	    return 1;
	}
	fclose(msgf);
    }

    /*
     * Now copy each line of the message into a new buffer, adding CR's
     * where neccesarry for RFC822 compliance.
     */
    withcrnlsize = statbuf.st_size + ALLOCSLOP;
    withcrnllen = 0;
    withcrnl = xmalloc(withcrnlsize);
    startline = allmsg;
    inheaders = 1;
    while ((p = strchr(startline,'\n'))) {
	if (withcrnllen + (int)(p-startline) + 4 > withcrnlsize) {
	    withcrnlsize += (int)(p-startline) + ALLOCSLOP;
	    withcrnl = xrealloc(withcrnl, withcrnlsize);
	}
	if (*startline == '\n') inheaders = 0;
	if (inheaders) {
	    /* Strip 8-bit data */
	    for (q = startline; q < p; q++) {
		if (*q & 0x80) *q &= 0x7f;
	    }

	    /* If not a valid header, make a header continuation line */
	    if (*startline == ':') withcrnl[withcrnllen++] = ' ';
	    else if (*startline != ' ' && *startline != '\t') {
		for (q = startline; *q != ':'; q++) {
		    if (*q <= ' ') break;
		}
		if (*q != ':') withcrnl[withcrnllen++] = ' ';
	    }
	}

	strncpy(withcrnl+withcrnllen, startline, (int)(p-startline));
	withcrnllen += (int)(p-startline);
	if (withcrnllen && withcrnl[withcrnllen-1] == '\r') withcrnllen--;
	withcrnl[withcrnllen++] = '\r';
	withcrnl[withcrnllen++] = '\n';
	startline = p+1;
    }
    if (inheaders) {
	/* Add delimiting blank line */
	if (withcrnllen + 4 > withcrnlsize) {
	    withcrnlsize += (int)(p-startline) + ALLOCSLOP;
	    withcrnl = xrealloc(withcrnl, withcrnlsize);
	}
	withcrnl[withcrnllen++] = '\r';
	withcrnl[withcrnllen++] = '\n';
    }	
    withcrnl[withcrnllen++] = '\0';
    /* Generate timestamp string for IMAP internaldate */
    gmtoff = gmtoff_of((tm=localtime(&msg->stamp)), msg->stamp);
    gmtnegative = 0;
    if (tm->tm_year < 80) {
	fprintf(stderr, "Invalid time stamp %ld in message %s\n",
		msg->stamp, msg->name);
	free(withcrnl);
	free(allmsg);
	free(amsfile);
	return 0;
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
    if (debug >=2)
       printf("Setting time to %s\n", buf);
    
    /* informative message for errcheck */
    descbuf=xmalloc(1024);
    sprintf(descbuf, "Append of %s%s to %s", unscribe ? "unscribed " : "",
	    amsfile, name);
    
    imclient_send(imclient, errcheck, descbuf,
		  "APPEND %s \"%a\" %s", name, buf, withcrnl);
    
    free(withcrnl);
    
    free(allmsg);
    return 0;
}
