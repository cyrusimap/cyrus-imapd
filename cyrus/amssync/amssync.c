/* amssync.c -- synchronize AMS bboard into IMAP
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/time.h>
#include <string.h>
#include <sysexits.h>

#include "acte.h"
#include "imclient.h"
#include "xmalloc.h"
#include "amssync.h"

extern struct acte_client krb_acte_client;
struct acte_client *login_acte_client[] = {
    &krb_acte_client,
    NULL
};
int cmpmsg(const message *m1, const message *m2)
{
    return (m1->stamp - m2->stamp);
}

void fatal(char *msg, int exitvalue)
{
    fputs(msg, stderr);
    fflush(stderr);
    printf("Aborted\n");    
    exit(exitvalue);
}

int debug=0,verbose=0;

int main(int argc, char *argv[])
{
    char *server, *port=NULL;
    char *imapser="cyrus.andrew.cmu.edu";
    struct imclient * imclient;
    int ilen,imaplen,arg,swarg;

    char amsname[MAXPATHLEN+1];
    char intstr[16];
    
    char imapname[MAXPATHLEN];
        
    if (argc < 3) {
	fprintf(stderr,
		"Usage: amssync [-d] [-v] [server [port]]\n");
	exit(EX_USAGE);
    }
    swarg=0;
    arg=1;
  
    if (!strcasecmp(argv[arg], "-d")) {
	debug=1;
	arg++;
	swarg++;
    }
    if (!strcasecmp(argv[arg], "-v")) {
	verbose=1;
	arg++;
	swarg++;
    }
    server=imapser;
    if (argc - swarg > 2) {
	server=argv[arg++];
    }

    if (argc - swarg > 4) {
	port=argv[arg++];
    }

    if (imclient_connect(&imclient,server,port)) {
	fatal("couldn't find server\n", EX_NOHOST);
    }
    if (imclient_authenticate(imclient,login_acte_client,NULL,ACTE_PROT_ANY)) {
	fatal("couldn't auth to server\n", EX_UNAVAILABLE);
    }
    while (1) {
        if (!fgets(amsname,MAXPATHLEN+1,stdin))
            break;
        if (!fgets(imapname,MAXPATHLEN,stdin)) /* In order to be able to
                                                  construct AMS name in the
                                                  first place, bboard name
                                                  length is < MAXPATHLEN */ 
            fatal("Premature EOF on stdin\n",EX_SOFTWARE);
        imapname[strlen(imapname)-1]=0;
        amsname[strlen(amsname)-1]=0;
        
        bbloop(imclient,amsname,imapname);
        do_imap_close(imclient);
        printf("Completed %s\n", imapname);
        fflush(stdout);        

    }
    
    imclient_close(imclient);
    exit(EX_OK);
}

        
        

int bbloop(struct imclient *imclient, char *amsname, char *imapname)
{
    time_t timediff;
    bboard amsbbd,imapbbd;
    register message *amsmsg, *imapmsg;
    int amsidx, imapidx,done,arg,swarg;
    
    
    
    getams(amsname,&amsbbd);    
    getimap(imclient,imapname,&imapbbd);
    amsidx=imapidx=0;
    done=0;
    /*
     * loop over sorted lists. if the timestamps are mismatched, a
     * message needs to be moved/removed. If "Tried <something> sentinel
     * <num>" ever appears, it means there's still a bug here.
     */
    while (!done) {
	amsmsg=&amsbbd.msgs[amsidx];
	imapmsg=&imapbbd.msgs[imapidx];   
	timediff=amsmsg->stamp - imapmsg->stamp;
	if (debug) {
	    printf("comparing %ld %ld %ld\n", timediff,
		   amsmsg->stamp, imapmsg->stamp);
	}

	if (timediff == 0) { /* Same message advance both*/
	    amsidx++;
	    imapidx++;
	}
	else if (timediff > 0) {
	    /* Imap message not in AMS, delete, and
	     * advance to next IMAP message
	     */
	    if (imapmsg->stamp != 0x7fffffff) {
		DeleteIMAP(imclient,imapname, imapmsg);
		if (debug)
		    printf("Deleted %s\n", imapmsg->name);
		imapidx++; 
	    } else {
		printf("Tried deleting sentinel %d\n",imapidx);
	    }
	} else {
	    /* AMS message not in IMAP, upload it and advance to next
	     * AMS message
	     */
	    if (amsmsg->stamp != 0x7fffffff) {
		UploadAMS(imclient, imapname, amsname, amsmsg);
		if (debug) {
		    printf("Uploaded %s\n",amsmsg->name);
		}
		amsidx++;
	    } else {
		printf("Tried uploading sentinel %d\n",amsidx);
	    }
	}
      
	if (amsidx > amsbbd.inuse   && imapidx > imapbbd.inuse) {
	    done=1; /* reached the end of both lists, so terminate */
	}
	else if (amsidx > amsbbd.inuse ) {
	    /* Reached the end of the AMS list. remove all of the
	     * remaining IMAP messages
	     */
	    while (imapidx <= imapbbd.inuse) {
		if (imapbbd.msgs[imapidx].stamp != 0x7fffffff) {
		    DeleteIMAP(imclient, imapname, imapbbd.msgs[imapidx]);
		    if (debug) {
			printf("comparing <NULL> <NULL> %ld\n",
			       imapbbd.msgs[imapidx].stamp);
			printf("Deleted %s\n",imapbbd.msgs[imapidx].name);
		    }
		    imapidx++;
		} else {
		    fprintf(stderr, "Tried deleting sentinel %d\n",imapidx);
		}
	    }
	    done=1;
	}
	else if (imapidx > imapbbd.inuse) {
	    /* Reached the end of the IMAP list. Upload the
	     * remaining AMS messages
	     */
	    while (amsidx <= amsbbd.inuse) {
		if (amsbbd.msgs[amsidx].stamp != 0x7fffffff) {
		    if (debug) {
			printf("comparing <NULL> %ld <NULL>\n",
			       amsbbd.msgs[amsidx].stamp); 
			printf("Uploaded %s\n",amsbbd.msgs[amsidx].name);
		    }
		    UploadAMS(imclient, imapname, amsname, amsbbd.msgs+amsidx);
		    amsidx++;
		} else {
		    printf("Tried uploaing sentinel %d\n",amsidx);
		}
	    }
	    done=1;
	}
    }
    if (verbose) printf("\n");
    free(amsbbd.msgs);
    free(imapbbd.msgs);
    amsbbd.alloced=0;
    amsbbd.inuse=0;
    imapbbd.alloced=0;
    imapbbd.inuse=0;
    
    return 0;
    
}
