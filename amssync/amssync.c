/* amssync.c -- synchronize AMS bboard into IMAP
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/time.h>
#include <string.h>
#include <sysexits.h>

#include "xmalloc.h"
#include "amssync.h"

int cmpmsg(const message *m1, const message *m2)
{
    return (m1->stamp - m2->stamp);
}

void fatal(char *msg, int exitvalue)
{
    fputs(msg, stderr);
    fflush(stderr);
    exit(exitvalue);
}

/*
 * Free a bboard struct, calling the appropriate hooks if neccesarry
 */
int freebbd(bboard *bbd)
{
    if (bbd->internalfreeproc) {
	(*bbd->internalfreeproc)(bbd->internaldata);
    }
    free(bbd->msgs);
    free(bbd);
    return 0;
}

int debug=0,verbose=0;

int main(int argc, char *argv[])
{
    time_t timediff;
    bboard *amsbbd,*imapbbd;
    register message *amsmsg, *imapmsg;
    int amsidx, imapidx,done,arg,swarg;
    char *imapname, *server, *port;

    if (argc < 3) {
	fprintf(stderr,
		"Usage: amssync [-d] [-v] amsdir bbname [server [port]]\n");
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
	setvbuf(stdout,NULL,_IONBF,0);
	arg++;
	swarg++;
    }
    amsbbd=getams(argv[arg++]);
    imapname=argv[arg++];
    if (argc - swarg > 3) {
	server=argv[arg++];
    }

    if (argc - swarg > 4) {
	port=argv[arg++];
    }
    else {
	port=NULL;
    }

    if (argc - swarg> 3) {
	setimapser(server,port);
    }
  
    imapbbd=getimap(imapname);
    amsidx=imapidx=0;
    done=0;
    /*
     * lookp over sorted lists. if the timestamps are mismatched, a
     * message needs to be moved/removed. If "Tried <something> sentinel
     * <num>" ever appears, it means there's still a bug here.
     */
    while (!done) {
	amsmsg=&amsbbd->msgs[amsidx];
	imapmsg=&imapbbd->msgs[imapidx];   
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
		DeleteIMAP(imapbbd, imapmsg);
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
		UploadAMS(imapbbd, amsbbd, amsmsg);
		if (debug) {
		    printf("Uploaded %s\n",amsmsg->name);
		}
		amsidx++;
	    } else {
		printf("Tried uploading sentinel %d\n",amsidx);
	    }
	}
      
	if (amsidx > amsbbd->inuse   && imapidx > imapbbd->inuse) {
	    done=1; /* reached the end of both lists, so terminate */
	}
	else if (amsidx > amsbbd->inuse ) {
	    /* Reached the end of the AMS list. remove all of the
	     * remaining IMAP messages
	     */
	    while (imapidx <= imapbbd->inuse) {
		if (imapbbd->msgs[imapidx].stamp != 0x7fffffff) {
		    DeleteIMAP(imapbbd, imapbbd->msgs[imapidx]);
		    if (debug) {
			printf("comparing <NULL> <NULL> %ld\n",
			       imapbbd->msgs[imapidx].stamp);
			printf("Deleted %s\n",imapbbd->msgs[imapidx].name);
		    }
		    imapidx++;
		} else {
		    fprintf(stderr, "Tried deleting sentinel %d\n",imapidx);
		}
	    }
	    done=1;
	}
	else if (imapidx > imapbbd->inuse) {
	    /* Reached the end of the IMAP list. Upload the
	     * remaining AMS messages
	     */
	    while (amsidx <= amsbbd->inuse) {
		if (amsbbd->msgs[amsidx].stamp != 0x7fffffff) {
		    if (debug) {
			printf("comparing <NULL> %ld <NULL>\n",
			       amsbbd->msgs[amsidx].stamp); 
			printf("Uploaded %s\n",amsbbd->msgs[amsidx].name);
		    }
		    UploadAMS(imapbbd, amsbbd, amsbbd->msgs+amsidx);
		    amsidx++;
		} else {
		    printf("Tried uploaing sentinel %d\n",amsidx);
		}
	    }
	    done=1;
	}
    }
    if (verbose) printf("\n");
    freebbd(amsbbd);
    freebbd(imapbbd);
    exit(EX_OK);
}
