/* 
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
 */

/* $Id: fud-client.c,v 1.4 2002/05/25 19:57:43 leg Exp $ */

/*  This is an example client for the experimental fud service. 
    For this to work, the mailbox must have the local ACL bit 0 enabled
    for user 'anonymous' ('anyone' will also work)
    For example, from cyradm:  'sam <mailbox> anonymous 0'
*/


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <signal.h>
#include <netdb.h>
#include <unistd.h>
#include <sysexits.h>
#include <stdio.h>

extern int optind;
extern char *optarg;

void
usage()
{
	fprintf(stderr,"usage: fud-client [-p port] host user mailbox\n");
	exit(EX_USAGE);
}

void
timeout(signo)
int signo;
{
	fprintf(stderr,"fud-client: request timed out.\n");
	exit(EX_UNAVAILABLE);
}

int
main(argc, argv)
int argc; 
char **argv;
{
	int soc,x,rc;
	struct sockaddr_in sin,sfrom;
	struct hostent *hp;
	fd_set fset;
	char buf[512];
	time_t lread, lappend;
	int numrecent;
	char username[16];
	char mbox[512];
	char time[35];
	int port = 4201;
	char ch,*hname;
	
	
	while ((ch = getopt(argc,argv,"p:")) != -1) {
		switch(ch) {
			case 'p':
				port = atoi(optarg);
				break;
			case '?':
				usage();
		}
	}
	argc -= optind;
	argv += optind;

	
	if(!*argv)  
		usage();
	hname = *argv;
	argv++;
	if(!*argv)  
		usage();
	strcpy(username,*argv);
	argv++;
	if(!*argv)  
		usage();
	strcpy(mbox,*argv);

	soc = socket(PF_INET,SOCK_DGRAM,0);

	hp = gethostbyname(hname);
	if(hp == (struct hostent*) 0) {
		fprintf(stderr,"%s doesn't appear to be a valid hostname.\n",hname);
		exit(EX_NOHOST);
	}
	memcpy(&sin.sin_addr.s_addr,hp->h_addr,hp->h_length);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	
	sprintf(buf,"%s|%s",username,mbox);
	sendto(soc,buf,strlen(buf),0,(struct sockaddr *)&sin,sizeof(sin));

	signal(SIGALRM,timeout);
	alarm(5);
	x = sizeof(sfrom);
	rc = recvfrom(soc,buf,512,0,(struct sockaddr *)&sfrom,&x);
	alarm(0);
	buf[rc] = '\0';
	switch(buf[0]) {
		case 'U':
			printf("Server did not recognize mailbox %s\n",mbox);
			exit(EX_UNAVAILABLE);
		case 'P':
			printf("Permission denied attempting get mailbox info for %s\n",mbox);
			exit(EX_NOPERM);
		default:
			sscanf(buf,"%[^|]|%[^|]|%d|%d|%d", username, mbox, &numrecent, &lread, &lappend);
			printf("user: %s\nmbox: %s\nNumber of Recent %d\n", username, mbox, numrecent);
			strcpy(time,ctime(&lread));
			printf("Last read: %s", time);
			strcpy(time,ctime(&lappend));
			printf("Last arrived: %s", time);
	}
	return(0);
}

