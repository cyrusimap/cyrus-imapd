/* fud-client.c */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
        (void)signo;
        fprintf(stderr,"fud-client: request timed out.\n");
        exit(EX_UNAVAILABLE);
}

int
main(argc, argv)
int argc;
char **argv;
{
        int soc,rc;
        unsigned int x;
        struct sockaddr_in sin,sfrom;
        struct hostent *hp;
        fd_set fset;
        char buf[512];
        time_t lread, lappend;
        uint32_t lread32, lappend32;
        int numrecent;
        char username[16];
        char mbox[512];
        char time[35];
        int port = 4201;
        char ch, *hname;

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
                        sscanf(buf,"%[^|]|%[^|]|%d|%u|%u", username, mbox,
                               &numrecent, &lread32, &lappend32);
                        lread = (time_t)lread32;
                        lappend = (time_t)lappend32;
                        printf("user: %s\nmbox: %s\nNumber of Recent %d\n",
                               username, mbox, numrecent);
                        strcpy(time, ctime(&lread));
                        printf("Last read: %s", time);
                        strcpy(time, ctime(&lappend));
                        printf("Last arrived: %s", time);
        }
        return(0);
}

