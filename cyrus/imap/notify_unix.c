/* notify_unix.c -- Module to send notifications to socket-based server
   Copyright (c) 2000, Jeremy Howard
*/


#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include "imapconf.h"

extern const char *config_getstring(const char *key, const char *def);
extern int config_getint(const char *key,int def);

#define SOCKFILE config_getstring("notify_socket","/tmp/notify_unix")
#define DIRSIZE 8192

void notify(const char *class,
	    const char *instance,
	    const char *user,
	    const char *mailbox,
	    const char *message)
{
       
    char messageToSend[2048];
    char dir[DIRSIZE];

    char buf[80];
    struct sockaddr myname;

    int   sock, adrlen, cnt;
    fd_set read_template, write_template; 
    struct timeval wait; 

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
	syslog(LOG_ERR, "client socket failure %d\n", errno);
	return;
    }

    myname.sa_family = AF_UNIX;
    strcpy(myname.sa_data, SOCKFILE);
    adrlen = strlen(myname.sa_data) +
	sizeof(myname.sa_family);

    if (connect( sock, &myname, adrlen) < 0) {
	syslog(LOG_ERR, "client connect failure %d\n", errno);
	return;
    }
    /*  . . . . .  */

    memset( messageToSend, 0, sizeof(messageToSend));
    sprintf (messageToSend,"%s\n%s\n%s\n%s\n%s\n",class,instance,user,mailbox,message);
    cnt = write(sock, messageToSend, strlen(messageToSend));

    close(sock);
}
