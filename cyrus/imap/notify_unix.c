/* notify_unix.c -- Module to send notifications to Unix socket-based server
 *    Copyright (c) 2000-2001, Jeremy Howard, j@howard.fm
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
#include "notify.h"

const char *notify_method_desc = "unix";

#define FNAME_NOTIFY_SOCK "/socket/notify"
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
    const char *notify_sock;
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
    notify_sock = config_getstring("notifysocket", NULL);
    if (notify_sock) {	
	strcpy(myname.sa_data, notify_sock);
    }
    else {
	strcpy(myname.sa_data, config_dir);
	strcat(myname.sa_data, FNAME_NOTIFY_SOCK);
    }
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
