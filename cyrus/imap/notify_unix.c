/* notify_unix.c -- Module to send notifications to Unix socket-based server
 *    Copyright (c) 2000-2001, Jeremy Howard, j@howard.fm
 */


#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include "imapconf.h"
#include "retry.h"
#include "notify.h"

const char *notify_method_desc = "unix";

#define FNAME_NOTIFY_SOCK "/socket/notify"

void notify(const char *class,
	    const char *instance,
	    const char *user,
	    const char *mailbox,
	    const char *message)
{
    char buf[80];
    const char *notify_sock;
    struct sockaddr myname;

    int   sock, addrlen, cnt;
    fd_set read_template, write_template; 
    struct timeval wait; 

    int fdflags;
    struct iovec iov[20];
    int num_iov;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
	syslog(LOG_ERR, "notify_unix: socket(): %m");
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
    addrlen = strlen(myname.sa_data) + sizeof(myname.sa_family);
    
    /* put us in non-blocking mode */
    fdflags = fcntl(sock, F_GETFD, 0);
    if (fdflags != -1) fdflags = fcntl(sock, F_SETFL, O_NONBLOCK | fdflags);
    if (fdflags == -1) { 
	syslog(LOG_ERR, 
	       "notify_unix: setting socket to nonblocking: fcntl(): %m");
	close(sock); 
	return; 
    }

    if (connect( sock, &myname, addrlen) < 0) {
	syslog(LOG_ERR, "notify_unix: connect(): %m");
	return;
    }

    /*  . . . . .  */

    num_iov = 0;

    WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) class);
    WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, "\n");
    WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) instance);
    WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, "\n");
    WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) user);
    WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, "\n");
    WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) mailbox);
    WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, "\n");
    WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) message);
    WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, "\n");
    cnt = retry_writev(sock, iov, num_iov);

    if (cnt < 0) {
	syslog(LOG_ERR, "notify_unix: retry_writev(): %m");
    }

    close(sock);
}
