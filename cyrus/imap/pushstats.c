
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include "pushstats.h"
    
#define SOCK_PATH "/tmp/imapd_log_socket"

int pushstats_socket = -1;
struct sockaddr_un pushstats_remote;


int pushstats_connect(void)
{
    int s, len;


    if ((s = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
	return 1;
    }

    pushstats_remote.sun_family = AF_UNIX;
    strcpy(pushstats_remote.sun_path, SOCK_PATH);
    len = strlen(pushstats_remote.sun_path) + sizeof(pushstats_remote.sun_family);

    /* put us in non-blocking mode; xxx this clobbers existing flags */
    /*    fcntl(s, F_SETFL, O_NONBLOCK); */

    pushstats_socket = s;

    return 0;
}

int pushstats_close(void)
{
    if (pushstats_socket > -1)
	close(pushstats_socket);

    return 0;
}

int pushstats_log(pushstats_t cmd)
{
    int len;
    char tosend[100];

    if (pushstats_socket == -1) return 1;

    /* xxx is this 64bit compat? */
    memcpy(tosend, &cmd, sizeof(cmd));

    strcpy(tosend+sizeof(cmd),"\n");

    len = strlen(pushstats_remote.sun_path) + sizeof(pushstats_remote.sun_family);

    if (sendto(pushstats_socket, tosend, 
	       sizeof(cmd)+strlen(tosend+sizeof(cmd)), 0, 
	       (struct sockaddr *) &pushstats_remote, len) == -1) {
	return 1;
    }

    return 0;
}

static char pushstats_names[PUSHSTATS_MAXCMDS][20] = 
{{"AUTHENTICATE"}, /* 0 */
 {"APPEND"},
 {"BBOARD"},
 {"CAPABILITY"},
 {"CHECK"},
 {"COPY"},
 {"CREATE"},
 {"CLOSE"},
 {"DELETE"},
 {"DELETEACL"},
 {"EXPUNGE"},
 {"EXAMINE"},
 {"FETCH"},
 {"FIND"},
 {"GETACL"},
 {"GETQUOTA"},
 {"GETQUOTAROOT"},
 {"GETUIDS"},
 {"LOGIN"},
 {"LOGOUT"},
 {"LIST"},
 {"LSUB"},
 {"LISTRIGHTS"},
 {"MYRIGHTS"},
 {"NOOP"},
 {"NAMESPACE"},
 {"PARTIAL"},
 {"RENAME"},
 {"STARTTLS"},
 {"STORE"},
 {"SELECT"},
 {"SEARCH"},
 {"SUBSCRIBE"},
 {"SETACL"},
 {"SETQUOTA"},
 {"STATUS"},
 {"UNSUBSCRIBE"},
 {"UNSELECT"}}; /* 37 */

char* pushstats_getname(pushstats_t cmd)
{
    if ((cmd <0) || (cmd>37)) return "";

    return pushstats_names[cmd];
}
