
#include <config.h>

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
#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>



#include "xmalloc.h"
#include "config.h"
#include "acapmbox.h"
#include "acappush.h"
#include <acap.h>

/* if disconnected and can't reconnect right away how long to wait until retrying */
#define RECONNECT_TIME (10*60)

typedef enum {
    CONNECTED,
    DISCONNECTED,
    LAST_CONNECT_FAILED
} connected_t;

acapmbox_handle_t *handle;

#define HASHSIZE 107

typedef struct hashentry_s {
    acapmbdata_t data;
    struct hashentry_s *next;
} hashentry_t;

typedef struct hashtb_s {

    hashentry_t *items[HASHSIZE];    

    int total_exists;

} hashtb_t;

hashtb_t hashtable;

static int hash_simple (const char *str)
{
    int     value = 0;
    int     i;

    if (!str)
	return 0;
    for (i = 0; *str; i++)
    {
	value ^= (*str++ << ((i & 3)*8));
    }
    return value % HASHSIZE;
}

void queueitem(acapmbdata_t *item)
{
    int hashval;
    hashentry_t *newentry;
    hashentry_t *e;

    hashval = hash_simple(item->name);

    /* see if entry for this already exists */
    e = hashtable.items[hashval];
	
    while (e!=NULL)
    {
	if (strcmp(e->data.name,item->name)==0)
	    break;

	e=e->next;
    }

    if (e!=NULL) {

	/* overwrite existing */
	memcpy(&(e->data), item, sizeof(acapmbdata_t));

    } else {

	/* make new entry */   
	newentry = xmalloc(sizeof(hashentry_t));
	memcpy(&(newentry->data), item, sizeof(acapmbdata_t));
    
	/* insert into hash table */	
	newentry->next = hashtable.items[hashval];
	hashtable.items[hashval] = newentry;

	hashtable.total_exists++;
    }
}

char *local_create_full_dataset_name(char *mailbox_name)
{
    static char fullname[MAX_MAILBOX_PATH];

    /* needs to convert from mUTF7 to UTF-8 */
    snprintf(fullname, sizeof(fullname), "%s/%s", 
	     global_dataset, mailbox_name);

    return fullname;
}

int senditem(acap_conn_t *acapconn, acapmbdata_t *item)
{
    int result;
    char *fullname;
    acap_cmd_t *cmd;
    acap_entry_t *newentry;
    char tmpstr[30];

    /* get the entry path */
    fullname = local_create_full_dataset_name(item->name);
    if (fullname == NULL) return ACAP_NOMEM;

    newentry = acap_entry_new(fullname);
    if (newentry == NULL) return ACAP_NOMEM;

    /* make and insert all our attributes */
    snprintf(tmpstr, sizeof(tmpstr), "%d", item->uidvalidity);
    add_attr(newentry->attrs, "mailbox.uidvalidity", tmpstr);

    snprintf(tmpstr, sizeof(tmpstr), "%d", item->answered);
    add_attr(newentry->attrs, "mailbox.answered", tmpstr);

    snprintf(tmpstr, sizeof(tmpstr), "%d", item->flagged);
    add_attr(newentry->attrs, "mailbox.flagged", tmpstr);

    snprintf(tmpstr, sizeof(tmpstr), "%d", item->deleted);
    add_attr(newentry->attrs, "mailbox.deleted", tmpstr);

    snprintf(tmpstr, sizeof(tmpstr), "%d", item->exists);
    add_attr(newentry->attrs, "mailbox.total", tmpstr);

    /* create the cmd; if it's the first time through, we ACAP_STORE_INITIAL */
    result = acap_store_entry(acapconn,
			      newentry,
			      NULL,
			      NULL,
			      0,
			      &cmd);

    if (result == ACAP_OK)
	result = acap_process_on_command(acapconn, cmd, NULL);

    return result;    
}

void sendsomequeued(acap_conn_t *acapconn, int num)
{
    int spot = rand() % HASHSIZE;
    hashentry_t *e, *next;
    int result;
    int lup;
	    
    if (num > hashtable.total_exists)
	num = hashtable.total_exists;

    for (lup=0;lup<num;lup++)
    {
	/* find an entry */
	while (hashtable.items[spot]==NULL)
	    spot++;

	/* pop it */
	next = hashtable.items[spot]->next;
	e = hashtable.items[spot];	
	hashtable.items[spot]=next;
	hashtable.total_exists--;

	/* send it */
	result = senditem(acapconn, &(e->data));

	/* if failure just requeue item and quit */
	if (result!=ACAP_OK) {	    
	    queueitem(&(e->data));
	    free(e);
	    return;
	}
	free(e);
    }
}


void fatal(const char *msg, int err)
{
    printf("dieing with %s %d\n",msg,err);
    exit(1);
}

acap_conn_t *connect_acap(void)
{
    acap_conn_t *acap_conn;

    handle = acapmbox_get_handle();

    if (!handle) return NULL;

    acap_conn = acapmbox_get_acapconn(handle);

    return acap_conn;
}

int main(void)
{
    int s, len;
    struct sockaddr_un local;
    char str[sizeof(acapmbdata_t)];
    struct sockaddr_un from;
    int fromlen;
    mode_t oldumask;
    connected_t connected = DISCONNECTED;
    int acapsock = -1;
    fd_set read_set, rset;
    int nfds;
    int r;
    int lup;
    acap_conn_t *acap_conn = NULL;
    struct timeval timeout;
    time_t when_disconnected = 0;

    /* timeout for select is 1 minute */
    timeout.tv_sec = 60;
    timeout.tv_usec = 0;

    config_init("acaplistener");

    /* initialize the hash table */
    hashtable.total_exists = 0;
    for (lup=0;lup<HASHSIZE;lup++)
	hashtable.items[lup] = NULL;

    /* create socket we are going to use */
    if ((s = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
	perror("socket");
	exit(1);
    }

    /* bind it to a local file */
    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, ACAPPUSH_PATH);
    unlink(local.sun_path);
    len = strlen(local.sun_path) + sizeof(local.sun_family);

    oldumask = umask((mode_t) 0); /* for Linux */

    if (bind(s, (struct sockaddr *)&local, len) == -1) {
	perror("bind");
	exit(1);
    }
    umask(oldumask); /* for Linux */
    chmod(ACAPPUSH_PATH, 0777); /* for DUX */



    /* get ready for select() */
    FD_ZERO(&read_set);
    FD_SET(s, &read_set);
    nfds = s + 1;

    for (;;) {
	int n;

	/* process any outstanding ACAP stuff */
	switch(connected)
	    {
	    case CONNECTED:
		r = acap_process_outstanding(acap_conn);
		if (r != ACAP_OK) syslog(LOG_ERR, "acap_process_outstanding(): %s",
					 error_message(r));
		if (r == ACAP_NO_CONNECTION)
		{
		    connected = DISCONNECTED;
		    FD_CLR(acapsock, &read_set);
		    nfds = s+1;
		}
		break;
	    case DISCONNECTED:

		acap_conn = connect_acap();
		if (acap_conn != NULL) {
		    acapsock = acap_conn_get_sock(acap_conn);	    
		    connected = CONNECTED;
		    
		    FD_SET(acapsock, &read_set);
		    if (acapsock+1 > nfds) nfds = acapsock + 1;
		    
		} else {
		    connected = LAST_CONNECT_FAILED;
		    when_disconnected = time(NULL);
		}
		break;
	       
	    case LAST_CONNECT_FAILED:

		if ( time(NULL) - when_disconnected >= RECONNECT_TIME)
		{
		    /* try to connect next time */
		    connected = DISCONNECTED;
		}
		break;

	    default:
		syslog(LOG_ERR,"Bad state");
		fatal("Bad state exiting",-1);
		break;
	}

	/* check for the next input */
	rset = read_set;
	n = select(nfds, &rset, NULL, NULL, &timeout);
	if (n < 0 && errno == EAGAIN) continue;
	if (n < 0 && errno == EINTR) continue;
	if (n == -1) {
	    /* uh oh */
	    syslog(LOG_ERR, "select(): %m");
	    close(s);
	    fatal("select error",-1);
	}

	/* read on unix socket */
	if (FD_ISSET(s, &rset)) {

	    fromlen = sizeof(from);
	    
	    memset(str,'\0',sizeof(str));
	    
	    n = recvfrom(s, str, sizeof(str), 0, (struct sockaddr *) &from, &fromlen);
	    str[n]  = '\0';
	    
	    switch(connected)
		{
		case CONNECTED:
		    if (hashtable.total_exists > 0)
		    {
			queueitem((acapmbdata_t *) str);
			sendsomequeued(acap_conn, 5);
		    } else {
			if (senditem(acap_conn,(acapmbdata_t *)str)!=ACAP_OK)
			    queueitem((acapmbdata_t *) str);
		    }

		    break;
		default:
		    queueitem((acapmbdata_t *)str);
		    break;
		    
		}
	    		
	    } else {
		/* log some sort of error */	    
	    }
    }

    /* never gets here */      
    exit(1);
}
