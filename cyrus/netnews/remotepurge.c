/*
 * Remotely purge old/too big articles
 */
/*
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 *
 */

#include <config.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>

#include <pwd.h>

#include "prot.h"

#include "imparse.h"
#include "imclient.h"
#include "xmalloc.h"
#include "exitcodes.h"

#include "readconfig.h"

#define SECS_IN_DAY (24*60*60)

#define NOTFINISHED 0
#define IMAP_OK 1
#define IMAP_NO 2
#define IMAP_BAD 3
#define IMAP_EOF 4

/* for statistical purposes */
typedef struct mbox_stats_s {

    int total;         /* total including those deleted */
    int total_bytes;
    int deleted;       
    int deleted_bytes;

} mbox_stats_t;

typedef struct uid_list_s {

    unsigned long *list;
    int allocsize;
    int size;

} uid_list_t;

/* globals for callback functions */
int days = -1;
int size = -1;
int exact = -1;
int pattern = -1;

int current_mbox_exists = 0;

int verbose = 0;
static int noop = 0;
char *username = NULL;
char *authname = NULL;
char *realm = NULL;

struct imclient *imclient_conn;

static int cmd_done;
static char *cmd_resp = NULL;

FILE *configstream;

void spew(int level, const char *fmt, ...)
{
    va_list ap;
    char buf[1024];

    if (verbose < level) return;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);

    if (verbose) {
	printf("%s\n", buf);
    }
    syslog(LOG_DEBUG, "%s", buf);
}

/* libcyrus makes us define this */
void fatal(const char *s, int code)
{
    if (cmd_resp) {
	syslog(LOG_ERR, "fatal error: %s (%s)", s, cmd_resp);
	fprintf(stderr, "fatal error: %s (%s)\n", s, cmd_resp);
    } else {
	syslog(LOG_ERR, "fatal error: %s", s);
	fprintf(stderr, "fatal error: %s\n", s);
    }
    exit(code);
}

/***********************
 * Parse a mech list of the form: ... AUTH=foo AUTH=bar ...
 *
 * Return: string with mechs seperated by spaces
 *
 ***********************/

typedef struct capabilies_s {

  char *mechs;
  
  /* 0 = false; 1 = true */
  int starttls;
  int logindisabled;

} capabilities_t;



static capabilities_t *parsecapabilitylist(char *str)
{
    char *tmp;
    int num=0;
    capabilities_t *ret=(capabilities_t *) xmalloc(sizeof(capabilities_t));
    ret->mechs = (char *)xmalloc(strlen(str)+1);
    ret->starttls=0;
    ret->logindisabled=0;

    /* check for stattls */
    if (strstr(str,"STARTTLS")!=NULL) {
	ret->starttls=1;
    }

    /* check for login being disabled */
    if (strstr(str,"LOGINDISABLED")!=NULL) {
	ret->logindisabled=1;
    }

    strcpy(ret->mechs,"");

    while ((tmp=strstr(str,"AUTH="))!=NULL) {
	char *end=tmp+5;
	tmp+=5;

	while(((*end)!=' ') && ((*end)!='\0'))
	    end++;

	(*end)='\0';

	/* add entry to list */
	if (num>0)
	    strcat(ret->mechs," ");
	strcat(ret->mechs, tmp);
	num++;

	/* reset the string */
	str=end+1;
    }

    return ret;
}

/*
 * IMAP command completion callback
 */
static void callback_capability(struct imclient *imclient, 
				void *rock,
				struct imclient_reply *reply)

{
    char *s;
    capabilities_t **caps = (capabilities_t **) rock;
    
    s = reply->text;

    *caps = parsecapabilitylist(s);
}

/*
 * IMAP command completion callback
 */
static void
callback_finish(struct imclient *imclient,
		void *rock,
		struct imclient_reply *reply)
{
    if (!strcmp(reply->keyword, "OK")) {
	cmd_done = IMAP_OK;
    } else if (!strcmp(reply->keyword, "NO")) {
	cmd_resp = reply->text;
	cmd_done = IMAP_NO;
    }
    else if (!strcmp(reply->keyword, "BAD")) {
	cmd_resp = reply->text;
	cmd_done = IMAP_BAD;
    }
    else if (!strcmp(reply->keyword, "EOF")) {
	syslog(LOG_ERR, "connection closed prematurely");
	cmd_done = IMAP_EOF;
    }
    else {
	printf("Huh?\n");
	cmd_done = IMAP_BAD;
    }
}

/*
 * Callback to deal with untagged LIST/LSUB data
 */
extern void
callback_list(struct imclient *imclient,
	      void *rock,
	      struct imclient_reply *reply);


void print_stats(mbox_stats_t *stats)
{
    syslog(LOG_INFO, "total messages considered %d deleted %d",
	   stats->total, stats->deleted);
    printf("total messages    \t\t %d\n",stats->total);
    printf("deleted messages  \t\t %d\n",stats->deleted);
    printf("remaining messages\t\t %d\n\n",stats->total - stats->deleted);
}

static void
callback_exists(struct imclient *imclient,
	       void *rock,
	       struct imclient_reply *reply)
{
    current_mbox_exists = reply->msgno;
}

static void
callback_search(struct imclient *imclient,
	       void *rock,
	       struct imclient_reply *reply)
{
    uid_list_t *uids = (uid_list_t *) rock;
    char *s;
    unsigned long num;

    s = reply->text;

    while (isdigit((int) *s)) {
	num = 0;
	
	while ((*s!='\0') && (*s!=' '))
	{
	    num = num*10 + (*s-'0');
	    s++;
	}

	if (uids->size >= uids->allocsize)
	{
	    if (uids->allocsize) uids->allocsize *= 2;
	    else uids->allocsize = 250;

	    uids->list = xrealloc(uids->list, 
				  sizeof(unsigned long) * uids->allocsize);
	}

	uids->list[uids->size] = num;
	uids->size++;

	if (*s == '\0') break;
	s++;
    }
   
}

static int send_delete(const char *mbox, const char *uidlist)
{
    imclient_send(imclient_conn, callback_finish, imclient_conn,
		  "UID STORE %a +FLAGS.SILENT (\\Deleted)", uidlist);
    cmd_done = NOTFINISHED;
    while (cmd_done == NOTFINISHED) {
	imclient_processoneevent(imclient_conn);
    }
    if (cmd_done == IMAP_OK) return 0;
    else if (cmd_done == IMAP_NO) {
	syslog(LOG_ERR, "%s can't mark messages deleted: %s", 
	       mbox, cmd_resp ? cmd_resp : "");
	return -1;
    }
    else fatal("marking message deleted", EC_TEMPFAIL);
}

void mark_all_deleted(const char *mbox, uid_list_t *list, mbox_stats_t *stats)
{
    int i;
    char buf[1024];
    int pos;
    unsigned long run_start;
    int first_time;
    unsigned long *A = list->list;
    int r;
    
    if (list->size == 0) return;

    /* we send blocks of 500 or so characters */
    i = 0;

    pos = 0; first_time = 1;
    run_start = A[i++];
    r = 0;
    for (; i < list->size && r == 0; i++) {
	if (A[i] == A[i-1] + 1)
	    continue; /* continue this run */
	if (first_time) {
	    first_time = 0;
	} else {
	    buf[pos++] = ',';
	}
	if (run_start != A[i-1]) {
	    /* run contains more than one entry */
	    pos += sprintf(buf + pos, "%lu:%lu", run_start, A[i-1]);
	} else {
	    /* singleton */
	    pos += sprintf(buf + pos, "%lu", A[i-1]);
	}
	if (pos > 500) {
	    r = send_delete(mbox, buf);
	    pos = 0; first_time = 1;
	}
	run_start = A[i];
    }

    if (!r) {
	/* handle the last entry */
	if (!first_time) {
	    buf[pos++] = ',';
	}
	if (run_start != A[i-1]) {
	    sprintf(buf + pos, "%lu:%lu", run_start, A[i-1]);
	} else {
	    sprintf(buf + pos, "%lu", A[i-1]);
	}
	
	/* send out the last one */
	send_delete(mbox, buf);
	
	stats->deleted += list->size;
    }
}

static char *month_string(int mon)
{
    switch(mon)
	{	    
	    case 0: return "Jan";
	    case 1: return "Feb";
	    case 2: return "Mar";
	    case 3: return "Apr";
	    case 4: return "May";
	    case 5: return "Jun";
	    case 6: return "Jul";
	    case 7: return "Aug";
	    case 8: return "Sep";
	    case 9: return "Oct";
	    case 10: return "Nov";
	    case 11: return "Dec";
	default: return "BAD";
	}
}

/* we don't check what comes in on matchlen and maycreate, should we? */
int purge_me(char *name, time_t when)
{
    mbox_stats_t   stats;
    char search_string[200];
    static uid_list_t uidlist;
    struct tm *my_tm;
    
    if (when == 0) return 0;

    my_tm = gmtime(&when);
    
    snprintf(search_string,sizeof(search_string),
	     "BEFORE %d-%s-%d",
	     my_tm->tm_mday,
	     month_string(my_tm->tm_mon),
	     1900+my_tm->tm_year);

    if (noop) {
	printf("%s: %s\n", name, search_string);
	return 0;
    }

    memset(&stats, '\0', sizeof(mbox_stats_t));
    
    spew(2, "%s selecting", name);

    /* select mailbox */
    imclient_addcallback(imclient_conn,
			 "EXISTS", CALLBACK_NUMBERED, callback_exists,
			 (void *)0, (char *)0);
    imclient_send(imclient_conn, callback_finish, (void *)imclient_conn,
		  "%a \"%s\"", "SELECT", name);		 

    cmd_done = NOTFINISHED;

    while (cmd_done == NOTFINISHED) {
	imclient_processoneevent(imclient_conn);
    }

    spew(2, "%s selecting", name);

    if (cmd_done == IMAP_NO)
    {
	syslog(LOG_ERR, "unable to select %s: %s", name, cmd_resp);
	return 0;
    } else if (cmd_done != IMAP_OK) {
	fatal("selecting mailbox", EC_TEMPFAIL);
    }

    stats.total = current_mbox_exists;

    spew(2, "%s exists %d", name, current_mbox_exists);

    /* make out list of uids */
    uidlist.size = 0;		/* reset to 0 */

    spew(3, "%s searching for messages %s", name, search_string);

    imclient_addcallback(imclient_conn,
			 "SEARCH", 0, callback_search,
			 (void *)&uidlist, (char *)0);
    imclient_send(imclient_conn, callback_finish, (void *)imclient_conn,
		  "UID SEARCH %a", search_string);
    

    cmd_done = NOTFINISHED;
    while (cmd_done == NOTFINISHED) {
	imclient_processoneevent(imclient_conn);
    }
    if (cmd_done != IMAP_OK) {
	fatal("UID Search failed", EC_TEMPFAIL);
    }

    if (uidlist.size > 0) {
	mark_all_deleted(name, &uidlist, &stats);
    }

    /* close mailbox */   
    imclient_send(imclient_conn, callback_finish, (void *)imclient_conn,
		  "CLOSE");

    cmd_done = NOTFINISHED;
    while (cmd_done == NOTFINISHED) {
	imclient_processoneevent(imclient_conn);
    }

    if (cmd_done != IMAP_OK) {
	fatal("unable to CLOSE mailbox", EC_TEMPFAIL);
    }

    spew(1, "%s exists %d deleted %d", 
	 name, current_mbox_exists, uidlist.size);

    return 0;
}



int purge_all(void)
{
    int num = 0;
    int ret = 0;

    while (ret == 0) {
	ret = ExpireExists(num);
	
	if (ret == 0)
	    purge_me(GetExpireName(num), GetExpireTime(num));

	num++;
    }

    return 0;
}

void do_list(char *matchstr)
{
    imclient_send(imclient_conn, callback_finish, (void *)imclient_conn,
		  "%a %s %s", "LIST", "*",
		  matchstr);

    cmd_done = NOTFINISHED;

    while (cmd_done == NOTFINISHED) {
	imclient_processoneevent(imclient_conn);
    }

    if (cmd_done!=IMAP_OK) fatal("unable to LIST mailboxes", EC_TEMPFAIL);
}

/*
 *  What we were given on the command line might just be a path or might not have an extension etc...
 */

static char *parseconfigpath(char *str)
{
    char *ret;

    /* if it ends with a '/' add expire.ctl */
    
    if (str[strlen(str)-1] == '/')
    {
	ret = (char *) xmalloc(strlen(str)+strlen("expire.ctl")+1);
	strcpy(ret,str);
	strcat(ret,"expire.ctl");

	return ret;
    }

    return str;
}

void remote_purge(char *configpath, char **matches)
{
    char *name;

    imclient_addcallback(imclient_conn,
			 "LIST", 0, callback_list,
			 (void *)0, (char *)0);

    if (matches[0]==NULL) {
	syslog(LOG_WARNING, "matching all mailboxes for possible purge");
	spew(1, "matching all mailboxes");

	do_list("*");
    } else {
	while (matches[0]!=NULL) {
	    spew(0, "matching %s", matches[0]);
	    do_list(matches[0]);
	    matches++;
	}
    }

    spew(1, "completed list");

    if (configpath!=NULL) {
	name = parseconfigpath(configpath);

	configstream = fopen(name,"r");

	if (configstream == NULL) 
	    fatal("unable to open config file", EC_CONFIG);

	EXPreadfile(configstream);
	/* ret val */
    } else {
	artificial_matchall(days);
    }

    purge_all();
}

/* didn't give correct parameters; let's exit */
void usage(void)
{
  printf("Usage: remotepurge [options] hostname [[match1] ... ]\n");
  printf("  -p port  : port to use\n");
  printf("  -k #     : minimum protection layer required\n");
  printf("  -l #     : max protection layer (0=none; 1=integrity; etc)\n");
  printf("  -u user  : authorization name to use\n");
  printf("  -v       : verbose\n");
  printf("  -n       : don't actually purge\n");
  printf("  -m mech  : SASL mechanism to use (\"login\" for LOGIN)\n");
  printf("  -r realm : realm\n");

  printf("  -e expire.ctl : use expire.ctl file (specify full path)\n");

  printf("  -d days  : purge all message <days> old\n");

  exit(EC_USAGE);
}

int main(int argc, char **argv)
{
    char *mechanism=NULL;
    char servername[1024];
    char *expirectlfile = NULL;

    int maxssf = 128;
    int minssf = 0;
    char c;

    char *tls_keyfile="";
    char *port = "imap";
    int dotls=0;
    int r;
    capabilities_t *capabilitylist;

    /* look at all the extra args */
    while ((c = getopt(argc, argv, "d:vne:k:l:p:u:a:m:t:")) != EOF)
	switch (c) {
	case 'd':
	    days = atoi(optarg);
	    break;
	case 'e':
	    expirectlfile = optarg;
	    break;
	case 'v':
	    verbose++;
	    break;
	case 'k':
	    minssf=atoi(optarg);      
	    break;
	case 'l':
	    maxssf=atoi(optarg);      
	    break;
	case 'p':
	    port = optarg;
	    break;
	case 'u':
	    username = optarg;
	    break;
	case 'm':
	    mechanism=optarg;
	    break;
	case 'r':
	    realm=optarg;
	    break;
	case 't':
	    dotls=1;
	    tls_keyfile=optarg;
	    break;
	case 'n':
	    noop = 1;
	    break;
	case '?':
	default:
	    usage();
	    break;
	}

    if (optind >= argc) usage();


    if ((days==-1) && (expirectlfile == NULL))
    {
	printf("Must specify expire.ctl file OR days old OR bytes large\n\n");
	usage();
    }

    /* next to last arg is server name */
    strncpy(servername, argv[optind], 1023);

    r = imclient_connect (&imclient_conn, servername, port, NULL);
  
    if (r!=0) {
	fatal("imclient_connect()", EC_TEMPFAIL);
    }

    spew(0, "connected");

    /* get capabilities */
    imclient_addcallback(imclient_conn, "CAPABILITY", 0,
			 callback_capability, (void *) &capabilitylist, 
			 (char *) 0);
  
    imclient_send(imclient_conn, callback_finish, NULL,
		  "CAPABILITY");

    cmd_done = 0;

    while (cmd_done == 0) {
	imclient_processoneevent(imclient_conn);
    }

    r = imclient_authenticate(imclient_conn,
			      capabilitylist->mechs,
			      "imap",
			      username,
			      minssf,
			      maxssf);

    if (r!=0) {
	fatal("imclient_authenticate()\n", EC_CONFIG);
    }

    spew(0, "authenticated");

    readconfig_init();

    remote_purge(expirectlfile, argv+(optind+1));

    spew(0, "done");

    exit(0);
}
