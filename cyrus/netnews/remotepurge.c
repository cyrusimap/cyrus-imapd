/*
 * Remotely purge old/too big articles
 */



#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <fcntl.h>


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>

#include <sasl.h>
#include <saslutil.h>

#include <pwd.h>

#include "prot.h"

#include "imclient.h"
#include "xmalloc.h"

#define SECS_IN_DAY (24*60*60)

typedef struct mbox_list_s {
    
    char *name;

    struct mbox_list_s *next;

} mbox_list_t;

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


mbox_list_t *mb_list = NULL;

int verbose = 0;
char *username = NULL;
char *authname = NULL;
char *realm = NULL;

struct imclient *imclient_conn;

int cmd_done;

/* libcyrus makes us define this */
void fatal(const char *s, int code)
{
  exit(1);
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
  if (strstr(str,"STARTTLS")!=NULL)
  {
    ret->starttls=1;
  }

  /* check for login being disabled */
  if (strstr(str,"LOGINDISABLED")!=NULL)
  {
    ret->logindisabled=1;
  }

  strcpy(ret->mechs,"");

  while ((tmp=strstr(str,"AUTH="))!=NULL)
  {
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
callback_finish(imclient, rock, reply)
struct imclient *imclient;
void *rock;
struct imclient_reply *reply;
{
    struct admconn *conn = (struct admconn *)rock;

    cmd_done = 1;

    if (!strcmp(reply->keyword, "OK")) {
	printf("OK\n");
	return;
    }
	    
    if (!strcmp(reply->keyword, "NO")) {
	printf("NO %s\n", reply->text);
    }
    else if (!strcmp(reply->keyword, "BAD")) {
	printf("BAD %s\n",reply->text);

    }
    else if (!strcmp(reply->keyword, "EOF")) {
	printf("EOF\n");
    }
    else {
	printf("unkown\n");

    }
}

/*
 * Callback to deal with untagged LIST/LSUB data
 */
static void
callback_list(struct imclient *imclient,
	      void *rock,
	      struct imclient_reply *reply)
{
    char *s, *end;
    char *mailbox, *attributes, *separator;
    int c;
    mbox_list_t *item;

    s = reply->text;
    
    if (*s++ != '(') return;
    end = strchr(s, ')');
    if (!end) return;
    attributes = s;
    s = end;
    *s++ = '\0';

    if (*s++ != ' ') return;
    if (*s == 'N') {
	if (s[1] != 'I' || s[2] != 'L') return;
	separator = "";
    	s += 3;
    }
    else if (*s == '\"') {
	s++;
	if (*s == '\\') s++;
	separator = s++;
	if (*s != '\"') return;
	*s++ = '\0';
    }

    if (*s++ != ' ') return;
    c = imparse_astring(&s, &mailbox);
    if (c != '\0') return;

    if ((strncasecmp(mailbox,"INBOX",5)!=0) && (strncasecmp(mailbox,"user.",5)!=0))
    {

	item = (mbox_list_t *) malloc (sizeof(mbox_list_t));
	if (item == NULL) return;

	item->name = malloc( strlen(mailbox)+1);
	strcpy(item->name, mailbox);
	item->next = NULL;
    

	if (mb_list == NULL)
	{
	    mb_list = item;
	} else {
	    item->next = mb_list;
	    mb_list = item;
	}
    }

    for (s = attributes; end = strchr(s, ' '); s = end+1) {
	*s = '\0';

    }

}

void print_stats(mbox_stats_t *stats)
{
    printf("total messages    \t\t %d\n",stats->total);
    printf("total bytes       \t\t %d\n",stats->total_bytes);
    printf("Deleted messages  \t\t %d\n",stats->deleted);
    printf("Deleted bytes     \t\t %d\n",stats->deleted_bytes);
    printf("Remaining messages\t\t %d\n",stats->total - stats->deleted);
    printf("Remaining bytes   \t\t %d\n",stats->total_bytes - stats->deleted_bytes);
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

    printf("s = %s\n",s);

    while (isdigit(*s)) {
	num = 0;
	
	while ((*s!='\0') && (*s!=' '))
	{
	    num = num*10 + (*s-'0');
	    s++;
	}

	printf("num = %d\n",num);

	uids->list[uids->size] = num;
	uids->size++;

	if (uids->size >= uids->allocsize)
	{
	    uids->list = realloc(uids->list, sizeof(unsigned long) * (uids->allocsize+250));
	    uids->allocsize+=250;
	}


	if (*s == '\0') break;
	s++;
    }
   
}

/*
 * Callback to deal with untagged LIST/LSUB data
 */
static void
callback_fetch(struct imclient *imclient,
	       void *rock,
	       struct imclient_reply *reply)
{
    char name[100];
    char *name_ptr;
    char value[200];
    char *value_ptr;
    int value_num;
    char *s;

    s = reply->text;

    if (*s != '(') printf("Expected LPAREN\n");
    s++;

    while (1) {

	name_ptr = name;
	while ((*s!=' ') && (*s!=')'))
	    {
		*name_ptr = *s;
		name_ptr++;
		s++;
	    }
	*name_ptr = '\0';

	s++;

	if (*s=='"') {
	    s++;
	    value_ptr = value;
	    while ((*s!='"') && (*s!='\0'))
		{
		    *value_ptr = *s;
		    value_ptr++;
		    s++;
		}
	    *value_ptr = '\0';
	    s++;
	} else if (isdigit(*s)) {
	    value_num = 0;
	
	    while ((*s!=' ') && (*s!=')'))
		{
		    value_num = value_num*10 + (*s-'0');
		    s++;
		}
	} else {
	    return;
	}

	if (strcasecmp(name,"UID")==0)
	{
	    printf("%s ^ %d\n",name, value_num);
	} else if (strcasecmp(name,"INTERNALDATE")==0) {
	    printf("%s ^ %s\n",name, value);
	} else if (strcasecmp(name,"RFC822.SIZE")==0) {
	    printf("%s ^ %d\n",name, value_num);
	}
	


	s++;
    }
    
}


void deleteit(void *the_record, mbox_stats_t *stats)
{
    stats->deleted++;
    /*    stats->deleted_bytes+=the_record->size; */
}

/* thumbs up routine, checks date & size and returns yes or no for deletion */
/* 0 = no, 1 = yes */
int purge_check(unsigned long msg_time, int msgsize, mbox_stats_t *stats)
{
    void *the_record;
    unsigned long       my_time;

    stats->total++;
    /*  stats->total_bytes+=the_record->size;*/

    if (exact == 1) {
	if (days >= 0) {
	    my_time = time(0);
	    /*    printf("comparing %ld :: %ld\n", my_time, the_record->sentdate); 
		  if (((my_time - the_record->sentdate)/86400) == (days/86400)) {
		  deleteit(the_record, stats);
		  return 1;
		  }*/
	}
	if (size >= 0) {
	    /* check size */
	    /*      if (the_record->size == size) {
		    deleteit(the_record, stats);
		    return 1;
		    }*/
	}
	return 0;
    } else {
	if (days >= 0) {
	    my_time = time(0);
	    /*    printf("comparing %ld :: %ld\n", my_time, the_record->sentdate); 
		  if ((my_time - the_record->sentdate) > days) {
		  deleteit(the_record, stats);
		  return 1;
		  }*/
	}
	if (size >= 0) {
	    /* check size */
	    /*      if (the_record->size > size) {
		    deleteit(the_record, stats);
		    return 1;
		    }*/
	}
	return 0;
    }
}

void mark_all_deleted(uid_list_t *list)
{
    int lup;

    for (lup=0;lup<list->size;lup++)
    {
	imclient_send(imclient_conn, callback_finish, (void *)imclient_conn,
		      "%a %d +FLAGS.SILENT (\\Deleted)", "UID STORE",list->list[lup]);

	cmd_done = 0;
	
	while (cmd_done == 0) {
	    imclient_processoneevent(imclient_conn);
	}
       	
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
int purge_me(char *name)
{
    int            error;
    mbox_stats_t   stats;
    char search_string[200];
    uid_list_t *uidlist;
    unsigned long       my_time;

    memset(&stats, '\0', sizeof(mbox_stats_t));
    
    if (verbose)
	printf("Working on %s...\n",name);

    /* select mailbox */
    imclient_send(imclient_conn, callback_finish, (void *)imclient_conn,
		  "%a \"%s\"", "SELECT", name);		 

    cmd_done = 0;

    while (cmd_done == 0) {
	imclient_processoneevent(imclient_conn);
    }

    /* xxx should check we can delete */
    /* xxx check return code */

    /* fetch all marking old as deleted */

    uidlist = (uid_list_t *) malloc(sizeof(uid_list_t));
    uidlist->list = malloc (sizeof(unsigned long) * 500);
    uidlist->allocsize = 500;
    uidlist->size = 0;
	

    if (exact == 1) {
	if (days >= 0) {
	    struct tm *my_tm;

	    my_time = time(NULL);
	    my_time -= days * (SECS_IN_DAY);
	    my_tm = gmtime(&my_time);

	    snprintf(search_string,sizeof(search_string),
		     "ON %d-%s-%d",
		     my_tm->tm_mday,month_string(my_tm->tm_mon),1900+my_tm->tm_year);
	}
	if (size >= 0) {
	    sprintf(search_string,"LARGER %d SMALLER %d",size-1,size+1);
	}
    } else {
	if (days >= 0) {
	    struct tm *my_tm;

	    my_time = time(NULL);
	    my_time -= days * (SECS_IN_DAY);
	    my_tm = gmtime(&my_time);

	    snprintf(search_string,sizeof(search_string),
		     "BEFORE %d-%s-%d",
		     my_tm->tm_mday,month_string(my_tm->tm_mon),1900+my_tm->tm_year);

	}
	if (size >= 0) {
	    sprintf(search_string,"LARGER %d",size);
	}
    }

    imclient_addcallback(imclient_conn,
			 "SEARCH", 0, callback_search,
			 (void *)uidlist, (char *)0);
    imclient_send(imclient_conn, callback_finish, (void *)imclient_conn,
		  "%a %a", "UID SEARCH",search_string);
    

    cmd_done = 0;

    while (cmd_done == 0) {
	imclient_processoneevent(imclient_conn);
    }

    if (uidlist->size > 0)
    {

	mark_all_deleted(uidlist);
            	
	print_stats(&stats);
    }
 
    /* close mailbox */   
    imclient_send(imclient_conn, callback_finish, (void *)imclient_conn,
		  "%a", "CLOSE");

    cmd_done = 0;

    while (cmd_done == 0) {
	imclient_processoneevent(imclient_conn);
    }

    return 0;
}



int purge_all(void)
{
    int r;
    mbox_list_t *item = mb_list;

    while (item != NULL)
    {
	printf("Purging %s...\n",item->name);

	purge_me(item->name);
       
	item = item->next;
    }

    return 0;
}

void remote_purge(void)
{
    imclient_addcallback(imclient_conn,
			 "LIST", 0, callback_list,
			 (void *)0, (char *)0);
    imclient_send(imclient_conn, callback_finish, (void *)imclient_conn,
		  "%a %s %s", "LIST", "*",
		  "*");

    cmd_done = 0;

    while (cmd_done == 0) {
	imclient_processoneevent(imclient_conn);
    }

    if (verbose) printf("Completed list command\n");

    purge_all();
}











/* didn't give correct parameters; let's exit */
void usage(void)
{
  printf("Usage: imtest [options] hostname\n");
  printf("  -p port  : port to use\n");
  printf("  -k #     : minimum protection layer required\n");
  printf("  -l #     : max protection layer (0=none; 1=integrity; etc)\n");
  printf("  -u user  : authorization name to use\n");
  printf("  -a user  : authentication name to use\n");
  printf("  -v       : verbose\n");
  printf("  -m mech  : SASL mechanism to use (\"login\" for LOGIN)\n");
  printf("  -r realm : realm\n");

  printf("  -d days  : purge all message <days> old\n");
  printf("  -b bytes : purge all messages larger than <bytes>\n");

  exit(1);
}




int main(int argc, char **argv)
{
  char *mechanism=NULL;
  char servername[1024];
  char *filename=NULL;

  char *mechlist;
  int *ssfp;
  int maxssf = 0;
  int minssf = 0;
  char c;
  int result;
  int errflg = 0;

  char *tls_keyfile="";
  char *port = "imap";
  struct servent *serv;
  int servport;
  int run_stress_test=0;
  int dotls=0;
  int server_supports_tls;
  int r;
  capabilities_t *capabilitylist;

  /* look at all the extra args */
  while ((c = getopt(argc, argv, "b:d:vk:l:p:u:a:m:t:")) != EOF)
    switch (c) {
    case 'b':
	size = atoi(optarg);
	break;
    case 'd':
	days = atoi(optarg) * SECS_IN_DAY;
	break;
    case 'v':
	verbose=1;
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
    case 'a':
	authname = optarg;
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
    case '?':
    default:
	errflg = 1;
	break;
    }

  if (optind != argc - 1) {
      errflg = 1;
  }

  if (errflg) {
      usage();
  }

  /* next to last arg is server name */
  strncpy(servername, argv[optind], 1023);

  r = imclient_connect (&imclient_conn, servername,
			port);
  
  if (r!=0)
  {
      fatal("imclient_connect()",r);
  }

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
			    authname,
			    minssf,
			    maxssf);

  if (r!=0)
  {
      fatal("imclient_authenticate()\n",r);
  }


  remote_purge();

  exit(0);
}
