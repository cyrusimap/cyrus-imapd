/*
 * Populate the ACAP server with the current imap mailboxes
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

#include "acapmbox.h"
#include "acap.h"

typedef struct mbox_list_s {
    
    acapmbox_data_t mb;

    struct mbox_list_s *next;

} mbox_list_t;

mbox_list_t *mb_list = NULL;

int verbose = 0;
char *username = NULL;
char *authname = NULL;
char *realm = NULL;

struct imclient *imclient_conn;
acap_conn_t *acap_conn;

int cmd_done;

/* libcyrus makes us define this */
void fatal(void)
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
	printf("NO\n");
    }
    else if (!strcmp(reply->keyword, "BAD")) {
	printf("BAD\n");

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
callback_list(imclient, rock, reply)
struct imclient *imclient;
void *rock;
struct imclient_reply *reply;
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

    item = (mbox_list_t *) malloc (sizeof(mbox_list_t));
    if (item == NULL) return;

    item->mb.name = mailbox;
    item->next = NULL;


    if (mb_list == NULL)
    {
	mb_list = item;
    } else {
	item->next = mb_list;
	mb_list = item;
    }

    printf("mailbox = %s\n",mailbox);

    for (s = attributes; end = strchr(s, ' '); s = end+1) {
	*s = '\0';

    }

}

int create_all(void)
{
    int r;
    mbox_list_t *item = mb_list;

    while (item != NULL)
    {
	printf("Creating %s\n",item->mb.name);
	r = acapmbox_create(acap_conn,item->mb.name,NULL);
	printf("c r = %d\n",r);
       
	item = item->next;
    }

    return 0;
}

void acap_populate(char *user, char *server)
{
    int r;
    char *url;

    /* connect to acap server */
    r = acap_init();
    if (r != ACAP_OK) {
	fatal();
    }

    url = (char *) malloc(strlen("acap://")+strlen(user)+1+strlen(server)+2);
    if (url==NULL) return;

    sprintf(url,"acap://%s@%s/",user,server);

    r = acap_conn_connect(url, &acap_conn);
    free(url);
    if (r != SASL_OK) {
	printf("acap_conn_connect() returned %d\n", r);
	fatal();
    }


    /* Delete all current entries */
    /* xxx    r = acapmbox_deleteall(acap_conn); */

    if (r != ACAP_OK)
    {
	printf("Error deleting all entries\n");
	fatal();
    }

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
    
    /* now we have the full list. go to creating */

    create_all();
}

















/* didn't give correct parameters; let's exit */
void usage(void)
{
  printf("Usage: imtest [options] hostname\n");
  printf("  -p port  : port to use\n");
  printf("  -z       : timing test\n");
  printf("  -k #     : minimum protection layer required\n");
  printf("  -l #     : max protection layer (0=none; 1=integrity; etc)\n");
  printf("  -u user  : authorization name to use\n");
  printf("  -a user  : authentication name to use\n");
  printf("  -v       : verbose\n");
  printf("  -m mech  : SASL mechanism to use (\"login\" for LOGIN)\n");
  printf("  -f file  : pipe file into connection after authentication\n");
  printf("  -r realm : realm\n");


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
  while ((c = getopt(argc, argv, "zvk:l:p:u:a:m:f:t:")) != EOF)
    switch (c) {
    case 'z':
	run_stress_test=1;
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
    case 'f':
        filename=optarg;
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

  if (optind != argc - 2) {
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
      printf("imclient_connect() -> %d\n",r);
      fatal();
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
      printf("imclient_authenticate() -> %d\n",r);
      fatal();
  }


  acap_populate(authname, argv[optind+1]);

  exit(0);
}
