/* imtest.c -- imap test client
 * Tim Martin (SASL implementation)
 * $Id: imtest.c,v 1.20 1999/06/24 18:52:44 leg Exp $
 *
 * Copyright 1999 Carnegie Mellon University
 * 
 * No warranties, either expressed or implied, are made regarding the
 * operation, use, or results of the software.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted for non-commercial purposes only
 * provided that this copyright notice appears in all copies and in
 * supporting documentation.
 *
 * Permission is also granted to Internet Service Providers and others
 * entities to use the software for internal purposes.
 *
 * The distribution, modification or sale of a product which uses or is
 * based on the software, in whole or in part, for commercial purposes or
 * benefits requires specific, additional permission from:
 *
 *  Office of Technology Transfer
 *  Carnegie Mellon University
 *  5000 Forbes Avenue
 *  Pittsburgh, PA  15213-3890
 *  (412) 268-4387, fax: (412) 268-7395
 *  tech-transfer@andrew.cmu.edu
 */

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>

#include <sasl.h>
#include <saslutil.h>

#include "prot.h"

#define IMTEST_OK    0
#define IMTEST_FAIL -1

typedef enum {
    STAT_CONT = 0,
    STAT_NO = 1,
    STAT_OK = 2
} stat;

/* global vars */
sasl_conn_t *conn;
int sock; /* socket descriptor */

struct protstream *pout, *pin;

char *authname;

extern int _sasl_debug;

extern char *optarg;

/* callbacks we support */
static sasl_callback_t callbacks[] = {
  {
    SASL_CB_USER, NULL, NULL
  }, {
    SASL_CB_AUTHNAME, NULL, NULL
  }, {
    SASL_CB_PASS, NULL, NULL    
  }, {
    SASL_CB_LIST_END, NULL, NULL
  }
};

void imtest_fatal(char *msg)
{
  if (msg!=NULL)
    printf("failure: %s\n",msg);
  exit(1);
}

/* libcyrus makes us define this */
void fatal(void)
{
  exit(1);
}

static sasl_security_properties_t *make_secprops(int min,int max)
{
  sasl_security_properties_t *ret=(sasl_security_properties_t *)
    malloc(sizeof(sasl_security_properties_t));

  ret->maxbufsize=1024;
  ret->min_ssf=min;
  ret->max_ssf=max;

  ret->security_flags=0;
  ret->property_names=NULL;
  ret->property_values=NULL;

  return ret;
}

int init_sasl(char *serverFQDN, int port, int ssf)
{
  int saslresult;
  sasl_security_properties_t *secprops=NULL;
  int addrsize=sizeof(struct sockaddr_in);
  struct sockaddr_in *saddr_l=malloc(sizeof(struct sockaddr_in));
  struct sockaddr_in *saddr_r=malloc(sizeof(struct sockaddr_in));

  /* attempt to start sasl */
  saslresult=sasl_client_init(callbacks);

  if (saslresult!=SASL_OK) return IMTEST_FAIL;

  /* client new connection */
  saslresult=sasl_client_new("imap",
			     serverFQDN,
			     NULL,
			     0,
			     &conn);

  if (saslresult!=SASL_OK) return IMTEST_FAIL;


  secprops=make_secprops(0,ssf);
  if (secprops!=NULL)
  {
    sasl_setprop(conn, SASL_SEC_PROPS, secprops);
    free(secprops);
  }

  if (getpeername(sock,(struct sockaddr *)saddr_r,&addrsize)!=0)
    return IMTEST_FAIL;

  if (sasl_setprop(conn, SASL_IP_REMOTE, saddr_r)!=SASL_OK)
    return IMTEST_FAIL;
  
  addrsize=sizeof(struct sockaddr_in);
  if (getsockname(sock,(struct sockaddr *)saddr_l,&addrsize)!=0)
    return IMTEST_FAIL;

  /* set the port manually since getsockname is stupid and doesn't */
  saddr_l->sin_port = htons(port);

  if (sasl_setprop(conn, SASL_IP_LOCAL, saddr_l)!=SASL_OK)
    return IMTEST_FAIL;


  /* should be freed */
  free(saddr_l);
  free(saddr_r);
  
  return IMTEST_OK;
}

stat getauthline(char **line, int *linelen)
{
  char buf[2048];
  int saslresult;
  char *str=(char *) buf;
  
  str=prot_fgets(str,2048,pin);
  if (str==NULL) imtest_fatal("prot layer failure");
  printf("S: %s",str);

  if (strstr(str,"OK")!=NULL) return STAT_OK;
  if (strstr(str,"NO")!=NULL) return STAT_NO;

  str+=2; /* jump past the "+ " */

  *line=malloc(strlen(str)+1);
  if ((*line)==NULL) return STAT_NO;

  saslresult=sasl_decode64(str,strlen(str),
			   *line,(unsigned *) linelen);


  return STAT_CONT;
}

void interaction (sasl_interact_t *t)
{
  char result[1024];

  if (authname!=NULL)
    printf("authname=%s\n",authname);

  if (((t->id==SASL_CB_USER) || (t->id==SASL_CB_AUTHNAME)) && (authname!=NULL))
  {
    strcpy(result,authname);
  } else {
    printf("%s:",t->prompt);
    scanf("%s",&result);
  }
  t->len=strlen(result);
  t->result=(char *) malloc(t->len+1);
  memset(t->result, 0, t->len+1);
  memcpy((char *) t->result, result, t->len);

}

void fillin_interactions(sasl_interact_t *tlist)
{
  while (tlist->id!=SASL_CB_LIST_END)
  {
    interaction(tlist);
    tlist++;
  }

}

int auth_sasl(char *mechlist)
{
  sasl_interact_t *client_interact=NULL;
  int saslresult=SASL_INTERACT;
  char *out;
  unsigned int outlen;
  char *in;
  int inlen;
  const char *mechusing;
  char inbase64[2048];
  int inbase64len;

  stat status=STAT_CONT;

  /* call sasl client start */
  while (saslresult==SASL_INTERACT)
  {
    saslresult=sasl_client_start(conn, mechlist,
				 NULL, &client_interact,
				 &out, &outlen,
				 &mechusing);
    if (saslresult==SASL_INTERACT)
      fillin_interactions(client_interact); /* fill in prompts */      

  }

  if ((saslresult!=SASL_OK) && (saslresult!=SASL_CONTINUE)) return saslresult;

  printf("mechusing: %s\n",mechusing);

  prot_printf(pout,"A01 AUTHENTICATE %s\r\n",mechusing);
  prot_flush(pout);


  status=getauthline(&in,&inlen);

  while (status==STAT_CONT)
  {
    saslresult=SASL_INTERACT;
    while (saslresult==SASL_INTERACT)
    {
      saslresult=sasl_client_step(conn,
				  in,
				  inlen,
				  &client_interact,
				  &out,
				  &outlen);

      if (saslresult==SASL_INTERACT)
	fillin_interactions(client_interact); /* fill in prompts */      	
    }



    /* convert to base64 */
    saslresult=sasl_encode64(out,outlen,
			     inbase64,2048,(unsigned *) &inbase64len);
    if (saslresult!=SASL_OK) return saslresult;

    free(in);
    free(out);

    /* send to server */
    printf("C: %s\n",inbase64);
    prot_write(pout, inbase64,inbase64len);
    prot_printf(pout,"\r\n");
    prot_flush(pout);

    /* get reply */
    status=getauthline(&in,&inlen);
  }
  
  return (status == STAT_OK) ? IMTEST_OK : IMTEST_FAIL;
}

/* initialize the network */
int init_net(char *serverFQDN, int port)
{
  struct sockaddr_in addr;
  struct hostent *hp;

  if ((hp = gethostbyname(serverFQDN)) == NULL) {
    perror("gethostbyname");
    return IMTEST_FAIL;
  }

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return IMTEST_FAIL;	
  }

  addr.sin_family = AF_INET;
  memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
  addr.sin_port = htons(port);

  if (connect(sock, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    perror("connect");
    return IMTEST_FAIL;
  }

  return IMTEST_OK;
}

/***********************
 * Parse a mech list of the form: ... AUTH=foo AUTH=bar ...
 *
 * Return: string with mechs seperated by spaces
 *
 ***********************/

static char *parsemechlist(char *str)
{
  char *tmp;
  int num=0;
  char *ret=malloc(strlen(str)+1);
  if (ret==NULL) return NULL;

  strcpy(ret,"");

  while ((tmp=strstr(str,"AUTH="))!=NULL)
  {
    char *end=tmp+5;
    tmp+=5;

    while(((*end)!=' ') && ((*end)!='\0'))
      end++;

    (*end)='\0';

    /* add entry to list */
    if (num>0)
      strcat(ret," ");
    strcat(ret, tmp);
    num++;

    /* reset the string */
    str=end+1;

  }

  return ret;
}

#define CAPABILITY "C01 CAPABILITY\r\n"

static char *ask_capability(void)
{
  char *str=malloc(301);
  char *ret;

  do {
  str=prot_fgets(str,300,pin);
  if (str==NULL) imtest_fatal("prot layer failure");
  printf("S: %s",str);
  } while (strstr(str,"*")==NULL);

  /* request capabilities of server */
  prot_printf(pout, CAPABILITY);
  prot_flush(pout);


  str=prot_fgets(str,300,pin);
  if (str==NULL) imtest_fatal("prot layer failure");

  printf("S: %s",str);

  ret=parsemechlist(str);

  str=prot_fgets(str,300,pin);
  printf("S: %s",str);

  free(str);

  return ret;
}

static int waitfor(char *tag)
{
  char *str=malloc(301);

  do {
    str=prot_fgets(str,300,pin);
    if (str==NULL) imtest_fatal("prot layer failure");
    printf("%s",str);
  } while (strstr(str,tag)==NULL);

  free(str);

  return 0;
}

#define HEADERS "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)\r\n \
From: Fred Foobar <foobar@Blurdybloop.COM>\r\n \
Subject: afternoon meeting\r\n \
To: mooch@owatagu.siam.edu\r\n \
Message-Id: <B27397-0100000@Blurdybloop.COM>\r\n \
MIME-Version: 1.0\r\n \
Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n\r\n"

static int append_msg(char *mbox, int size)
{
  int lup;

  prot_printf(pout,"A003 APPEND %s (\\Seen) {%u}\r\n",mbox,size+strlen(HEADERS));
  /* do normal header foo */
  prot_printf(pout,HEADERS);

  for (lup=0;lup<size/10;lup++)
    prot_printf(pout,"0123456789");
  prot_printf(pout,"\r\n");

  prot_flush(pout);

  waitfor("A003");

  return IMTEST_OK;
}

/**************
 *
 * This tests throughput of IMAP server
 *
 * Steps:
 *  Creat mailbox
 *  Append message of 200 bytes, 2000 bytes, 20k, 200k, 2M
 *  Delete mailbox
 *  
 *************/


static void send_recv_test(void)
{
  char *mboxname="inbox.imtest";
  time_t start, end;
  int lup;

  start=time(NULL);

  for (lup=0;lup<10;lup++)
  {
    prot_printf(pout,"C01 CREATE %s\r\n",mboxname);
    prot_flush(pout);  
    waitfor("C01");
    
    append_msg(mboxname,200);
    append_msg(mboxname,2000);
    append_msg(mboxname,20000);
    append_msg(mboxname,200000);
    append_msg(mboxname,2000000);

    prot_printf(pout,"D01 DELETE %s\r\n",mboxname);
    prot_flush(pout);  
    waitfor("D01");
  }

  end=time(NULL);

  printf("Took: %i seconds\n",(int) end-start);
}

#define LOGOUT "L01 LOGOUT\r\n"

void interactive(char *filename)
{
  char buf[4096];
  fd_set read_set, rset;
  int nfds;
  int nfound;
  int count;
  FILE *fp;
  int atend=0;

  /* open the file if available */
  if (filename != NULL) {
    if ((fp = fopen(filename, "r")) == NULL) {
      fprintf(stderr,"Unable to open file: %s:", filename);
      perror("");
      exit(1);
    }
  }
  
  FD_ZERO(&read_set);
  if (filename==NULL)
    FD_SET(0, &read_set);  
  
  FD_SET(sock, &read_set);
  nfds = getdtablesize();

  /* let's send the whole file. IMAP is smart. it'll handle everything
     in order*/
  if (filename!=NULL)
  {

    while (atend==0)
    {
      if (fgets(buf, sizeof (buf) - 1, fp) == NULL) {
	printf(LOGOUT);
	prot_write(pout, LOGOUT, sizeof (LOGOUT));
	atend=1;
      } else {
	count = strlen(buf);
	buf[count - 1] = '\r';
	buf[count] = '\n';
	buf[count + 1] = '\0';
	printf("%s", buf);
	prot_write(pout, buf, count + 1);
      }
      prot_flush(pout);
    }
  }

  /* loop reading from network and from stdio if applicable */
  while(1)
  {

    rset = read_set;
    nfound = select(nfds, &rset, NULL, NULL, NULL);
    if (nfound < 0) {
      perror("select");
      imtest_fatal("select");
    }

    if (FD_ISSET(0, &rset)) {

	if (fgets(buf, sizeof (buf) - 1, stdin) == NULL) {
	  printf(LOGOUT);
	  prot_write(pout, LOGOUT, sizeof (LOGOUT));
	  FD_CLR(0, &read_set);
	} else {
	  count = strlen(buf);
	  buf[count - 1] = '\r';
	  buf[count] = '\n';
	  buf[count + 1] = '\0';
	  prot_write(pout, buf, count + 1);
	}
	prot_flush(pout);
      }

    if (FD_ISSET(sock, &rset)) {
      count = prot_read(pin, buf, sizeof (buf) - 1);
      if (count == 0) {
	if (prot_error(pin)) {
	  printf("Protection error: %s\n", prot_error(pin));
	}
	close(sock);
	printf("Connection Closed.\n");
	break;
      }
      if (count < 0) {
	perror("read");
	imtest_fatal("prot_read");
      }
      buf[count] = '\0';
      printf("%s", buf);
    }
  }
}

/* didn't give correct parameters; let's exit */
void usage(void)
{
  printf("Usage: imtest [options] hostname\n");
  printf("  -p port : port to use      \n");
  printf("  -z      : timing test      \n");
  printf("  -l #    : max protection layer (0=none;1=intergrity;etc..)\n");
  printf("  -u user : authentication name to use\n");
  printf("  -v      : verbose\n");
  printf("  -m mech : SASL mechanism to use (\"login\" for no authentication)\n");
  printf("  -f file : pipe file into connection after authentication\n");

  exit(1);
}


int main(int argc, char **argv)
{
  char *mechanism=NULL;
  char *servername=NULL;
  char *filename=NULL;

  char *mechlist;
  int *ssfp;
  int ssf;
  char c;
  int result;
  int errflg = 0;

  char *port = "imap";
  struct servent *serv;
  int servport;
  int run_stress_test=0;
  int verbose=0;

  /* look at all the extra args */
  while ((c = getopt(argc, argv, "zvl:p:u:m:f:")) != EOF)
    switch (c) {
    case 'z':
	run_stress_test=1;
	break;
    case 'v':
	verbose=1;
	break;
    case 'l':
	ssf=atoi(optarg);      
	break;
    case 'p':
	port = optarg;
	break;
    case 'u':
	authname=optarg;
	break;
    case 'm':
	mechanism=optarg;
	break;
    case 'f':
	filename=optarg;
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

  /* last arg is server name */
  servername = argv[optind];

  /* map port -> num */
  serv = getservbyname(port, "tcp");
  if (serv == NULL) {
      servport = atoi(port);
  } else {
      servport = ntohs(serv->s_port);
  }

  if (init_net(servername, servport) != IMTEST_OK)
    imtest_fatal("Network initializion");
  
  if (init_sasl(servername, servport, ssf) != IMTEST_OK)
    imtest_fatal("SASL initialization");


  /* set up the prot layer */
  pin = prot_new(sock, 0);
  pout = prot_new(sock, 1); 

  mechlist=ask_capability();   /* get the * line also */

  if (mechanism) {
      if (!strcasecmp(mechanism, "login")) {
	  result = IMTEST_FAIL;
      } else {
	  result = auth_sasl(mechanism);
      }
  } else {
      result = auth_sasl(mechlist);
  }

  if (result == IMTEST_OK) {
      printf("Authenticated.\n");
  } else {
      printf("Authentication failed.\n");
  }

  result = sasl_getprop(conn, SASL_SSF, (void **)&ssfp);
  if (result != SASL_OK) {
      printf("SSF: unable to determine (SASL ERROR %d!)\n", result);
  } else {
      printf("SSF: %d\n", *ssfp);
  }

  /* turn on layer if need be */
  prot_setsasl(pin,  conn);
  prot_setsasl(pout, conn);

  if (run_stress_test==1)
  {
    send_recv_test();
  } else {
    interactive(filename);
  }

  exit(0);
}
