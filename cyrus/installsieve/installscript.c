/* installscrip.c -- command line program to install sieve scripts
 * Tim Martin
 * 9/21/99
 */
/* 
 * Copyright (c) 1999-2000 Carnegie Mellon University.  All rights reserved.
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
 */

/* $Id: installscript.c,v 1.28 2002/05/25 19:57:46 leg Exp $ */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

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

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include <pwd.h>

#include "prot.h"
#include "lex.h"
#include "request.h"

#define IMTEST_OK    0
#define IMTEST_FAIL -1

typedef enum {
    STAT_CONT = 0,
    STAT_NO = 1,
    STAT_OK = 2
} imt_stat;

char *authname=NULL;
char *username=NULL;
char *realm=NULL;
char *password=NULL;

/* global vars */
sasl_conn_t *conn;
int sock; /* socket descriptor */

struct protstream *pout, *pin;

static int version;

void imtest_fatal(char *msg)
{
  if (msg!=NULL)
    printf("failure: %s\n",msg);
  exit(1);
}

static int
getsecret(sasl_conn_t *conn,
	  void *context __attribute__((unused)),
	  int id,
	  sasl_secret_t **psecret)
{
  char *password;
  size_t len;

  if (! conn || ! psecret || id != SASL_CB_PASS)
    return SASL_BADPARAM;

  printf("xxx todo\n");
  return -1;

  /*  printf("Password: ", prompt);
  *tresult=strdup(getpass(""));
  *tlen=strlen(*tresult);
  if (! password)
  return SASL_FAIL; */

  len = strlen(password);

  *psecret = (sasl_secret_t *) malloc(sizeof(sasl_secret_t) + len);
  
  if (! *psecret) {
    memset(password, 0, len);
    return SASL_NOMEM;
  }

  (*psecret)->len = len;
  strcpy((*psecret)->data, password);
  memset(password, 0, len);
    
  return SASL_OK;
}

static int
simple(void *context,
       int id,
       const char **result,
       unsigned *len)
{
  const char *value = (const char *)context;
  int l;

  /* xxx */
  printf("asking for %d\n",id);

  if (! result)
    return SASL_BADPARAM;

  switch (id) {
  case SASL_CB_USER:
      printf("Username: ");
      *result = xmalloc(1025);
      fgets(*result, 1024, stdin);
      l = strlen(*result);
      (*result)[l - 1] = '\0';
      if (len)
	  *len = strlen(*result);
    break;
  case SASL_CB_AUTHNAME:
    *result = value;
    if (len)
      *len = value ? strlen(value) : 0;
    break;
  case SASL_CB_LANGUAGE:
    *result = NULL;
    if (len)
      *len = 0;
    break;
  default:
    return SASL_BADPARAM;
  }
  return SASL_OK;
}

void interaction (int id, const char *prompt,
		  char **tresult, unsigned int *tlen)
{
    char result[1024];
    
    if (id==SASL_CB_PASS) {
      if (password!=NULL) /* if specified on command line */
      {
	*tresult = strdup(password);
	*tlen=strlen(*tresult);
	
	/* wipe it out from memory now. we don't want to hold 
	   onto the user's plaintext password */
	memset(password, '\0', strlen(password));
	
      } else {
	printf("%s: ", prompt);
	*tresult=strdup(getpass(""));
	*tlen=strlen(*tresult);
      }
	return;
    } else if ((id==SASL_CB_USER) || (id==SASL_CB_AUTHNAME)) {
        if ((id==SASL_CB_USER) && (username!=NULL))
	{
	  strcpy(result, username);
	} else if (authname) {
	    strcpy(result, authname);
	} else {
	    strcpy(result, getpwuid(getuid())->pw_name);
	}
#ifdef SASL_CB_GETREALM
    } else if ((id==SASL_CB_GETREALM) && (realm!=NULL)) {
      strcpy(result, realm);
#endif
    } else {
	int c;
	
	printf("%s: ",prompt);
	fgets(result, 1023, stdin);
	c = strlen(result);
	result[c - 1] = '\0';
    }

    *tlen = strlen(result);
    *tresult = (char *) malloc(*tlen+1);
    memset(*tresult, 0, *tlen+1);
    memcpy((char *) *tresult, result, *tlen);
}

void fillin_interactions(sasl_interact_t *tlist)
{
  while (tlist->id!=SASL_CB_LIST_END)
  {
    interaction(tlist->id, tlist->prompt,
		(void *) &(tlist->result), 
		&(tlist->len));
    tlist++;
  }

}

/* callbacks we support */
static sasl_callback_t callbacks[] = {
  {
    SASL_CB_GETREALM, &simple, NULL
  }, {
    SASL_CB_USER, &simple, NULL
  }, {
    SASL_CB_AUTHNAME, &simple, NULL
  }, {
    SASL_CB_PASS, &getsecret, NULL    
  }, {
    SASL_CB_LIST_END, NULL, NULL
  }
};


/* libcyrus makes us define this */
void fatal(const char *s, int code)
{
    printf("Error: %s\n",s);
    exit(code);
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


/*
 * Initialize SASL and set necessary options
 */

static int init_sasl(char *serverFQDN, int port, int ssf)
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
  saslresult=sasl_client_new(SIEVE_SERVICE_NAME,
			     serverFQDN,
			     NULL,
			     0,
			     &conn);

  if (saslresult!=SASL_OK) return IMTEST_FAIL;

  /* create a security structure and give it to sasl */
  secprops = make_secprops(0, ssf);
  if (secprops != NULL)
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


int getauthline(char **line, unsigned int *linelen)
{
  lexstate_t state;
  int res;
  int ret;
  mystring_t *errstr;

  /* now let's see what the server said */
  res=yylex(&state, pin);
  if (res!=STRING)
  {
      ret = handle_response(res,version,
			    pin, &errstr);

    if (res==TOKEN_OK) {
      return STAT_OK;
    } else { /* server said no */
      printf("Authentication failed with: \"%s\"\n",string_DATAPTR(errstr));
      return STAT_NO;    
    }
  }

  *line=(char *) malloc(state.str->len*2+1);

  sasl_decode64(string_DATAPTR(state.str), state.str->len,
		*line, linelen);

  if (yylex(&state, pin)!=EOL)
    parseerror("EOL");

  return STAT_CONT;
}

int auth_sasl(int version, char *mechlist)
{
  sasl_interact_t *client_interact=NULL;
  int saslresult=SASL_INTERACT;
  char *out;
  unsigned int outlen;
  char *in;
  unsigned int inlen;
  const char *mechusing;
  char inbase64[2048];
  unsigned int inbase64len;

  imt_stat status = STAT_CONT;

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

  if (out!=NULL)
  {
    prot_printf(pout,"AUTHENTICATE \"%s\" ",mechusing);

    sasl_encode64(out, outlen,
		  inbase64, sizeof(inbase64), &inbase64len);

    prot_printf(pout, "{%d+}\r\n",inbase64len);
    prot_write(pout,inbase64,inbase64len);
    prot_printf(pout,"\r\n");
  } else {
    prot_printf(pout,"AUTHENTICATE \"%s\"\r\n",mechusing);
  }
  prot_flush(pout);

  inlen = 0;
  status = getauthline(&in,&inlen);

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

    /* check if sasl suceeded */
    if (saslresult<SASL_OK)
    {
      printf("sasl result = %s\n",sasl_errstring(saslresult,NULL,NULL));
      return saslresult;
    }

    /* send to server */

    sasl_encode64(out, outlen,
		  inbase64, sizeof(inbase64), &inbase64len);

    prot_printf(pout, "{%d+}\r\n",inbase64len);
    prot_flush(pout);
    prot_write(pout,inbase64,inbase64len);
    prot_flush(pout);
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

char *read_capability(int *version)
{
  lexstate_t state;
  char *cap = NULL;

  *version = NEW_VERSION;

  while (yylex(&state,pin)==STRING)
  {
      char *attr = string_DATAPTR(state.str);
      char *val = NULL;


      if (yylex(&state,pin)==' ')
      {
	  if (yylex(&state,pin)!=STRING)
	  {
	      parseerror("STRING");
	  }
	  val = string_DATAPTR(state.str);
	  if (yylex(&state,pin)!=EOL)
	  {
	      parseerror("EOL1");
	  }
      }

      if (strcasecmp(attr,"SASL")==0)
      {
	cap = val;
      } else if (strcasecmp(attr,"SIEVE")==0) {

      } else if (strcasecmp(attr,"IMPLEMENTATION")==0) {

      } else if (strncmp(val,"SASL=",5)==0) {
	  *version = OLD_VERSION;
	  cap = (char *) malloc(strlen(val));
	  memset(cap, '\0', strlen(val));
	  memcpy(cap, val+6, strlen(val)-7);

	  return cap;
      } else {
	  /* unkown capability */
      }
  }

  if (yylex(&state,pin)!=EOL)
  {
      parseerror("EOL2");
  }
  
  return cap;
}

void list_cb(char *name, int isactive)
{
    printf("name = %s active = %d\n",name,isactive);
}


void usage(void)
{
  printf("usage:\n");
  printf(" installsieve [options] servername\n");
  printf("  -v <name>    view script\n");
  printf("  -l           list available scripts\n");
  printf("  -p <port>    port to connect to\n");
  printf("  -i <file>    filename of script to install\n");
  printf("  -a <name>    Set <name> as the active script\n");
  printf("  -d <name>    Delete <name> script from server\n");
  printf("  -m <mech>    Mechanism to use for authentication\n");
  printf("  -g <name>    Get script <name> and save to disk\n");
  printf("  -u <user>    Userid/Authname to use\n");
  printf("  -t <user>    Userid to use (for proxying)\n");
  printf("  -w <passwd>  Specify password (Should only be used for automated scripts)\n");
  exit(1);
}


int main(int argc, char **argv)
{
  char c;
  int dolist = 0;
  int deflist = 1;

  char *portstr = "sieve";
  int port;
  struct servent *serv;

  char *mechanism=NULL;
  char *installfile=NULL;
  char *viewfile=NULL;
  char *servername;
  char *setactive=NULL;
  char *deletescript=NULL;
  char *getscriptname=NULL;
  int ssf=0;

  char *mechlist=NULL;

  int result;

  /* look at all the extra args */
  while ((c = getopt(argc, argv, "a:d:g:lv:p:i:m:u:w:t:")) != EOF)
    switch (c) 
    {
    case 'a':
      setactive=optarg;
      deflist = 0;
      break;
    case 'd':
      deletescript=optarg;
      deflist = 0;
      break;
    case 'i':
      installfile=optarg;
      deflist = 0;
      break;
    case 'l':
      dolist=1;
      break;
    case 'v':
      viewfile=optarg;
      deflist = 0;
      break;
    case 'p':
      portstr=optarg;
      break;
    case 'm':
      mechanism=optarg;
      break;
    case 'g':
      getscriptname=optarg;
      deflist = 0;
      break;
    case 'u':
      authname = optarg;
      break;
    case 't':
      username = optarg;
      break;
    case 'w':
      password = optarg;
      break;
    default:
      usage();
      break;
    }

  if (optind != argc - 1) {
    usage();
  }

  /* last arg is server name */
  servername = argv[optind];

  /* map port -> num */
  serv = getservbyname(portstr, "tcp");
  if (serv == NULL) {
      port = atoi(portstr);
  } else {
      port = ntohs(serv->s_port);
  }

  if (init_net(servername, port) != IMTEST_OK) {
      imtest_fatal("Network initialization");
  }
  
  if (init_sasl(servername, port, ssf) != IMTEST_OK) {
      imtest_fatal("SASL initialization");
  }
  
  /* set up the prot layer */
  pin = prot_new(sock, 0);
  pout = prot_new(sock, 1); 
  
  mechlist=read_capability(&version);
  
  if (mechanism!=NULL) {
      result=auth_sasl(version,mechanism);
  } else if (mechlist==NULL) {
      printf("Error reading mechanism list from server\n");
      exit(1);
  } else {
      result=auth_sasl(version,mechlist);
  }
  
  if (result!=IMTEST_OK) {
      printf("Authentication failed.\n");
      exit(1);
  }
  
  if (viewfile!=NULL)
  {
      getscript(version,pout,pin, viewfile,0);
  }
  
  if (installfile!=NULL)
  {
      installafile(version,pout,pin,installfile);
  }
  
  if (setactive!=NULL)
  {
      setscriptactive(version,pout,pin,setactive);
  }
  
  if (deletescript!=NULL)
  {
      deleteascript(version,pout, pin, deletescript);
  }
  
  if (getscriptname!=NULL)
  {
      getscript(version,pout,pin, getscriptname,1);
  }
  
  if (dolist || deflist) {
      showlist(version,pout,pin);
  }

  return 0;
}
