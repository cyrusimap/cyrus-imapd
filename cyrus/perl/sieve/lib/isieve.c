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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

#include <sasl.h>

#include "isieve.h"
#include "lex.h"
#include "request.h"

#include <prot.h>


struct iseive_s {
    
    char *serverFQDN;
    int port;

    int sock;

    sasl_conn_t *conn;

    int version;

    struct protstream *pin;
    struct protstream *pout;

};

/* initialize the network */
int init_net(char *serverFQDN, int port, isieve_t **obj)
{
  struct sockaddr_in addr;
  struct hostent *hp;
  int sock;

  if ((hp = gethostbyname(serverFQDN)) == NULL) {
    perror("gethostbyname");
    return -1;
  }

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return -1;
  }

  addr.sin_family = AF_INET;
  memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
  addr.sin_port = htons(port);

  if (connect(sock, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    perror("connect");
    return -1;
  }

  *obj = (isieve_t *) malloc(sizeof(isieve_t));
  if (!*obj) return -1;

  memset(*obj, '\0', sizeof(isieve_t));

  (*obj)->sock = sock;
  (*obj)->serverFQDN = serverFQDN;
  (*obj)->port = port;

  /* set up the prot layer */
  (*obj)->pin = prot_new(sock, 0);
  (*obj)->pout = prot_new(sock, 1); 

  return 0;
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

int init_sasl(isieve_t *obj,
	      int ssf,
	      sasl_callback_t *callbacks)
{
  int saslresult;
  sasl_security_properties_t *secprops=NULL;
  socklen_t addrsize=sizeof(struct sockaddr_in);
  struct sockaddr_in *saddr_l=malloc(sizeof(struct sockaddr_in));
  struct sockaddr_in *saddr_r=malloc(sizeof(struct sockaddr_in));

  /* attempt to start sasl */
  saslresult=sasl_client_init(callbacks);

  if (saslresult!=SASL_OK) return -1;

  /* client new connection */
  saslresult=sasl_client_new("imap",
			     obj->serverFQDN,
			     NULL,
			     0,
			     &obj->conn);

  if (saslresult!=SASL_OK) return -1;

  /* create a security structure and give it to sasl */
  secprops = make_secprops(0, ssf);
  if (secprops != NULL)
  {
    sasl_setprop(obj->conn, SASL_SEC_PROPS, secprops);
    free(secprops);
  }

  if (getpeername(obj->sock,(struct sockaddr *)saddr_r,&addrsize)!=0)
    return -1;

  if (sasl_setprop(obj->conn, SASL_IP_REMOTE, saddr_r)!=SASL_OK)
    return -1;
  
  addrsize=sizeof(struct sockaddr_in);
  if (getsockname(obj->sock,(struct sockaddr *)saddr_l,&addrsize)!=0)
    return -1;

  /* set the port manually since getsockname is stupid and doesn't */
  saddr_l->sin_port = htons(obj->port);

  if (sasl_setprop(obj->conn, SASL_IP_LOCAL, saddr_l)!=SASL_OK)
    return -1;


  /* should be freed */
  free(saddr_l);
  free(saddr_r);
  
  return 0;
}

char * read_capability(isieve_t *obj)
{
  lexstate_t state;
  char *cap = NULL;

  obj->version = NEW_VERSION;

  while (yylex(&state,obj->pin)==STRING)
  {
      char *attr = string_DATAPTR(state.str);
      char *val = NULL;

      if (yylex(&state,obj->pin)==' ')
      {
	  if (yylex(&state,obj->pin)!=STRING)
	  {
	      parseerror("STRING");
	  }
	  val = string_DATAPTR(state.str);
	  if (yylex(&state,obj->pin)!=EOL)
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
	  obj->version = OLD_VERSION;
	  cap = (char *) malloc(strlen(val));
	  memset(cap, '\0', strlen(val));
	  memcpy(cap, val+6, strlen(val)-7);

	  return cap;
      } else {
	  /* unkown capability */
      }
  }

  if (yylex(&state,obj->pin)!=EOL)
  {
      parseerror("EOL2");
  }
  
  return cap;
}

static int getauthline(isieve_t *obj, char **line, unsigned int *linelen,
		       char **errstrp)
{
  lexstate_t state;
  int res;
  int ret;
  mystring_t *errstr;

  /* now let's see what the server said */
  res=yylex(&state, obj->pin);
  if (res!=STRING)
  {
      ret = handle_response(res,obj->version,
			    obj->pin, &errstr);

    if (res==TOKEN_OK) {
      return STAT_OK;
    } else { /* server said no */
	*errstrp = string_DATAPTR(errstr);
	return STAT_NO;
    }
  }

  *line=(char *) malloc(state.str->len*2+1);

  sasl_decode64(string_DATAPTR(state.str), state.str->len,
		*line, linelen);

  if (yylex(&state, obj->pin)!=EOL)
      return STAT_NO;

  return STAT_CONT;
}


int auth_sasl(char *mechlist, isieve_t *obj, char **errstr)
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
    saslresult=sasl_client_start(obj->conn, mechlist,
				 NULL, &client_interact,
				 &out, &outlen,
				 &mechusing);
    if (saslresult==SASL_INTERACT)
      fillin_interactions(client_interact); /* fill in prompts */      

  }

  if ((saslresult!=SASL_OK) && (saslresult!=SASL_CONTINUE)) return saslresult;

  if (out!=NULL)
  {
    prot_printf(obj->pout,"AUTHENTICATE \"%s\" ",mechusing);

    sasl_encode64(out, outlen,
		  inbase64, sizeof(inbase64), &inbase64len);

    prot_printf(obj->pout, "{%d+}\r\n",inbase64len);
    prot_write(obj->pout,inbase64,inbase64len);
    prot_printf(obj->pout,"\r\n");
  } else {
    prot_printf(obj->pout,"AUTHENTICATE \"%s\"\r\n",mechusing);
  }
  prot_flush(obj->pout);

  inlen = 0;
  status = getauthline(obj,&in,&inlen, errstr);

  while (status==STAT_CONT)
  {
    saslresult=SASL_INTERACT;
    while (saslresult==SASL_INTERACT)
    {
      saslresult=sasl_client_step(obj->conn,
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
	*errstr = strdup(sasl_errstring(saslresult,NULL,NULL));
	return saslresult;
    }

    /* send to server */

    sasl_encode64(out, outlen,
		  inbase64, sizeof(inbase64), &inbase64len);

    prot_printf(obj->pout, "{%d+}\r\n",inbase64len);
    prot_flush(obj->pout);
    prot_write(obj->pout,inbase64,inbase64len);
    prot_flush(obj->pout);
    prot_printf(obj->pout,"\r\n");
    prot_flush(obj->pout);

    /* get reply */
    status=getauthline(obj,&in,&inlen, errstr);
  }
  
  return (status == STAT_OK) ? 0 : -1;
}


int isieve_put_file(isieve_t *obj, char *filename, char **errstr)
{
    return installafile(obj->version,
			obj->pout, obj->pin,
			filename, errstr);
}

int isieve_put(isieve_t *obj, char *name, char *data, int len, char **errstr)
{
    return installdata(obj->version,
		       obj->pout, obj->pin,
		       name, data, len, errstr);
}

int isieve_delete(isieve_t *obj, char *name, char **errstr)
{
    return deleteascript(obj->version,
			 obj->pout, obj->pin,
			 name, errstr);
}

int isieve_list(isieve_t *obj, isieve_listcb_t *cb,void *rock, char **errstr)
{
    return list_wcb(obj->version, obj->pout, obj->pin, cb, rock);
}

int isieve_activate(isieve_t *obj, char *name, char **errstr)
{
    return setscriptactive(obj->version,obj->pout, obj->pin, name, errstr);
}

int isieve_get(isieve_t *obj,char *name, char **output, char **errstr)
{
    int ret;
    mystring_t *mystr = NULL;

    ret = getscriptvalue(obj->version,obj->pout, obj->pin,
			 name, &mystr, errstr);

    *output = string_DATAPTR(mystr);

    return ret;
}
