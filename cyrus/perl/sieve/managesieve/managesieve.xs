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

/* $Id: managesieve.xs,v 1.18.4.3 2003/02/12 19:12:52 rjs3 Exp $ */

#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
}
#endif

#include "managesieve.h"

#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>

typedef struct xscyrus *Sieveobj;
static char *globalerr = NULL;

#include "isieve.h"

#include "xmalloc.h"

static int
not_here(s)
char *s;
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

static double
constant(name, arg)
char *name;
int arg;
{
    errno = 0;
    switch (*name) {
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

void fatal(const char *s, int t)
{
    croak("failure: %s", s);
    exit(-1);
}

static int
perlsieve_getpass(conn, context, id, psecret)
	sasl_conn_t *conn;
	void *context;
	int id;
        sasl_secret_t **psecret;
{
        int count;
        dSP ;
        char *tmp;
        SV * func = (SV *) context;

        ENTER ;
        SAVETMPS;
        PUSHMARK(sp) ;

        XPUSHs(sv_2mortal(newSVpv("password", 0)));
	XPUSHs(sv_2mortal(newSVpv("Please enter your password", 0)));

        PUTBACK ;
        count = perl_call_sv(func, G_SCALAR);
        SPAGAIN ;
        if (count != 1)
            croak("Big trouble\n") ;
        tmp = POPp;

        /* copy result */
        *psecret = malloc(sizeof(sasl_secret_t) + strlen(tmp) + 2);
        if (!*psecret) return SASL_NOMEM;
        strcpy( (*psecret)->data ,tmp);
        (*psecret)->len = strlen(tmp);

        PUTBACK ;
        FREETMPS ;
        LEAVE ;

        PUTBACK ;

        return SASL_OK;
}

static int
perlsieve_simple(context, id, result, len)
	void *context;
        int id;
	unsigned char **result;
        unsigned *len;
{
        int count;
        dSP ;
        char *tmp;
        SV * func = (SV *) context;

        ENTER ;
        SAVETMPS;
        PUSHMARK(sp) ;
	if (id == SASL_CB_USER) {
	        XPUSHs(sv_2mortal(newSVpv("username", 0)));
		XPUSHs(sv_2mortal(newSVpv("Please enter your username", 0)));
	} else if (id == SASL_CB_AUTHNAME) {
	        XPUSHs(sv_2mortal(newSVpv("authname", 0)));
		XPUSHs(sv_2mortal(newSVpv("Please enter your authentication name", 0)));
	} else if (id == SASL_CB_GETREALM) {
	        XPUSHs(sv_2mortal(newSVpv("realm", 0)));
		XPUSHs(sv_2mortal(newSVpv("Please enter your realm", 0)));
	} else {
	        croak("Bad callback\n");
		return SASL_FAIL;
	}

        PUTBACK ;
        count = perl_call_sv(func, G_SCALAR);
        SPAGAIN ;
        if (count != 1)
            croak("Big trouble\n") ;
        tmp = POPp;

        /* copy result */
        *result = malloc(strlen(tmp) + 2);
        if (!*result) return SASL_NOMEM;
        strcpy(*result,tmp);
        if (len) *len = strlen(*result);

        PUTBACK ;
        FREETMPS ;
        LEAVE ;

        PUTBACK ;

        return SASL_OK;
}


static void *
call_listcb(unsigned char *name, int isactive, void *rock)
{
        dSP ;
        PUSHMARK(sp) ;
        XPUSHs(sv_2mortal(newSVpv(name, 0)));
        XPUSHs(sv_2mortal(newSViv(isactive)));
        PUTBACK ;

        /* call perl func */
        perl_call_sv((SV *)rock, G_DISCARD) ;
	return NULL;
}


MODULE = Cyrus::SIEVE::managesieve		PACKAGE = Cyrus::SIEVE::managesieve
PROTOTYPES: ENABLE



Sieveobj
sieve_get_handle(servername, username_cb, authname_cb, password_cb, realm_cb)
  char *servername
  SV *username_cb
  SV *authname_cb
  SV *password_cb
  SV *realm_cb

  PREINIT:
  Sieveobj ret = NULL;
  sasl_callback_t *callbacks;
  int sock,port;
  sasl_conn_t *saslconn;
  int r;
  struct servent *serv;
  char *mechlist=NULL,*mlist=NULL;
  const char *mtried;
  isieve_t *obj;
  char *p;

  CODE:

  /* xxx this gets leaked! */
  callbacks = safemalloc(5 * sizeof(sasl_callback_t));

  callbacks[0].id = SASL_CB_USER;
  callbacks[0].proc = &perlsieve_simple;
  callbacks[0].context = username_cb;
  callbacks[1].id = SASL_CB_AUTHNAME;
  callbacks[1].proc = &perlsieve_simple;
  callbacks[1].context = authname_cb;
  callbacks[2].id = SASL_CB_GETREALM;
  callbacks[2].proc = &perlsieve_simple;
  callbacks[2].context = realm_cb;
  callbacks[3].id = SASL_CB_PASS;
  callbacks[3].proc = &perlsieve_getpass;
  callbacks[3].context = password_cb;
  callbacks[4].id = SASL_CB_LIST_END;

  /* see if we have server:port (or IPv6, etc)*/
  p = servername;
  if (*servername == '[') {
      if ((p = strrchr(servername + 1, ']')) != NULL) {
	  *p++ = '\0';
	  servername++;			/* skip first bracket */
      } else
	  p = servername;
  }
  if ((p = strchr(p, ':'))) {
      *p++ = '\0';
      port = atoi(p);
  } else {
      /* map port -> num */
      serv = getservbyname("sieve", "tcp");
      if (serv == NULL) {
	  port = 2000;
      } else {
	  port = ntohs(serv->s_port);
      }
  }

  if (init_net(servername, port, &obj)) {
      globalerr = "network initialization failed";
      XSRETURN_UNDEF;
  }

  if (init_sasl(obj, 128, callbacks)) {
      globalerr = "sasl initialization failed";
      XSRETURN_UNDEF;
  }
  
  ret = malloc(sizeof(struct xscyrus));
  ret->class = safemalloc(20);
  strcpy(ret->class,"managesieve");
  ret->isieve = obj;
  ret->errstr = NULL;
  
  mechlist=read_capability(obj);
  if(!mechlist) {
	globalerr = "sasl mech list empty";
	XSRETURN_UNDEF;
  }

  mlist = (char*) xstrdup(mechlist);
  if(!mlist) {
	globalerr = "could not allocate memory for mech list";
	XSRETURN_UNDEF;
  }

  /* loop through all the mechanisms */
  do {
    mtried = NULL;
    r = auth_sasl(mlist, obj, &mtried, &globalerr);

    if(r) init_sasl(obj, 128, callbacks);

    if(mtried) {
	char *newlist = (char*) xmalloc(strlen(mlist)+1);
	char *mtr = (char*) xstrdup(mtried);
	char *tmp;

	ucase(mtr);
	tmp = strstr(mlist,mtr);
	*tmp ='\0';
	strcpy(newlist, mlist);
	tmp++;

	tmp = strchr(tmp,' ');
        if (tmp) {
	    strcat(newlist,tmp);
	}

	free(mtr);
	free(mlist);
	mlist = newlist;
    }
  } while (r && mtried);

  if(r) {
	/* we failed */
	free(ret->class);
	free(ret);
	XSRETURN_UNDEF;
  }
  ST(0) = sv_newmortal();
  sv_setref_pv(ST(0), ret->class, (void *) ret);

char *
sieve_get_error(obj)
  Sieveobj obj
  CODE:
    RETVAL = obj->errstr;
  OUTPUT:
    RETVAL

char *
sieve_get_global_error()
  CODE:
    RETVAL = globalerr;
  OUTPUT:
    RETVAL

int
sieve_logout(obj)
  Sieveobj obj
  CODE:
	/* xxx this leaves the object unusable */
	isieve_logout(&(obj->isieve));
	XSRETURN_UNDEF;

int
sieve_put_file(obj, filename)
  Sieveobj obj
  char *filename
  CODE:
    RETVAL = isieve_put_file(obj->isieve, filename, NULL, &obj->errstr);
  OUTPUT:
    RETVAL

int
sieve_put_file_withdest(obj, filename, destname)
  Sieveobj obj
  char *filename
  char *destname
  CODE:
    RETVAL = isieve_put_file(obj->isieve, filename, destname, &obj->errstr);
  OUTPUT:
    RETVAL

int
sieve_put(obj,name,data)
  Sieveobj obj
  char *name
  char *data

  CODE:
    RETVAL = isieve_put(obj->isieve, name, data, strlen(data), &obj->errstr);
  OUTPUT:
    RETVAL

int
sieve_delete(obj,name)
  Sieveobj obj
  char *name

  CODE:
    RETVAL = isieve_delete(obj->isieve, name, &obj->errstr);
  OUTPUT:
    RETVAL

int
sieve_list(obj,cb)
  Sieveobj obj
  SV *cb

  CODE:
    RETVAL = isieve_list(obj->isieve, (isieve_listcb_t *) &call_listcb,
			 cb, &obj->errstr);
  OUTPUT:
    RETVAL

int
sieve_activate(obj,name)
  Sieveobj obj
  char *name

  CODE:
    RETVAL = isieve_activate(obj->isieve, name, &obj->errstr);
  OUTPUT:
    RETVAL

int
sieve_get(obj,name,output)
  Sieveobj obj
  char *name
  char *output

  CODE:
    RETVAL = isieve_get(obj->isieve, name, &output, &obj->errstr);  

  OUTPUT:
  RETVAL
  output
