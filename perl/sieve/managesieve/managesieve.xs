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

#include <sasl.h>

typedef struct xscyrus *Sieveobj;

#include "isieve.h"

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

int
fatal(s,t)
char *s;
int t;
{
    croak("failure: %s", s);
    return -1;
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
        *psecret = malloc(sizeof(sasl_secret_t)+strlen(tmp));
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
		printf("Bad callback\n");
		return SASL_FAIL;
	}

        PUTBACK ;
        count = perl_call_sv(func, G_SCALAR);
        SPAGAIN ;
        if (count != 1)
            croak("Big trouble\n") ;
        tmp = POPp;

        /* copy result */
        *result = malloc(strlen(tmp));
        if (!*result) return SASL_NOMEM;
        strcpy(*result,tmp);
        if (len) *len = strlen(*result);

        PUTBACK ;
        FREETMPS ;
        LEAVE ;

        PUTBACK ;

        return SASL_OK;
}


static void
call_listcb(name, isactive, rock)
char *name;
int isactive;
SV *    rock;
{
        dSP ;
        PUSHMARK(sp) ;
        XPUSHs(sv_2mortal(newSVpv(name, 0)));
        XPUSHs(sv_2mortal(newSViv(isactive)));
        PUTBACK ;

        /* call perl func */
        perl_call_sv(rock, G_DISCARD) ;
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
  sasl_callback_t callbacks[10];
  int sock;
  sasl_conn_t *saslconn;
  int port;
  struct servent *serv;
  char *mechlist=NULL;
  isieve_t *obj;

  CODE:

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
  callbacks[3].context = username_cb;
  callbacks[4].id = SASL_CB_LIST_END;

  /* map port -> num */
  serv = getservbyname("sieve", "tcp");
  if (serv == NULL) {
      port = 2000;
  } else {
      port = ntohs(serv->s_port);
  }

  if (init_net(servername, port, &obj)) {
	printf("network init failure!\n");
  }

  if (init_sasl(obj, 128, callbacks)) {
      printf("sasl init failure!\n");
  }
  
  ret = malloc(sizeof(struct xscyrus));
  ret->class = safemalloc(10);
  strcpy(ret->class,"foo");
  ret->isieve = obj;
  
  mechlist=read_capability(obj);

  if (auth_sasl(mechlist, obj)) {
      printf("auth failed\n");
  }

  ST(0) = sv_newmortal();
  sv_setref_pv(ST(0), ret->class, (void *) ret);


int
sieve_put_file(obj, filename)
  Sieveobj obj
  char *filename
  PREINIT:
  int ret;

  CODE:

  ret = isieve_put_file(obj->isieve, filename);

  ST(0) = sv_newmortal();
  sv_setnv( ST(0), ret);


int
sieve_put(obj,name,data)
  Sieveobj obj
  char *name
  char *data

  PREINIT:
  int ret;

  CODE:

  ret = isieve_put(obj->isieve, name, data, strlen(data));

  ST(0) = sv_newmortal();
  sv_setnv( ST(0), ret);


int
sieve_delete(obj,name)
  Sieveobj obj
  char *name

  PREINIT:
  int ret;

  CODE:

  ret = isieve_delete(obj->isieve, name);

  ST(0) = sv_newmortal();
  sv_setnv( ST(0), ret);

int
sieve_list(obj,cb)
  Sieveobj obj
  SV *cb


  PREINIT:
  int ret;

  CODE:

  ret = isieve_list(obj->isieve,
                    &call_listcb,
                    cb);


  ST(0) = sv_newmortal();
  sv_setnv( ST(0), ret);


int
sieve_activate(obj,name)
  Sieveobj obj
  char *name

  PREINIT:
  int ret;

  CODE:

  ret = isieve_activate(obj->isieve, name);

  ST(0) = sv_newmortal();
  sv_setnv( ST(0), ret);

int
sieve_get(obj,name,output)
  Sieveobj obj
  char *name
  char *output

  PREINIT:
  int ret;
  char *a;

  CODE:

  ret = isieve_get(obj->isieve, name, &output);  

  ST(0) = sv_newmortal();
  sv_setnv( ST(0), ret);

  OUTPUT:
  output