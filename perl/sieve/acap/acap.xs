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

/* $Id: acap.xs,v 1.6 2002/05/25 19:57:50 leg Exp $ */

#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
}
#endif

#include "acap.h"

typedef struct xscyrus *Sieveobj;

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
   int ret;
   return 0; /*xxx */
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
        *result = malloc(strlen(tmp)+1);
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


MODULE = Cyrus::SIEVE::acap		PACKAGE = Cyrus::SIEVE::acap
PROTOTYPES: ENABLE



Sieveobj
sieve_get_handle(servername, username_cb, authname_cb, password_cb, realm_cb)
  char *servername
  SV *username_cb
  SV *authname_cb
  SV *password_cb
  SV *realm_cb

  PREINIT:
  acapsieve_handle_t *handle;
  Sieveobj ret = NULL;
  sasl_callback_t callbacks[10];
  char *username;

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

  perlsieve_simple(username_cb, SASL_CB_USER, &username, NULL);
 
  handle = acapsieve_connect(username, servername, (void *) callbacks);

  if (handle) {
	  ret = malloc(sizeof(struct xscyrus));
	  ret->handle = handle;
	  ret->class = safemalloc(10);
	  strcpy(ret->class,"foo");
  } else {
	ret = 0;
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

  ret = acapsieve_put_file(obj->handle, filename);

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

  ret = acapsieve_put_simple(obj->handle,
                             name,
                             data,
                             strlen(data));

  ST(0) = sv_newmortal();
  sv_setnv( ST(0), ret);


int
sieve_delete(obj,name)
  Sieveobj obj
  char *name

  PREINIT:
  int ret;

  CODE:

  ret = acapsieve_delete(obj->handle,
                         name);

  ST(0) = sv_newmortal();
  sv_setnv( ST(0), ret);

int
sieve_list(obj,cb)
  Sieveobj obj
  SV *cb


  PREINIT:
  int ret;

  CODE:

  ret = acapsieve_list(obj->handle,
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

  ret = acapsieve_activate(obj->handle,
                           name);

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

  ret = acapsieve_get(obj->handle,
	              name,
                      &output);

  ST(0) = sv_newmortal();
  sv_setnv( ST(0), ret);

  OUTPUT:
  output
