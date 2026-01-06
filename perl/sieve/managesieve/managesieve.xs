/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
}
#endif

#include <netdb.h>
#include <netinet/in.h>
#include <sys/file.h>
#include <sys/socket.h>

#include "managesieve/managesieve.h"

typedef struct xscyrus *Sieveobj;
static char *globalerr = NULL;

#include "isieve.h"
#include "util.h"
#include "xmalloc.h"

void fatal(const char *s, int t)
{
    croak("failure: %s", s);
    exit(-1);
}

static int perlsieve_getpass(sasl_conn_t *conn, void *context,
                             int id, sasl_secret_t **psecret)
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
    *psecret = xmalloc(sizeof(sasl_secret_t) + strlen(tmp) + 2);
    strcpy((char *) (*psecret)->data ,tmp);
    (*psecret)->len = strlen(tmp);

    PUTBACK ;
    FREETMPS ;
    LEAVE ;

    PUTBACK ;

    return SASL_OK;
}

static int perlsieve_simple(void *context, int id,
                            unsigned char **result, unsigned *len)
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
    *result = xmalloc(strlen(tmp) + 2);
    strcpy((char *) *result, tmp);
    if (len) *len = strlen((char *) *result);

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
    XPUSHs(sv_2mortal(newSVpv((const char *) name, 0)));
    XPUSHs(sv_2mortal(newSViv(isactive)));
    PUTBACK ;

    /* call perl func */
    perl_call_sv((SV *)rock, G_DISCARD) ;
    return NULL;
}


MODULE = Cyrus::SIEVE::managesieve              PACKAGE = Cyrus::SIEVE::managesieve
PROTOTYPES: ENABLE



Sieveobj
sieve_get_handle(char *servername, SV *username_cb, SV *authname_cb, SV *password_cb, SV *realm_cb)

  PREINIT:
    Sieveobj ret = NULL;
    sasl_callback_t *callbacks;
    int port;
    int r;
    struct servent *serv;
    char *mechlist=NULL,*mlist=NULL;
    const char *mtried;
    isieve_t *obj;
    char *p;
    sasl_ssf_t ssf;

  CODE:

    /* xxx this gets leaked! */
    callbacks = safemalloc(5 * sizeof(sasl_callback_t));

    callbacks[0].id = SASL_CB_USER;
    callbacks[0].proc = (int (*)(void))&perlsieve_simple;
    callbacks[0].context = username_cb;
    callbacks[1].id = SASL_CB_AUTHNAME;
    callbacks[1].proc = (int (*)(void))&perlsieve_simple;
    callbacks[1].context = authname_cb;
    callbacks[2].id = SASL_CB_GETREALM;
    callbacks[2].proc = (int (*)(void))&perlsieve_simple;
    callbacks[2].context = realm_cb;
    callbacks[3].id = SASL_CB_PASS;
    callbacks[3].proc = (int (*)(void))&perlsieve_getpass;
    callbacks[3].context = password_cb;
    callbacks[4].id = SASL_CB_LIST_END;

    /* see if we have server:port (or IPv6, etc)*/
    p = servername;
    if (*servername == '[') {
        if ((p = strrchr(servername + 1, ']')) != NULL) {
            *p++ = '\0';
            servername++;                       /* skip first bracket */
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
            port = 4190;
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
        sieve_free_net(obj);
        XSRETURN_UNDEF;
    }

    ret = xmalloc(sizeof(struct xscyrus));
    ret->class = safemalloc(20);
    strcpy(ret->class,"managesieve");
    ret->isieve = obj;
    ret->errstr = NULL;

    mechlist=read_capability(obj);
    if (!mechlist) {
        globalerr = "sasl mech list empty";
        free(ret);
        XSRETURN_UNDEF;
    }

    mlist = (char*) xstrdup(mechlist);

    /* loop through all the mechanisms */
    do {
        mtried = NULL;
        r = auth_sasl(mlist, obj, &mtried, &ssf, &globalerr);

        if (r) init_sasl(obj, 128, callbacks);

        if (mtried) {
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

    if (r) {
        /* we failed */
        safefree(ret->class);
        free(ret);
        free(mechlist);
        XSRETURN_UNDEF;
    }

    if (ssf) {
        /* SASL security layer negotiated --
           check if SASL mech list changed */
        if (detect_mitm(obj, mechlist)) {
            globalerr = "possible MITM attack: "
                "list of available SASL mechanisms changed";
            free(ret);
            free(mechlist);
            XSRETURN_UNDEF;
        }
    }
    free(mechlist);

    ST(0) = sv_newmortal();
    sv_setref_pv(ST(0), ret->class, (void *) ret);

char *
sieve_get_error(Sieveobj obj)
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
sieve_logout(Sieveobj obj)
  CODE:
    /* xxx this leaves the object unusable */
    isieve_logout(&(obj->isieve));
    XSRETURN_UNDEF;

int
sieve_put_file(Sieveobj obj, char *filename)
  CODE:
    RETVAL = isieve_put_file(obj->isieve, filename, NULL, &obj->errstr);
  OUTPUT:
    RETVAL

int
sieve_put_file_withdest(Sieveobj obj, char *filename, char *destname)
  CODE:
    RETVAL = isieve_put_file(obj->isieve, filename, destname, &obj->errstr);
  OUTPUT:
    RETVAL

int
sieve_put(Sieveobj obj, char *name, char *data)
  CODE:
    RETVAL = isieve_put(obj->isieve, name, data, strlen(data), &obj->errstr);
  OUTPUT:
    RETVAL

int
sieve_delete(Sieveobj obj, char *name)
  CODE:
    RETVAL = isieve_delete(obj->isieve, name, &obj->errstr);
  OUTPUT:
    RETVAL

int
sieve_list(Sieveobj obj, SV *cb)
  CODE:
    RETVAL = isieve_list(obj->isieve, (isieve_listcb_t *) &call_listcb,
                         cb, &obj->errstr);
  OUTPUT:
    RETVAL

int
sieve_activate(Sieveobj obj, char *name)
  CODE:
    RETVAL = isieve_activate(obj->isieve, name, &obj->errstr);
  OUTPUT:
    RETVAL

int
sieve_get(Sieveobj obj, char *name, char *output)
  CODE:
    RETVAL = isieve_get(obj->isieve, name, &output, &obj->errstr);

  OUTPUT:
    RETVAL
    output
