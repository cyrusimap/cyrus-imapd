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

/* $Id: IMAP.xs,v 1.15.4.2 2002/09/19 18:06:43 ken3 Exp $ */

/*
 * Perl interface to the Cyrus imclient routines.  This enables the
 * use of Perl to implement Cyrus utilities, in particular imtest and cyradm.
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <pwd.h>
#include "imclient.h"
#include "cyrperl.h"
#include "imapurl.h"

typedef struct xscyrus *Cyrus_IMAP;

/* Perl pre-5.6.0 compatibility */
#ifndef aTHX_
#define aTHX_
#endif

/*
 * This is the code from xsutil.c
 */

/* hack, since libcyrus apparently expects fatal() to exist */
void
fatal(char *s, int exit)
{
  croak(s);
}

/*
 * Decrement the refcounts of the Perl SV's in the passed rock, then free the
 * rock.  This cleans up a callback.
 */

void imclient_xs_callback_free(struct xsccb *rock)
{
  struct xscb *xcb;

  if (rock) {
    /* find the destructor-cleanup version and nuke its record */
    for (xcb = rock->client->cb; xcb; xcb = xcb->next) {
      if (xcb->rock == rock) break;
    }
    if (xcb) {
      if (xcb->prev)
	xcb->prev->next = xcb->next;
      else
	rock->client->cb = xcb->next;
      if (xcb->next) xcb->next->prev = xcb->prev;
      if (xcb->name) safefree(xcb->name);
      safefree(xcb);
    }
    /* if (rock->pcb) SvREFCNT_dec(rock->pcb); */
    /* if (rock->prock) SvREFCNT_dec(rock->prock); */
    safefree(rock);
  }
}

/*
 * Invoke a Perl callback on behalf of a Cyrus callback.  This requires some
 * silliness to adapt what we're passed to Perl conventions; specifically,
 * the reply struct becomes a hash (passed as a list).
 */

void imclient_xs_cb(struct imclient *client, struct xsccb *rock,
		    struct imclient_reply *reply)
{
  dSP;
  dTARG;
  SV* rv;

  /* push our args onto Perl's stack */
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  XPUSHs(sv_2mortal(newSVpv("-client", 0)));
  rv = newSVsv(&sv_undef);
  sv_setref_pv(rv, NULL, (void *) rock->client);
  XPUSHs(rv);
  if (rock->prock != &sv_undef) {
    XPUSHs(sv_2mortal(newSVpv("-rock", 0)));
    XPUSHs(sv_mortalcopy(rock->prock));
  }
  XPUSHs(sv_2mortal(newSVpv("-keyword", 0)));
  XPUSHs(sv_2mortal(newSVpv(reply->keyword, 0)));
  XPUSHs(sv_2mortal(newSVpv("-text", 0)));
  XPUSHs(sv_2mortal(newSVpv(reply->text, 0)));
  if (reply->msgno != -1) {
    char tmp[100];
    XPUSHs(sv_2mortal(newSVpv("-msgno", 0)));
    sprintf(tmp,"%d",reply->msgno);
    XPUSHs(sv_2mortal(newSVpv(tmp, 0)));
  }
  PUTBACK;
  /* invoke Perl */
  perl_call_sv(rock->pcb, G_VOID|G_DISCARD);
  FREETMPS;
  LEAVE;
  /* clean up */
  if (rock->autofree) imclient_xs_callback_free(rock);
}

/*
 * Callback used when ::_send is invoked without a callback.  The "prock" is an
 * AV, which is set to the contents of the imclient_reply; this is detected in
 * ::_send, which is calling imclient_processoneevent() repeatedly.  (This
 * simulates a non-callback-based invocation, for trivial clients.)
 */
void imclient_xs_fcmdcb(struct imclient *client, struct xsccb *rock,
			struct imclient_reply *reply)
{
  AV *av;

  /* SvREFCNT_dec(SvRV(rock->prock)); */
  SvRV(rock->prock) = (SV *) (av = newAV());
  /* sv_setsv(rock->prock, sv_2mortal(newRV_inc((SV *) (av = newAV())))); */
  av_push(av, sv_2mortal(newSVpv(reply->keyword, 0)));
  av_push(av, sv_2mortal(newSVpv(reply->text, 0)));
  if (reply->msgno != -1) av_push(av, sv_2mortal(newSViv(reply->msgno)));
  /* clean up */
  if (rock->autofree) imclient_xs_callback_free(rock);
}

static int get_username(void *context, int id,
			const char **result, unsigned *len) {
  Cyrus_IMAP text = (Cyrus_IMAP)context;
  if(id == SASL_CB_AUTHNAME) {
	if(len) *len = strlen(text->authname);
	*result = text->authname;
	return SASL_OK;
  } else if (id == SASL_CB_USER) {
	if(text->username) {
	    if(len) *len = strlen(text->username);
	    *result = text->username;
	} else {
	    if(len) *len = 0;
	    *result = "";
	}
	return SASL_OK;
  } 
  return SASL_FAIL;
}

static int get_password(sasl_conn_t *conn, void *context, int id,
			sasl_secret_t **psecret) {
  Cyrus_IMAP text = (Cyrus_IMAP)context;
  if(id != SASL_CB_PASS) return SASL_FAIL;
  if(!text->password) {
	char *ptr;
	printf("Password: ");
	fflush(stdout);
	ptr = getpass("");
	text->password = safemalloc(sizeof(sasl_secret_t) + strlen(ptr));
	text->password->len = strlen(ptr);
	strncpy(text->password->data, ptr, text->password->len);
  }
  *psecret = text->password;
  return SASL_OK;  
}

/* callbacks we support */
static const sasl_callback_t sample_callbacks[NUM_SUPPORTED_CALLBACKS] = {
  { SASL_CB_USER, get_username, NULL }, 
  { SASL_CB_AUTHNAME, get_username, NULL }, 
  { SASL_CB_PASS, get_password, NULL },
  { SASL_CB_LIST_END, NULL, NULL }
};

MODULE = Cyrus::IMAP	PACKAGE = Cyrus::IMAP
PROTOTYPES: ENABLE

int
CONN_NONSYNCLITERAL()
PPCODE:
	RETVAL = IMCLIENT_CONN_NONSYNCLITERAL;

int
CONN_INITIALRESPONSE()
PPCODE:
	RETVAL = IMCLIENT_CONN_INITIALRESPONSE;

int
CALLBACK_NUMBERED()
PPCODE:
	RETVAL = CALLBACK_NUMBERED;

int
CALLBACK_NOLITERAL()
PPCODE:
	RETVAL = CALLBACK_NOLITERAL;

MODULE = Cyrus::IMAP	PACKAGE = Cyrus::IMAP	PREFIX=imclient_
PROTOTYPES: ENABLE

SV *
imclient_new(class, host = "localhost", port = 0, flags = 0)
	char *class;
	char *host
	char *port
	int flags;
PREINIT:
	struct imclient *client;
	int rc;
	SV *bang;
	Cyrus_IMAP rv;
	int i;
CODE:
	/* Allocate and setup the return value */
	rv = safemalloc(sizeof *rv);

	rv->authenticated = 0;

	memcpy(rv->callbacks, sample_callbacks, sizeof(sample_callbacks));

	/* Setup respective contexts */
	for(i=0; i < NUM_SUPPORTED_CALLBACKS; i++) {
	    rv->callbacks[i].context = rv;
	}

	/* Connect */
	rc = imclient_connect(&client, host, port, rv->callbacks);
	switch (rc) {
	case -1:
	  Perl_croak(aTHX_ "imclient_connect: unknown host \"%s\"", host);
	  safefree(rv);
	  break;
	case -2:
	  Perl_croak(aTHX_ "imclient_connect: unknown service \"%s\"", port);
	  safefree(rv);
	  break;
	case 0:
	  if (client) {
	    rv->class = safemalloc(strlen(class) + 1);
	    strcpy(rv->class, class);
	    rv->username = rv->authname = NULL;
	    rv->password = NULL;
	    rv->imclient = client;
	    imclient_setflags(client, flags);
	    rv->flags = flags;
	    rv->cb = 0;
	    rv->cnt = 1;
	    break;
	  }
	  /*FALLTHROUGH*/
	default:
	  bang = perl_get_sv("^E", TRUE);
	  Perl_sv_setiv(aTHX_ bang, rc);
	  XSRETURN_UNDEF;
	}
	ST(0) = sv_newmortal();
	/* fprintf(stderr, "!NEW %p %s\n", rv, class); */
	sv_setref_pv(ST(0), class, (void *) rv);

void
imclient_DESTROY(client)
	Cyrus_IMAP client
PREINIT:
	struct xscb *nx;
CODE:
/* fprintf(stderr, "!DESTROY %p %d\n", client, client->cnt); */
	if (!--client->cnt) {
/* printf("closing\n"); */
	  imclient_close(client->imclient);
	  while (client->cb) {
	    nx = client->cb->next;
	    if (client->cb->name) safefree(client->cb->name);
	    /* if (client->cb->rock->pcb) SvREFCNT_dec(client->cb->rock->pcb); */
	    /* if (client->cb->rock->prock) SvREFCNT_dec(client->cb->rock->prock); */
	    safefree(client->cb->rock);
	    client->cb = nx;
	  }
	  safefree(client->password);
	  safefree(client->class);
	  safefree(client);
	}

void
imclient_setflags(client, flags)
	Cyrus_IMAP client
	int flags
PPCODE:
	imclient_setflags(client->imclient, flags);
	client->flags |= flags;

void
imclient_clearflags(client, flags)
	Cyrus_IMAP client
	int flags
PPCODE:
	imclient_clearflags(client->imclient, flags);
	client->flags &= ~flags;

int
imclient_flags(client)
	Cyrus_IMAP client
PPCODE:
	/* why is there no way to query this? */
	RETVAL = client->flags;

char *
imclient_servername(client)
	Cyrus_IMAP client
PREINIT:
	char *cp;
CODE:
	cp = imclient_servername(client->imclient);
	RETVAL = cp;
OUTPUT:
	RETVAL

void
imclient_processoneevent(client)
	Cyrus_IMAP client
PPCODE:
	imclient_processoneevent(client->imclient);

SV *
imclient__authenticate(client, mechlist, service, user, auth, password, minssf, maxssf)
	Cyrus_IMAP client
	char* mechlist
	char* service
	char* user
	char* auth
	char* password
	int minssf
	int maxssf
PREINIT:
	int rc;
CODE:
	ST(0) = sv_newmortal();

	if(client->authenticated) {
	  ST(0) = &sv_no;
	  return;
	}

	/* If the user parameter is undef, set user to be NULL */
	if(!SvOK(ST(3))) user = NULL;
	if(!SvOK(ST(5))) password = NULL;

	client->username = user; /* AuthZid */
	client->authname = auth; /* Authid */

	if(password) {
	    if(client->password) safefree(client->password);
	    client->password =
		safemalloc(sizeof(sasl_secret_t) + strlen(password));
	    client->password->len = strlen(password);
	    strncpy(client->password->data, password, client->password->len);
	}

	rc = imclient_authenticate(client->imclient, mechlist, service, user,
				   minssf, maxssf);
	if (rc)
	  ST(0) = &sv_no;
	else {
	  client->authenticated = 1;
	  ST(0) = &sv_yes;
	}

void
imclient_addcallback(client, ...)
	Cyrus_IMAP client
PREINIT:
	int arg;
	HV *cb;
	char *keyword;
	STRLEN klen;
	int flags;
	SV **val;
	SV *pcb;
	SV *prock;
	struct xsccb *rock;
	struct xscb *xcb;
PPCODE:
	/*
	 * $client->addcallback(\%cb[, ...]);
	 *
	 * where %cb is:
	 *
	 * -trigger => 'OK' (or 'NO', etc.)
	 * -flags => CALLBACK_NOLITERAL|CALLBACK_NUMBERED (optional)
	 * -callback => \&sub or undef (optional)
	 * -rock => SV, reference or undef (optional)
	 *
	 * this is moderately complicated because the callback is a Perl ref...
	 */
	for (arg = 1; arg < items; arg++) {
	  if (!SvROK(ST(arg)) || SvTYPE(SvRV(ST(arg))) != SVt_PVHV)
	    Perl_croak(aTHX_ "addcallback: arg %d not a hash reference", arg);
	  cb = (HV *) SvRV(ST(arg));
	  /* pull callback crud */
	  if (((val = hv_fetch(cb, "-trigger", 8, 0)) ||
	       (val = hv_fetch(cb, "Trigger", 7, 0))) &&
	      SvTYPE(*val) == SVt_PV)
	    keyword = SvPV(*val, klen);
	  else
	    Perl_croak(aTHX_ "addcallback: arg %d missing trigger", arg);
	  if ((((val = hv_fetch(cb, "-flags", 6, 0)) ||
		 (val = hv_fetch(cb, "Flags", 5, 0)))))
	  {	
	    flags = SvIV(*val);
          } else {
            flags = 0;
          }

	  if (((val = hv_fetch(cb, "-callback", 9, 0)) ||
	       (val = hv_fetch(cb, "Callback", 8, 0))) &&
	      ((SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVCV) ||
	       SvTYPE(*val) == SVt_PV))
	    pcb = *val;
	  else
	    pcb = 0;
	  if ((val = hv_fetch(cb, "-rock", 5, 0)) ||
	      (val = hv_fetch(cb, "Rock", 4, 0)))
	    prock = *val;
	  else
	    prock = &sv_undef;
	  /*
	   * build our internal rock, which is used by our internal
	   * callback handler to invoke the Perl callback
	   */
	  if (!pcb)
	    rock = 0;
	  else {
	    rock = (struct xsccb *) safemalloc(sizeof *rock);
	    /* bump refcounts on these so they don't go away */
	    rock->pcb = SvREFCNT_inc(pcb);
	    if (!prock) prock = &sv_undef;
	    rock->prock = SvREFCNT_inc(prock);
	    rock->client = client;
	    rock->autofree = 0;
	  }
	  /* and add the resulting callback */
	  imclient_addcallback(client->imclient, keyword, flags,
			       (pcb ? imclient_xs_cb : 0), rock, 0);
	  /* update the callback list, possibly freeing old callback info */
	  for (xcb = client->cb; xcb; xcb = xcb->next) {
	    if (xcb->name && strcmp(xcb->name, keyword) == 0 &&
		xcb->flags == flags)
	      break;
	  }
	  if (xcb) {
	    if (xcb->rock->pcb) SvREFCNT_dec(xcb->rock->pcb);
	    if (xcb->rock->prock) SvREFCNT_dec(xcb->rock->prock);
	    safefree(xcb->rock);
	  }
	  else if (pcb) {
	    xcb = (struct xscb *) safemalloc(sizeof *xcb);
	    xcb->prev = 0;
	    xcb->name = safemalloc(strlen(keyword) + 1);
	    strcpy(xcb->name, keyword);
	    xcb->flags = flags;
	    xcb->next = client->cb;
	    client->cb = xcb;
	  }
	  if (pcb)
	    xcb->rock = rock;
	  else if (xcb) {
	    if (xcb->prev)
	      xcb->prev->next = xcb->next;
	    else
	      client->cb = xcb->next;
	    if (xcb->next) xcb->next->prev = xcb->prev;
	    safefree(xcb->name);
	    safefree(xcb);
	  }
	}
	
void
imclient__send(client, finishproc, finishrock, str)
	Cyrus_IMAP client
	SV *finishproc
	SV *finishrock
	char *str
PREINIT:
	STRLEN arg;
	SV *pcb;
	SV *prock;
	struct xscb *xcb;
	struct xsccb *rock;
	char *cp, *dp, *xstr;
PPCODE:
	/*
	 * The C version does escapes.  It also does varargs, which I would
	 * much rather not have to reimplement in XS code; so that is done in
	 * Perl instead.  (The minus being that I have to track any changes
	 * to the C API; but it'll be easier in Perl than in XS.)
	 *
	 * We still have to do the callback, though.
	 *
	 * @@@ the Perl code can't do synchronous literals
	 */
	if (SvROK(finishproc) && SvTYPE(SvRV(finishproc)) == SVt_PVCV)
	  pcb = SvRV(finishproc);
	else
	  pcb = 0;
	if (!pcb)
	  prock = sv_2mortal(newRV_inc(&PL_sv_undef));
	else if (finishrock)
	  prock = finishrock;
	else
	  prock = sv_2mortal(newSVsv(&PL_sv_undef));
	/*
	 * build our internal rock, which is used by our internal
	 * callback handler to invoke the Perl callback
	 */
	rock = (struct xsccb *) safemalloc(sizeof *rock);
        /* bump refcounts on these so they don't go away */
	if (!pcb) pcb = sv_2mortal(newSVsv(&PL_sv_undef));
	rock->pcb = pcb;
	if (!prock) prock = sv_2mortal(newSVsv(&PL_sv_undef));
	rock->prock = prock;
	rock->client = client;
	rock->autofree = 1;
	/* register this callback so it can be gc'ed properly (pointless?) */
	xcb = (struct xscb *) safemalloc(sizeof *xcb);
	xcb->prev = 0;
	xcb->name = 0;
	xcb->flags = 0;
	xcb->rock = rock;
	xcb->next = client->cb;
	client->cb = xcb;
	/* protect %'s in the string, since the caller does the dirty work */
	arg = 0;
	for (cp = str; *cp; cp++)
	  if (*cp == '%') arg++;
	xstr = safemalloc(strlen(str) + arg + 1);
	dp = xstr;
	for (cp = str; *cp; cp++) {
	  *dp++ = *cp;
	  if (*cp == '%') *dp++ = *cp;
	}
	*dp = 0;
	/* and do it to it */
	imclient_send(client->imclient,
		      (SvTRUE(pcb) ?
		       (void *) imclient_xs_cb :
		       (void *) imclient_xs_fcmdcb),
		      (void *) rock, xstr);
	safefree(xstr);
	/* if there was no Perl callback, spin on events until finished */
	if (!SvTRUE(pcb)) {
	  AV *av;
	  while (SvTYPE(SvRV(prock)) != SVt_PVAV)
	    imclient_processoneevent(client->imclient);
	  /* push the result; if scalar, stuff text in $@ */
	  av = (AV *) SvRV(prock);
	  if (GIMME_V == G_SCALAR) {
	    EXTEND(SP, 1);
	    pcb = av_shift(av);
	    if (strcmp(SvPV(pcb, arg), "OK") == 0)
	      PUSHs(&sv_yes);
	    else
	      PUSHs(&sv_no);
	    pcb = perl_get_sv("@", TRUE);
	    Perl_sv_setsv(aTHX_ pcb, av_shift(av));
	    if (av_len(av) != -1) {
	      pcb = perl_get_sv("^E", TRUE);
	      Perl_sv_setsv(aTHX_ pcb, av_shift(av));
	    }
	  } else {
	    EXTEND(SP, av_len(av) + 1);
	    PUSHs(av_shift(av));
	    PUSHs(av_shift(av));
	    if (av_len(av) != -1) PUSHs(av_shift(av));
	  }
	  /* and free it */
	  /* SvREFCNT_dec(prock); */
	}

void
imclient_getselectinfo(client)
	Cyrus_IMAP client
PREINIT:
	int fd, writep;
PPCODE:
	imclient_getselectinfo(client->imclient, &fd, &writep);
	/*
	 * should this return a glob?  (evil, but would solve a nasty issue
	 * in &send()...)
	 *
	 * also, should this check for scalar context and complain?
	 */
	EXTEND(SP, 2);
	PUSHs(sv_2mortal(newSViv(fd)));
	if (writep)
	  PUSHs(&sv_yes);
	else
	  PUSHs(&sv_no);

void
imclient_fromURL(client,url)
	Cyrus_IMAP client
	char *url
PREINIT:
	SV *out_server, *out_box;
	char *server_buf, *box_buf;
	int len;
PPCODE:
	len = strlen(url);
	server_buf = safemalloc(len);
	box_buf = safemalloc(2*len);

	server_buf[0] = '\0';
	box_buf[0] = '\0';
	imapurl_fromURL(server_buf, box_buf, url);

	if(!server_buf[0] || !box_buf[0]) {
		safefree(server_buf);
		safefree(box_buf);
		XSRETURN_UNDEF;
	}

	XPUSHs(sv_2mortal(newSVpv(server_buf, 0)));
	XPUSHs(sv_2mortal(newSVpv(box_buf, 0)));

	/* newSVpv copies these */
	safefree(server_buf);
	safefree(box_buf);
	
	XSRETURN(2);

void
imclient_toURL(client,server,box)
	Cyrus_IMAP client
	char *server
	char *box
PREINIT:
	SV *out;
	char *out_buf;
	int len;
PPCODE:
	len = strlen(server)+strlen(box);
	out_buf = safemalloc(4*len);

	out_buf[0] = '\0';
	imapurl_toURL(out_buf, server, box, NULL);

	if(!out_buf[0]) {
		safefree(out_buf);
		XSRETURN_UNDEF;
	}

	XPUSHs(sv_2mortal(newSVpv(out_buf, 0)));

	/* newSVpv copies this */
	safefree(out_buf);
	
	XSRETURN(1);
