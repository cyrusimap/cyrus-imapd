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
/* $Id: xsutil.c,v 1.4 2002/05/25 19:57:49 leg Exp $ */
/*
 * Various C functions in support of the Cyrus Perl interface.
 */

#include "EXTERN.h"
#include "perl.h"
#include <imclient.h>
#define CYRPERL_INTERNAL
#include "cyrperl.h"

/* hack, since libcyrus apparently expects fatal() to exist */
void
fatal(char *s, int exit)
{
  croak(s);
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
  sv_setref_pv(rv, rock->client->class, (void *) rock->client);
  rock->client->cnt++;
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
    XPUSHs(sv_2mortal(newSVpv("-msgno", 0)));
    XPUSHi(reply->msgno);
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

  SvREFCNT_dec(SvRV(rock->prock));
  SvRV(rock->prock) = (SV *) av = newAV();
  av_push(av, newSVpv(reply->keyword, 0));
  av_push(av, newSVpv(reply->text, 0));
  if (reply->msgno != -1) av_push(av, newSViv(reply->msgno));
  /* clean up */
  if (rock->autofree) imclient_xs_callback_free(rock);
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
    if (rock->pcb) SvREFCNT_dec(rock->pcb);
    if (rock->prock) SvREFCNT_dec(rock->prock);
    safefree(rock);
  }
}
