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
/* $Id: cyrperl.h,v 1.6 2002/05/25 19:57:49 leg Exp $ */
/*
 * Internal callback rock, used to invoke arbitrary Perl code via a CODE
 * reference ( \&sub ).  Allocate with Perl's New(), free with Safefree().
 * The Perl callback is a CODE reference; the rock is any Perl value.
 * autofree is nonzero if the C callback routine should decrement the
 * refcounts on the Perl objects and free the callback struct (used by the
 * imclient_send() finish callback).
 */

struct xsccb {
  SV *pcb;			/* Perl callback PV */
  SV *prock;			/* Perl rock SV */
  /* gack.  but otherwise we're in even more pain */
  struct xscyrus *client;	/* client object, pre-Perlization */
  int autofree;			/* nonzero if callback should free it */
};

#ifdef CYRPERL_INTERNAL
#define rock_t struct xsccb *
#else
#define rock_t void *
#endif

/*
 * our wrapper for the cyrus imclient struct.  mainly exists so I can track
 * callbacks without grotting around inside the struct imclient.
 */

struct xscb {
  struct xscb *prev;
  char *name;
  int flags;
  struct xsccb *rock;
  struct xscb *next;
};

#define NUM_SUPPORTED_CALLBACKS 4

struct xscyrus {
  struct imclient *imclient;
  char *class;
  struct xscb *cb;
  int flags;
  int authenticated;
  int cnt;			/* hack */
  /* For holding per-connection information during authentication */
  /* We need to initialize this when we create a new connection */  
  sasl_callback_t callbacks[NUM_SUPPORTED_CALLBACKS];
  const char *username, *authname;
  sasl_secret_t *password;
};

/* C callback to invoke a Perl callback on behalf of imclient */
/*void imclient_xs_cb(struct imclient *, rock_t, struct imclient_reply *);*/

/* C callback to invoke a Perl callback on behalf of imclient_send()'s cb */
/*void imclient_xs_fcmdcb(struct imclient *, rock_t,
  struct imclient_reply *);*/

/* Clean up after a "self-freeing" Perl callback */
/*void imclient_xs_callback_free(struct xsccb *);*/
