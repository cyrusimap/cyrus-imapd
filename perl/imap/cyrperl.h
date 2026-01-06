/* cyrperl.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/*
 * Internal callback rock, used to invoke arbitrary Perl code via a CODE
 * reference ( \&sub ).  Allocate with Perl's New(), free with Safefree().
 * The Perl callback is a CODE reference; the rock is any Perl value.
 * autofree is nonzero if the C callback routine should decrement the
 * refcounts on the Perl objects and free the callback struct (used by the
 * imclient_send() finish callback).
 */

struct xsccb {
  SV *pcb;                      /* Perl callback PV */
  SV *prock;                    /* Perl rock SV */
  /* gack.  but otherwise we're in even more pain */
  struct xscyrus *client;       /* client object, pre-Perlization */
  int autofree;                 /* nonzero if callback should free it */
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
  int cnt;                      /* hack */
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
