/* imclient.h -- Streaming IMxP client library
 $Id: imclient.h,v 1.17 2000/01/28 22:09:54 leg Exp $
 
 #        Copyright 1998 by Carnegie Mellon University
 #
 #                      All Rights Reserved
 #
 # Permission to use, copy, modify, and distribute this software and its
 # documentation for any purpose and without fee is hereby granted,
 # provided that the above copyright notice appear in all copies and that
 # both that copyright notice and this permission notice appear in
 # supporting documentation, and that the name of CMU not be
 # used in advertising or publicity pertaining to distribution of the
 # software without specific, written prior permission.
 #
 # CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 # ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 # CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 # ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 # WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 # ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 # SOFTWARE.
 *
 */

#ifndef INCLUDED_IMCLIENT_H
#define INCLUDED_IMCLIENT_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

struct imclient;
struct sasl_client; /* to avoid having to include sasl sometimes */

struct imclient_reply {
    char *keyword;		/* reply keyword */
    long msgno;			/* message number (-1 = no message number) */
    char *text;			/* subsequent text */
};

/* Flags for untagged-reply callbacks */
#define CALLBACK_NUMBERED 1	/* Has a message sequence number */
#define CALLBACK_NOLITERAL 2	/* Data cannot contain a literal */

/* Connection flags */
#define IMCLIENT_CONN_NONSYNCLITERAL 1 /* Server supports non-synchronizing literals */
#define IMCLIENT_CONN_INITIALRESPONSE 1 /* Server supports SASL initial response */

typedef void imclient_proc_t P((struct imclient *imclient, void *rock,
				struct imclient_reply *reply));

extern int imclient_connect P((struct imclient **imclient, const char *host,
			       const char *port));
extern void imclient_close P((struct imclient *imclient));
extern void imclient_setflags P((struct imclient *imclient, int flags));
extern void imclient_clearflags P((struct imclient *imclient, int flags));
extern char *imclient_servername P((struct imclient *imclient));
#ifdef __STDC__
extern void imclient_addcallback(struct imclient *imclient, ...);
extern void imclient_send(struct imclient *imclient,
			  imclient_proc_t *proc, void *rock,
			  const char *fmt, ...);
#else
extern void imclient_addcallback();
extern void imclient_send();
#endif
extern void imclient_processoneevent P((struct imclient *imclient));
extern void imclient_getselectinfo P((struct imclient *imclient,
				      int *fd, int *wanttowrite));

extern int imclient_authenticate(struct imclient *imclient, 
				 char *mechlist, 
				 char *service, 
				 char *user, 
				 int minssf, 
				 int maxssf);


#ifdef HAVE_SSL
extern int imclient_starttls(struct imclient *imclient,
			     int verifydepth,
			     char *var_tls_cert_file, 
			     char *var_tls_key_file,
			     int *layer);
#endif /* HAVE_SSL */



#endif /* INCLUDED_IMCLIENT_H */
