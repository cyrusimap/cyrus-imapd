/* imclient.h -- Streaming IMxP client library
 $Id: imclient.h,v 1.23 2002/04/23 20:47:44 rjs3 Exp $
 
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
 *
 */

#ifndef INCLUDED_IMCLIENT_H
#define INCLUDED_IMCLIENT_H

#include <sasl/sasl.h>

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

typedef void imclient_proc_t(struct imclient *imclient, void *rock,
			     struct imclient_reply *reply);

extern int imclient_connect(struct imclient **imclient, const char *host,
			    const char *port, sasl_callback_t *cbs);
extern void imclient_close(struct imclient *imclient);
extern void imclient_setflags(struct imclient *imclient, int flags);
extern void imclient_clearflags(struct imclient *imclient, int flags);
extern char *imclient_servername(struct imclient *imclient);
extern void imclient_addcallback(struct imclient *imclient, ...);
extern void imclient_send(struct imclient *imclient,
			  imclient_proc_t *proc, void *rock,
			  const char *fmt, ...);
extern void imclient_processoneevent(struct imclient *imclient);
extern void imclient_getselectinfo(struct imclient *imclient,
				   int *fd, int *wanttowrite);

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

extern void imclient_write (struct imclient *imclient,
			    const char *s, size_t len);

#endif /* INCLUDED_IMCLIENT_H */
