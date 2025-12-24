/* imclient.h -- Streaming IMxP client library */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_IMCLIENT_H
#define INCLUDED_IMCLIENT_H

#include <sasl/sasl.h>

struct imclient;
struct sasl_client; /* to avoid having to include sasl sometimes */

struct imclient_reply {
    char *keyword;              /* reply keyword */
    long msgno;                 /* message number (-1 = no message number) */
    char *text;                 /* subsequent text */
};

/* Flags for untagged-reply callbacks */
#define CALLBACK_NUMBERED 1     /* Has a message sequence number */
#define CALLBACK_NOLITERAL 2    /* Data cannot contain a literal */

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

extern int imclient_havetls (void);

extern int imclient_starttls(struct imclient *imclient,
                             char *cert_file,
                             char *key_file,
                             char *CAfile,
                             char *CApath);

void imclient_write (struct imclient *imclient,
                            const char *s, size_t len);

#endif /* INCLUDED_IMCLIENT_H */
