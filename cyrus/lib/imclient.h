/* imclient.h -- Streaming IMxP client library
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
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
extern int imclient_authenticate P((struct imclient *imclient,
				    struct sasl_client **availmech,
				    const char *service,
				    const char *user, int protallowed));

#endif /* INCLUDED_IMCLIENT_H */
