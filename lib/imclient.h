/* imclient.h -- Streaming IMxP client library
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */
struct imclient_reply {
    char *keyword;		/* reply keyword */
    long msgno;			/* message number (-1 = no message number) */
    char *text;			/* subsequent text */
};


/* Flags for untagged-reply callbacks */
#define CALLBACK_NUMBERED 1	/* Has a message sequence number */
#define CALLBACK_NOLITERAL 2	/* Data cannot contain a literal */

/* Connection flags */
#define IMCLIENT_CONN_NOWAITLITERAL 1 /* Server supports no-wait literals */

#ifdef __STDC__
struct imclient;
extern int imclient_connect(struct imclient **, char *, char *);
extern void imclient_close(struct imclient *);
extern void imclient_setflags(struct imclient *, int);
extern void imclient_clearflags(struct imclient *, int);
extern char *imclient_servername(struct imclient *);
extern void imclient_addcallback(struct imclient *, ...);
extern void imclient_send(struct imclient *, void (*)(), void *, char *, ...);
extern void imclient_processoneevent(struct imclient *);
extern int imclient_authenticate(struct imclient *, struct acte_client **,
				 char *, int);
#else
extern char *imclient_servername();
extern void imclient_close();
extern void imclient_setflags();
extern void imclient_clearflags();
extern void imclient_processoneevent();
extern void imclient_addcallback();
extern void imclient_send();
#endif
