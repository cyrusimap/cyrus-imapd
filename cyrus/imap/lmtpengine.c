/* lmtpengine.c: LMTP protocol engine
 * $Id: lmtpengine.c,v 1.46 2002/01/15 20:24:22 rjs3 Exp $
 *
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <com_err.h>
#include <errno.h>
#include <sys/types.h>
#include <limits.h>
#include <sys/wait.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "assert.h"
#include "util.h"
#include "auth.h"
#include "prot.h"
#include "rfc822date.h"
#include "imapconf.h"
#include "iptostring.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "xmalloc.h"
#include "version.h"

#include "lmtpengine.h"
#include "lmtpstats.h"
#include "tls.h"

#define RCPT_GROW 30

/* data per message */
struct Header {
    char *name;
    int ncontents;
    char *contents[1];
};

struct address_data {
    char *user;
    char *all;
    int ignorequota;
    int status;
};

struct clientdata {
    struct protstream *pin;
    struct protstream *pout;
    int fd;

    char clienthost[250];
    char lhlo_param[250];

    sasl_conn_t *conn;

#ifdef HAVE_SSL
    SSL *tls_conn;
#endif /* HAVE_SSL */
    int starttls_done;
};

/* Enable the resetting of a sasl_conn_t */
static int reset_saslconn(sasl_conn_t **conn);

static struct 
{
    char *ipremoteport;
    char *iplocalport;
    sasl_ssf_t ssf;
    char *authid;
} saslprops = {NULL,NULL,0,NULL};

/* a simple hash function for sasl mechanisms */
static int hash_simple (const char *str)
{
    int     value = 0;
    int     i;

    if (!str)
	return 0;
    for (i = 0; *str; i++)
    {
	value ^= (*str++ << ((i & 3)*8));
    }
    return value;
}

/* round to nearest 1024 bytes and return number of Kbytes.
 used for SNMP updates. */
static int roundToK(int x)
{
    double rd = (x*1.0)/1024.0;
    int ri = x/1024;
    
    if (rd-ri < 0.5)
	return ri;
    else
	return ri+1;    
}

static void send_lmtp_error(struct protstream *pout, int r)
{
    switch (r) {
    case 0:
	prot_printf(pout, "250 2.1.5 Ok\r\n");
	break;

    case IMAP_IOERROR:
	prot_printf(pout, "451 4.3.0 System I/O error\r\n");
	break;

    case IMAP_SERVER_UNAVAILABLE:
	prot_printf(pout, "451 4.4.0 Remote server unavailable\r\n");
	break;

    case IMAP_NOSPACE:
	prot_printf(pout, "451 4.3.1 cannot create file: out of space\r\n");
	break;

    case IMAP_AGAIN:
	prot_printf(pout, "451 4.3.0 transient system error\r\n");
	break;

    case IMAP_PERMISSION_DENIED:
	if (LMTP_LONG_ERROR_MSGS) {
	    prot_printf(pout, 
"550-You do not have permission to post a message to this mailbox.\r\n"
"550-Please contact the owner of this mailbox in order to submit\r\n"
"550-your message, or postmaster@andrew.cmu.edu if you believe you\r\n"
"550-received this message in error.\r\n"
"550 5.7.1 Permission denied");
	} else {
	    prot_printf(pout, "550 5.7.1 Permission denied\r\n");
	}
	break;

    case IMAP_QUOTA_EXCEEDED:
	prot_printf(pout, "452 4.2.2 Over quota\r\n");
	break;

    case IMAP_MAILBOX_BADFORMAT:
    case IMAP_MAILBOX_NOTSUPPORTED:
	prot_printf(pout, "451 4.2.0 Mailbox has an invalid format\r\n");
	break;

    case IMAP_MESSAGE_CONTAINSNULL:
	prot_printf(pout, "554 5.6.0 Message contains NUL characters\r\n");
	break;

    case IMAP_MESSAGE_CONTAINSNL:
	prot_printf(pout, "554 5.6.0 Message contains bare newlines\r\n");
	break;

    case IMAP_MESSAGE_CONTAINS8BIT:
	prot_printf(pout, "554 5.6.0 Message contains non-ASCII characters in headers\r\n");
	break;

    case IMAP_MESSAGE_BADHEADER:
	prot_printf(pout, "554 5.6.0 Message contains invalid header\r\n");
	break;

    case IMAP_MESSAGE_NOBLANKLINE:
	prot_printf(pout, 
		    "554 5.6.0 Message has no header/body separator\r\n");
	break;

    case IMAP_MAILBOX_NONEXISTENT:
	/* XXX Might have been moved to other server */
	prot_printf(pout, "550 5.1.1 User unknown\r\n");
	break;

    case IMAP_PROTOCOL_BAD_PARAMETERS:
	prot_printf(pout, "501 5.5.4 Syntax error in parameters\r\n");
	break;

    default:
	/* Some error we're not expecting. */
	prot_printf(pout, "554 5.0.0 Unexpected internal error\r\n");
	break;
    }
}

/* ----- this section defines functions on message_data_t.
   ----- access functions and the like, etc. */

/* returns non-zero on failure */
int msg_new(message_data_t **m)
{
    message_data_t *ret = (message_data_t *) xmalloc(sizeof(message_data_t));
    int i;

    ret->data = NULL;
    ret->f = NULL;
    ret->id = NULL;
    ret->size = 0;
    ret->return_path = NULL;
    ret->rcpt = NULL;
    ret->rcpt_num = 0;

    ret->authuser = NULL;
    ret->authstate = NULL;

    for (i = 0; i < HEADERCACHESIZE; i++)
	ret->cache[i] = NULL;

    *m = ret;
    return 0;
}

void msg_free(message_data_t *m)
{
    int i;

    if (m->data) {
	prot_free(m->data);
    }
    if (m->f) {
	fclose(m->f);
    }
    if (m->id) {
	free(m->id);
    }

    if (m->return_path) {
	free(m->return_path);
    }
    if (m->rcpt) {
	for (i = 0; i < m->rcpt_num; i++) {
	    if (m->rcpt[i]->all) free(m->rcpt[i]->all);
	    if (m->rcpt[i]->user) free(m->rcpt[i]->user);
	    free(m->rcpt[i]);
	}
	free(m->rcpt);
    }

    if (m->authuser) {
	free(m->authuser);
	if (m->authstate) auth_freestate(m->authstate);
    }

    for (i = 0; i < HEADERCACHESIZE; i++) {
	if (m->cache[i]) {
	    int j;

	    free(m->cache[i]->name);
	    for (j = 0; j < m->cache[i]->ncontents; j++) {
		free(m->cache[i]->contents[j]);
	    }

	    free(m->cache[i]);
	}
    }

    free(m);
}

/* hash function used for header cache in struct msg */
static int hashheader(char *header)
{
    int x = 0;
    /* any CHAR except ' ', :, or a ctrl char */
    for (; !iscntrl((int) *header) && (*header != ' ') && (*header != ':'); 
	 header++) {
	x *= 256;
	x += *header;
	x %= HEADERCACHESIZE;
    }
    return x;
}

const char **msg_getheader(message_data_t *m, const char *phead)
{
    char *head;
    const char **ret = NULL;
    int clinit, cl;

    assert(m && phead);

    head = xstrdup(phead);
    lcase(head);

    /* check the cache */
    clinit = cl = hashheader(head);
    while (m->cache[cl] != NULL) {
	if (!strcmp(head, m->cache[cl]->name)) {
	    ret = (const char **) m->cache[cl]->contents;
	    break;
	}
	cl++; /* try next hash bin */
	cl %= HEADERCACHESIZE;
	if (cl == clinit) break; /* gone all the way around */
    }

    free(head);

    return ret;
}

int msg_getsize(message_data_t *m)
{
    return m->size;
}

int msg_getnumrcpt(message_data_t *m)
{
    return m->rcpt_num;
}

const char *msg_getrcpt(message_data_t *m, int rcpt_num)
{
    assert(0 <= rcpt_num && rcpt_num < m->rcpt_num);
    return m->rcpt[rcpt_num]->user;
}

const char *msg_getrcptall(message_data_t *m, int rcpt_num)
{
    assert(0 <= rcpt_num && rcpt_num < m->rcpt_num);
    return m->rcpt[rcpt_num]->all;
}

int msg_getrcpt_ignorequota(message_data_t *m, int rcpt_num)
{
    assert(0 <= rcpt_num && rcpt_num < m->rcpt_num);
    return m->rcpt[rcpt_num]->ignorequota;
}

/* set a recipient status; 'r' should be an IMAP error code that will be
   translated into an LMTP status code */
void msg_setrcpt_status(message_data_t *m, int rcpt_num, int r)
{
    assert(0 <= rcpt_num && rcpt_num < m->rcpt_num);
    m->rcpt[rcpt_num]->status = r;
}

/* return a malloc'd string representing the authorized user.
 advance 'strp' over the parameter */
static char *parseautheq(char **strp)
{
    char *ret;
    char *str;
    char *s = *strp;

    if (!strcmp(s, "<>")) {
	*strp = s + 2;
	return NULL;
    }

    ret = (char *) xmalloc(strlen(s)+1);
    ret[0]='\0';
    str = ret;

    if (*s == '<') s++; 	/* we'll be liberal and accept "<foo>" */
    while (1)
    {
	/* hexchar */
	if (*s == '+')
	{
	    int lup;
	    *str = '\0';
	    s++;
	    
	    for (lup=0;lup<2;lup++)
	    {
		if ((*s>='0') && (*s<='9'))
		    (*str) = (*str) & (*s - '0');
		else if ((*s>='A') && (*s<='F'))
		    (*str) = (*str) & (*s - 'A' + 10);
		else {
		    free(ret);
		    *strp = s;
		    return NULL;
		}
		if (lup==0)
		{
		    (*str) = (*str) << 4;
		    s++;
		}		
	    }
	    str++;

	} else if ((*s >= '!') && (*s <='~') && (*s!='+') && (*s!='=')) {
	    /* ascii char */
	    *str = *s;
	    str++;
	} else {
	    /* bad char or end-of-line */
	    break;
	}
	s++;
    }

    *strp = s;
    if (*s && (*s!=' ')) { free(ret); return NULL; }

    *str = '\0';

    /* take off trailing '>' */
    if ((str!=ret) && ( *(str-1)=='>'))
    {
	*(str-1) = '\0';
    }

    return ret;
}

/* return malloc'd string containing the address */
static char *parseaddr(char *s)
{
    char *p;
    int len;

    p = s;

    if (*p++ != '<') return 0;

    /* at-domain-list */
    while (*p == '@') {
	p++;
	if (*p == '[') {
	    p++;
	    while (isdigit((int) *p) || *p == '.') p++;
	    if (*p++ != ']') return 0;
	}
	else {
	    while (isalnum((int) *p) || *p == '.' || *p == '-') p++;
	}
	if (*p == ',' && p[1] == '@') p++;
	else if (*p == ':' && p[1] != '@') p++;
	else return 0;
    }
    
    /* local-part */
    if (*p == '\"') {
	p++;
	while (*p && *p != '\"') {
	    if (*p == '\\') {
		if (!*++p) return 0;
	    }
	    p++;
	}
	if (!*p++) return 0;
    }
    else {
	while (*p && *p != '@' && *p != '>') {
	    if (*p == '\\') {
		if (!*++p) return 0;
	    }
	    else {
		if (*p <= ' ' || (*p & 128) ||
		    strchr("<>()[]\\,;:\"", *p)) return 0;
	    }
	    p++;
	}
    }

    /* @domain */
    if (*p == '@') {
	p++;
	if (*p == '[') {
	    p++;
	    while (isdigit((int) *p) || *p == '.') p++;
	    if (*p++ != ']') return 0;
	}
	else {
	    while (isalnum((int) *p) || *p == '.' || *p == '-') p++;
	}
    }
    
    if (*p++ != '>') return 0;
    if (*p && *p != ' ') return 0;
    len = p - s;

    s = xstrdup(s);
    s[len] = '\0';
    return s;
}

/* clean off the <> from the return path */
void clean_retpath(char *rpath)
{
    int i, sl;

    /* Remove any angle brackets around return path */
    if (*rpath == '<') {
	sl = strlen(rpath);
	for (i = 0; i < sl; i++) {
	    rpath[i] = rpath[i+1];
	}
	sl--; /* string is one shorter now */
	if (rpath[sl-1] == '>') {
	    rpath[sl-1] = '\0';
	}
    }
}

/*
 * Destructively remove any whitespace and 822 comments
 * from string pointed to by 'buf'.  Does not handle continuation header
 * lines.
 */
void
clean822space(buf)
char *buf;
{
    char *from=buf, *to=buf;
    int c;
    int commentlevel = 0;

    while ((c = *from++)!=0) {
	switch (c) {
	case '\r':
	case '\n':
	case '\0':
	    *to = '\0';
	    return;

	case ' ':
	case '\t':
	    continue;

	case '(':
	    commentlevel++;
	    break;

	case ')':
	    if (commentlevel) commentlevel--;
	    break;

	case '\\':
	    if (commentlevel && *from) from++;
	    /* FALL THROUGH */

	default:
	    if (!commentlevel) *to++ = c;
	    break;
	}
    }
}

/* copies the message from fin to fout, massaging accordingly: mostly
 * newlines are fiddled. "." terminates */
static int copy_msg(struct protstream *fin, FILE *fout)
{
    char buf[8192], *p;

    while (prot_fgets(buf, sizeof(buf)-1, fin)) {
	p = buf + strlen(buf) - 1;
	if (p <= buf || (p[0] == '\n' && p[-1] != '\r')) {
	    /* either a \0 by itself or a \n without a \r */
	    p[0] = '\r';
	    p[1] = '\n';
	    p[2] = '\0';
	} else if (*p == '\r') {
	    if (buf[0] == '\r' && buf[1] == '\0') {
		/* The message contained \r\0, and fgets is confusing us.
		   XXX ignored
		   */
	    } else {
		/*
		 * We were unlucky enough to get a CR just before we ran
		 * out of buffer--put it back.
		 */
		prot_ungetc('\r', fin);
		*p = '\0';
	    }
	}
	/* Remove any lone CR characters */
	while ((p = strchr(buf, '\r')) && p[1] != '\n') {
	    strcpy(p, p+1);
	}
	
	if (buf[0] == '.') {
	    if (buf[1] == '\r' && buf[2] == '\n') {
		/* End of message */
		goto lmtpdot;
	    }
	    /* Remove the dot-stuffing */
	    fputs(buf+1, fout);
	} else {
	    fputs(buf, fout);
	}
    }

    /* wow, serious error---got a premature EOF. */
    return IMAP_IOERROR;

 lmtpdot:
    return 0;
}

/* take a list of headers, pull the first one out and return it in
   name and contents.

   copies fin to fout, massaging 

   returns 0 on success, negative on failure */
typedef enum {
    NAME_START,
    NAME,
    COLON,
    BODY_START,
    BODY
} state;

enum {
    NAMEINC = 128,
    BODYINC = 1024
};

/* we don't have to worry about dotstuffing here, since it's illegal
   for a header to begin with a dot! */
static int parseheader(struct protstream *fin, FILE *fout, 
		       char **headname, char **contents) {
    int c;
    static char *name = NULL, *body = NULL;
    static int namelen = 0, bodylen = 0;
    int off = 0;
    state s = NAME_START;

    if (namelen == 0) {
	namelen += NAMEINC;
	name = (char *) xrealloc(name, namelen * sizeof(char));
    }
    if (bodylen == 0) {
	bodylen += BODYINC;
	body = (char *) xrealloc(body, bodylen * sizeof(char));
    }

    /* there are two ways out of this loop, both via gotos:
       either we successfully read a character (got_header)
       or we hit an error (ph_error) */
    while ((c = prot_getc(fin)) != EOF) { /* examine each character */
	switch (s) {
	case NAME_START:
	    if (c == '\r' || c == '\n') {
		/* no header here! */
		goto ph_error;
	    }
	    if (!isalpha(c)) {
		/* invalid header name */
		goto ph_error;
	    }
	    name[0] = tolower(c);
	    off = 1;
	    s = NAME;
	    break;

	case NAME:
	    if (c == ' ' || c == '\t' || c == ':') {
		name[off] = '\0';
		s = (c == ':' ? BODY_START : COLON);
		break;
	    }
	    if (iscntrl(c)) {
		goto ph_error;
	    }
	    name[off++] = tolower(c);
	    if (off >= namelen - 3) {
		namelen += NAMEINC;
		name = (char *) xrealloc(name, namelen);
	    }
	    break;
	
	case COLON:
	    if (c == ':') {
		s = BODY_START;
	    } else if (c != ' ' && c != '\t') {
		/* i want to avoid confusing dot-stuffing later */
		while (c == '.') {
		    fputc(c, fout);
		    c = prot_getc(fin);
		}
		goto ph_error;
	    }
	    break;

	case BODY_START:
	    if (c == ' ' || c == '\t') /* eat the whitespace */
		break;
	    off = 0;
	    s = BODY;
	    /* falls through! */
	case BODY:
	    /* now we want to convert all newlines into \r\n */
	    if (c == '\r' || c == '\n') {
		int peek;

		peek = prot_getc(fin);
		
		fputc('\r', fout);
		fputc('\n', fout);
		/* we should peek ahead to see if it's folded whitespace */
		if (c == '\r' && peek == '\n') {
		    c = prot_getc(fin);
		} else {
		    c = peek; /* single newline seperator */
		}
		if (c != ' ' && c != '\t') {
		    /* this is the end of the header */
		    body[off] = '\0';
		    prot_ungetc(c, fin);
		    goto got_header;
		}
		/* ignore this whitespace, but we'll copy all the rest in */
		break;
	    } else {
		/* just an ordinary character */
		body[off++] = c;
		if (off >= bodylen - 3) {
		    bodylen += BODYINC;
		    body = (char *) xrealloc(body, bodylen);
		}
	    }
	}

	/* copy this to the output */
	fputc(c, fout);
    }

    /* if we fall off the end of the loop, we hit some sort of error
       condition */

 ph_error:
    /* put the last character back; we'll copy it later */
    prot_ungetc(c, fin);

    /* and we didn't get a header */
    if (headname != NULL) *headname = NULL;
    if (contents != NULL) *contents = NULL;
    return -1;

 got_header:
    if (headname != NULL) *headname = xstrdup(name);
    if (contents != NULL) *contents = xstrdup(body);

    return 0;
}

static int fill_cache(struct protstream *fin, FILE *fout, message_data_t *m)
{
    /* let's fill that header cache */
    for (;;) {
	char *name, *body;
	int cl, clinit;

	if (parseheader(fin, fout, &name, &body) < 0) {
	    break;
	}

	/* put it in the hash table */
	clinit = cl = hashheader(name);
	while (m->cache[cl] != NULL && strcmp(name, m->cache[cl]->name)) {
	    cl++;		/* resolve collisions linearly */
	    cl %= HEADERCACHESIZE;
	    if (cl == clinit) break; /* gone all the way around, so bail */
	}

	/* found where to put it, so insert it into a list */
	if (m->cache[cl]) {
	    /* add this body on */
	    m->cache[cl]->contents[m->cache[cl]->ncontents++] = body;

	    /* whoops, won't have room for the null at the end! */
	    if (!(m->cache[cl]->ncontents % 8)) {
		/* increase the size */
		m->cache[cl] = (header_t *)
		    xrealloc(m->cache[cl],sizeof(header_t) +
			     ((8 + m->cache[cl]->ncontents) * sizeof(char *)));
	    }

	    /* have no need of this */
	    free(name);
	} else {
	    /* create a new entry in the hash table */
	    m->cache[cl] = (header_t *) xmalloc(sizeof(header_t) + 
						8 * sizeof(char*));
	    m->cache[cl]->name = name;
	    m->cache[cl]->contents[0] = body;
	    m->cache[cl]->ncontents = 1;
	}

	/* we always want a NULL at the end */
	m->cache[cl]->contents[m->cache[cl]->ncontents] = NULL;
    }

    return copy_msg(fin, fout);
}

/*
 * file in the message structure 'm' from 'pin', assuming a dot-stuffed
 * stream a la lmtp.
 *
 * returns 0 on success, imap error code on failure
 */
static int savemsg(struct clientdata *cd,
		   const char *addheaders,
		   message_data_t *m)
{
    FILE *f;
    struct stat sbuf;
    const char **body;
    int r;
    int nrcpts = m->rcpt_num;
    time_t t;
    char datestr[80];

    /* Copy to temp file */
    f = tmpfile();
    if (!f) {
	prot_printf(cd->pout, 
		    "451 4.3.%c cannot create temporary file: %s\r\n",
		    (
#ifdef EDQUOT
			errno == EDQUOT ||
#endif
			errno == ENOSPC) ? '1' : '2',
		    error_message(errno));
	return IMAP_IOERROR;
    }

    prot_printf(cd->pout, "354 go ahead\r\n");

    if (m->return_path) { /* add the return path */
	char *rpath = m->return_path;
	const char *hostname = 0;

	clean_retpath(rpath);
	/* Append our hostname if there's no domain in address */
	hostname = NULL;
	if (!strchr(rpath, '@')) {
	    hostname = config_servername;
	}

	fprintf(f, "Return-Path: <%s%s%s>\r\n",
		rpath, hostname ? "@" : "", hostname ? hostname : "");
    }

    /* add a received header */
    t = time(NULL);
    rfc822date_gen(datestr, sizeof(datestr), t);
    fprintf(f, "Received: from %s (%s)",
	    cd->lhlo_param, cd->clienthost);
    if (m->authuser) {
	const int *ssfp;
	sasl_getprop(cd->conn, SASL_SSF, (const void **) &ssfp);
	fprintf(f, " (authenticated user=%s bits=%d)", m->authuser, *ssfp);
    }
    fprintf(f, "\r\n\tby %s (Cyrus %s) with LMTP",
		config_servername, CYRUS_VERSION);

#ifdef HAVE_SSL
    if (cd->tls_conn) {
	char tls_info[250];

	tls_info[0] = '\0';
	/* grab TLS info for Received: header */
	tls_get_info(cd->tls_conn, tls_info, sizeof(tls_info));
	if (*tls_info) fprintf(f, " (%s)", tls_info);
    }
#endif /* HAVE_SSL */

    fprintf(f, "; %s\r\n", datestr);

    /* add any requested headers */
    if (addheaders) {
	fputs(addheaders, f);
    }

    /* fill the cache */
    r = fill_cache(cd->pin, f, m);
    if (r) {
	fclose(f);
	while (nrcpts--) {
	    send_lmtp_error(cd->pout, r);
	}
	return r;
    }

    /* now, using our header cache, fill in the data that we want */

    /* first check resent-message-id */
    if ((body = msg_getheader(m, "resent-message-id")) != NULL) {
	m->id = xstrdup(body[0]);
    } else if ((body = msg_getheader(m, "message-id")) != NULL) {
	m->id = xstrdup(body[0]);
    } else {
	m->id = NULL;		/* no message-id */
    }

    if (!m->return_path &&
	(body = msg_getheader(m, "return-path"))) {
	/* let's grab return_path */
	m->return_path = xstrdup(body[0]);
	clean822space(m->return_path);
	clean_retpath(m->return_path);
    }

    fflush(f);
    if (ferror(f)) {
	while (nrcpts--) {
	    prot_printf(cd->pout,
	       "451 4.3.%c cannot copy message to temporary file: %s\r\n",
		   (
#ifdef EDQUOT
		    errno == EDQUOT ||
#endif
		    errno == ENOSPC) ? '1' : '2',
		   error_message(errno));
	}
	fclose(f);
	return IMAP_IOERROR;
    }

    if (fstat(fileno(f), &sbuf) == -1) {
	while (nrcpts--) {
	    prot_printf(cd->pout,
			"451 4.3.2 cannot stat message temporary file: %s\r\n",
			error_message(errno));
	}
	fclose(f);
	return IMAP_IOERROR;
    }
    m->size = sbuf.st_size;
    m->f = f;
    m->data = prot_new(fileno(f), 0);

    return 0;
}

/* see if 'addr' exists. if so, fill in 'ad' appropriately.
   on success, return NULL.
   on failure, return the error. */
static int process_recipient(char *addr,
			     int ignorequota,
			     int (*verify_user)(const char *, long,
						struct auth_state *),
			     message_data_t *msg)
{
    char *dest;
    char *user;
    int r, sl;
    address_data_t *ret = (address_data_t *) xmalloc(sizeof(address_data_t));

    assert(addr != NULL && msg != NULL);

    if (*addr == '<') addr++;
    dest = user = addr;
    
    /* preserve the entire address */
    ret->all = xstrdup(addr);
    sl = strlen(ret->all);
    if (ret->all[sl-1] == '>')
	ret->all[sl-1] = '\0';

    /* now find just the user */
    
    /* Skip at-domain-list */
    if (*addr == '@') {
	addr = strchr(addr, ':');
	if (!addr) {
	    free(ret->all);
	    free(ret);
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	}
	addr++;
    }
    
    if (*addr == '\"') {
	addr++;
	while (*addr && *addr != '\"') {
	    if (*addr == '\\') addr++;
	    *dest++ = *addr++;
	}
    }
    else {
	while (*addr != '@' && *addr != '>') {
	    if (*addr == '\\') addr++;
	    *dest++ = *addr++;
	}
    }
    *dest = '\0';
	
    r = verify_user(user, ignorequota ? -1 : msg->size, msg->authstate);
    if (r) {
	/* we lost */
	free(ret->all);
	free(ret);
	return r;
    }
    ret->user = xstrdup(user);

    ret->ignorequota = ignorequota;

    msg->rcpt[msg->rcpt_num] = ret;

    return 0;
}

static int localauth_mechlist_override(
    void *context __attribute__((unused)), 
    const char *plugin_name __attribute__((unused)),
    const char *option,
    const char **result,
    unsigned *len)
{
    /* If we are doing local auth, we only support EXTERNAL */
    if (strcmp(option,"mech_list")==0)
    {
	*result = "EXTERNAL";
	if (len)
	    *len = strlen(*result);
	return SASL_OK;
    }

    /* if we don't find the option,
       this should percolate to the global getopt */
    return SASL_FAIL;
}

static struct sasl_callback localauth_override_cb[] = {
    { SASL_CB_GETOPT, &localauth_mechlist_override, NULL },
    { SASL_CB_LIST_END, NULL, NULL },
};

void lmtpmode(struct lmtp_func *func,
	      struct protstream *pin, 
	      struct protstream *pout,
	      int fd)
{
    message_data_t *msg = NULL;
    int max_msgsize;
    char buf[4096];
    char *p;
    int r;
    struct clientdata cd;

    struct sockaddr_in localaddr, remoteaddr;
    int havelocal = 0, haveremote = 0;
    char localip[60], remoteip[60];
    socklen_t salen;
    char clienthost[250];

    sasl_ssf_t ssf;
    char *auth_id;
    int plaintext_result;

    int secflags = 0;
    sasl_security_properties_t *secprops = NULL;
    enum {
	EXTERNAL_AUTHED = -1, /* -1: external auth'd, but no AUTH issued */
	NOAUTH = 0,
	DIDAUTH = 1
    } authenticated = NOAUTH;	

    /* setup the clientdata structure */
    cd.pin = pin;
    cd.pout = pout;
    cd.fd = fd;
    cd.clienthost[0] = '\0';
    cd.lhlo_param[0] = '\0';
#ifdef HAVE_SSL
    cd.tls_conn = NULL;
#endif
    cd.starttls_done = 0;

    max_msgsize = config_getint("maxmessagesize", INT_MAX);

    msg_new(&msg);

    /* determine who we're talking to */
    salen = sizeof(remoteaddr);
    r = getpeername(fd, (struct sockaddr *)&remoteaddr, &salen);
    if (!r && remoteaddr.sin_family == AF_INET) {
	/* connected to an internet socket */
	struct hostent *hp;
	hp = gethostbyaddr((char *)&remoteaddr.sin_addr,
			   sizeof(remoteaddr.sin_addr), AF_INET);
	if (hp != NULL) {
	    strlcpy(cd.clienthost, hp->h_name, sizeof(cd.clienthost) - 30);
	} else {
	    strlcpy(cd.clienthost, inet_ntoa(remoteaddr.sin_addr), 
		    sizeof(cd.clienthost) - 30);
	}
	strlcat(cd.clienthost, " [", sizeof(cd.clienthost));
	strlcat(cd.clienthost, inet_ntoa(remoteaddr.sin_addr), 
		sizeof(cd.clienthost));
	strlcat(cd.clienthost, "]", sizeof(cd.clienthost));

	salen = sizeof(localaddr);
	if (!getsockname(fd, (struct sockaddr *)&localaddr, &salen)) {
	    /* set the ip addresses here */
	    if(iptostring((struct sockaddr *)&localaddr,
                          sizeof(struct sockaddr_in), localip, 60) == 0) {
		havelocal = 1;
                saslprops.iplocalport = xstrdup(localip);
            }
            if(iptostring((struct sockaddr *)&remoteaddr,
                          sizeof(struct sockaddr_in), remoteip, 60) == 0) {
		haveremote = 1;
                saslprops.ipremoteport = xstrdup(remoteip);
            }
	} else {
	    fatal("can't get local addr", EC_SOFTWARE);
	}

	syslog(LOG_DEBUG, "connection from %s%s", 
	       cd.clienthost, 
	       func->preauth ? " preauth'd as postman" : "");
    } else {
	/* we're not connected to a internet socket! */
	func->preauth = 1;
	strcpy(cd.clienthost, "[unix socket]");
	syslog(LOG_DEBUG, "lmtp connection preauth'd as postman");
    }

    /* Setup SASL to go.  We need to do this *after* we decide if
     *  we are preauthed or not. */
    if (sasl_server_new("lmtp", NULL, NULL, NULL,
			NULL, (func->preauth ? localauth_override_cb : NULL),
			0, &cd.conn) != SASL_OK) {
	fatal("SASL failed initializing: sasl_server_new()", EC_TEMPFAIL);
    }

    /* set my allowable security properties */
    /* ANONYMOUS is silly because we allow that anyway */
    secflags = SASL_SEC_NOANONYMOUS;
    plaintext_result = config_getswitch("allowplaintext",1);
    if (!config_getswitch("lmtp_allowplaintext", plaintext_result)) {
	secflags |= SASL_SEC_NOPLAINTEXT;
    }
    secprops = mysasl_secprops(secflags);
    sasl_setprop(cd.conn, SASL_SEC_PROPS, secprops);

    if (func->preauth) {
	authenticated = EXTERNAL_AUTHED;	/* we'll allow commands, 
						   but we still accept
						   the AUTH command */
	ssf = 2;
	auth_id = "postman";
	sasl_setprop(cd.conn, SASL_SSF_EXTERNAL, &ssf);
	sasl_setprop(cd.conn, SASL_AUTH_EXTERNAL, auth_id);
    } else {
	if(havelocal) sasl_setprop(cd.conn, SASL_IPLOCALPORT,  &localip );
	if(haveremote) sasl_setprop(cd.conn, SASL_IPREMOTEPORT, &remoteip);  
    }

    prot_printf(pout, "220 %s LMTP Cyrus %s ready\r\n", 
		config_servername,
		CYRUS_VERSION);
    for (;;) {
    nextcmd:
      signals_poll();

      if (!prot_fgets(buf, sizeof(buf)-1, pin)) {
	  const char *err = prot_error(pin);
	  
	  if (err != NULL) {
	      prot_printf(pout, "421 4.4.1 bye %s\r\n", err);
	      prot_flush(pout);
	  }
	  goto cleanup;
      }
      p = buf + strlen(buf) - 1;
      if (p >= buf && *p == '\n') *p-- = '\0';
      if (p >= buf && *p == '\r') *p-- = '\0';

      switch (buf[0]) {
      case 'a':
      case 'A':
	  if (!strncasecmp(buf, "auth ", 5)) {
	      char mech[128];
	      char *in = NULL;
	      const char *out = NULL;
	      unsigned int inlen, outlen;
	      const char *user;
	      
	      if (authenticated > 0) {
		  prot_printf(pout,
			      "503 5.5.0 already authenticated\r\n");
		  continue;
	      }
	      if (msg->rcpt_num != 0) {
		  prot_printf(pout,
			      "503 5.5.0 AUTH not permitted now\r\n");
		  continue;
	      }
	      
	      /* ok, what mechanism ? */
	      p = buf + 5;
	      while ((*p != ' ') && (*p != '\0')) {
		  p++;
	      }
	      if (*p == ' ') {
		  *p = '\0';
		  p++;
	      } else {
		  p = NULL;
	      }
	      strlcpy(mech, buf + 5, sizeof(mech));
	      if (p == NULL) {
		  in = NULL;
		  inlen = 0;
	      } else if (!strcmp(p, "=")) {
		  /* zero-length initial response */
		  in = xstrdup("");
		  inlen = 0;
	      } else {
		  unsigned len = strlen(p);
		  in = xmalloc(len);
		  r = sasl_decode64(p, len, in, len, &inlen);
		  if (r != SASL_OK) {
		      prot_printf(pout,
				  "501 5.5.4 cannot base64 decode\r\n");
		      if (in) { free(in); in = NULL; }
		      continue;
		  }
	      }
	      
	      r = sasl_server_start(cd.conn, mech,
				    in, inlen,
				    &out, &outlen);
	      if (in) { free(in); in = NULL; }
	      if (r == SASL_NOMECH) {
		  prot_printf(pout, 
			      "504 Unrecognized authentication type.\r\n");
		  continue;
	      }
	      
	      while (r == SASL_CONTINUE) {
		  char inbase64[4096];
		  unsigned len;

		  if(out) {
		    r = sasl_encode64(out, outlen, 
				    inbase64, sizeof(inbase64), NULL);
		    if (r != SASL_OK) break;
	  
		    /* send out */
		    prot_printf(pout,"334 %s\r\n", inbase64);
		  }
		  
		  /* read a line */
		  if (!prot_fgets(buf, sizeof(buf)-1, pin)) {
		      goto cleanup;
		  }
		  p = buf + strlen(buf) - 1;
		  if (p >= buf && *p == '\n') *p-- = '\0';
		  if (p >= buf && *p == '\r') *p-- = '\0';

		  if(buf[0] == '*') {
		      prot_printf(pout,
				  "501 5.5.4 client canceled authentication\r\n");
		      reset_saslconn(&cd.conn);
		      goto nextcmd;
		  }
		  
		  len = strlen(buf);
		  in = xmalloc(len);
		  r = sasl_decode64(buf, len, in, len, &inlen);
		  if (r != SASL_OK) {
		      prot_printf(pout,
				  "501 5.5.4 cannot base64 decode\r\n");
		      reset_saslconn(&cd.conn);
		      goto nextcmd;
		  }

		  r = sasl_server_step(cd.conn,
				       in, inlen,
				       &out, &outlen);
		  if (in) { free(in); in = NULL; }
	      }
	      
	      if (in) { free(in); in = NULL; }
	      if ((r != SASL_OK) && (r != SASL_CONTINUE)) {
		  sleep(3);
		  
		  syslog(LOG_ERR, "badlogin: %s %s %s",
			 remoteaddr.sin_family == AF_INET ?
			 inet_ntoa(remoteaddr.sin_addr) :
			 "[unix socket]",
			 mech,
			 sasl_errdetail(cd.conn));
		  
		  snmp_increment_args(AUTHENTICATION_NO, 1,
				      VARIABLE_AUTH, hash_simple(mech), 
				      VARIABLE_LISTEND);

		  prot_printf(pout, "501 5.5.4 %s\r\n",
		       sasl_errstring((r == SASL_NOUSER ? SASL_BADAUTH : r),
				      NULL, NULL));
		  
		  reset_saslconn(&cd.conn);
		  continue;
	      }
	      r = sasl_getprop(cd.conn, SASL_USERNAME, (const void **) &user);
	      if (r != SASL_OK) {
		  prot_printf(pout, "501 5.5.4 SASL Error\r\n");
		  reset_saslconn(&cd.conn);
		  goto nextcmd;
	      }

	      /* authenticated successfully! */
	      snmp_increment_args(AUTHENTICATION_YES,1,
				  VARIABLE_AUTH, hash_simple(mech), 
				  VARIABLE_LISTEND);
	      syslog(LOG_NOTICE, "login: %s %s %s%s %s",
		     cd.clienthost, user, mech,
		     cd.starttls_done ? "+TLS" : "", "User logged in");

	      authenticated += 2;
	      prot_printf(pout, "235 Authenticated!\r\n");

	      /* set protection layers */
	      prot_setsasl(pin,  cd.conn);
	      prot_setsasl(pout, cd.conn);
	      continue;
	  }
	  goto syntaxerr;

      case 'd':
      case 'D':
	    if (!strcasecmp(buf, "data")) {
		int delivered = 0;
		int j;

		if (!msg->rcpt_num) {
		    prot_printf(pout, "503 5.5.1 No recipients\r\n");
		    continue;
		}
		/* copy message from input to msg structure */
		r = savemsg(&cd, func->addheaders, msg);
		if (r) continue;

		if (msg->size > max_msgsize) {
		    prot_printf(pout, 
				"552 5.2.3 Message size (%d) exceeds fixed "
				"maximum message size (%d)\r\n",
				msg->size, max_msgsize);
		    continue;
		}

		snmp_increment(mtaReceivedMessages, 1);
		snmp_increment(mtaReceivedVolume, roundToK(msg->size));
		snmp_increment(mtaReceivedRecipients, msg->rcpt_num);

		/* do delivery, report status */
		r = func->deliver(msg, msg->authuser, msg->authstate);
		for (j = 0; j < msg->rcpt_num; j++) {
		    if (!msg->rcpt[j]->status) delivered++;
		    send_lmtp_error(pout, msg->rcpt[j]->status);
		}

		snmp_increment(mtaTransmittedMessages, delivered);
		snmp_increment(mtaTransmittedVolume, 
			       roundToK(delivered * msg->size));
		goto rset;
	    }
	    goto syntaxerr;

      case 'l':
      case 'L':
	  if (!strncasecmp(buf, "lhlo ", 5)) {
	      unsigned int mechcount;
	      const char *mechs;
	      
	      prot_printf(pout, "250-%s\r\n"
			  "250-8BITMIME\r\n"
			  "250-ENHANCEDSTATUSCODES\r\n"
			  "250-PIPELINING\r\n",
			  config_servername);
	      if (max_msgsize < INT_MAX)
		  prot_printf(pout, "250-SIZE %d\r\n", max_msgsize);
	      else
		  prot_printf(pout, "250-SIZE\r\n");
	      if (tls_enabled("lmtp") && !func->preauth) {
		  prot_printf(pout, "250-STARTTLS\r\n");
	      }
	      if (sasl_listmech(cd.conn, NULL, "AUTH ", " ", "", &mechs, 
				NULL, &mechcount) == SASL_OK && 
		  mechcount > 0) {
		  prot_printf(pout,"250-%s\r\n", mechs);
	      }
	      prot_printf(pout, "250 IGNOREQUOTA\r\n");

	      strlcpy(cd.lhlo_param, buf + 5, sizeof(cd.lhlo_param));
	      
	      continue;
	  }
	  goto syntaxerr;
    
      case 'm':
      case 'M':
	    if (!authenticated) {
		if (config_getswitch("soft_noauth", 1)) {
		    prot_printf(pout, "430 Authentication required\r\n");
		} else {
		    prot_printf(pout, "530 Authentication required\r\n");
		}
		continue;
	    }

	    if (!strncasecmp(buf, "mail ", 5)) {
		char *tmp;
		if (msg->return_path) {
		    prot_printf(pout, 
				"503 5.5.1 Nested MAIL command\r\n");
		    continue;
		}
		if (strncasecmp(buf+5, "from:", 5) != 0 ||
		    !(msg->return_path = parseaddr(buf+10))) {
		    prot_printf(pout, 
				"501 5.5.4 Syntax error in parameters\r\n");
		    continue;
		}
		tmp = buf+10+strlen(msg->return_path);

		/* is any other whitespace allow seperating? */
		while (*tmp == ' ') {
		    tmp++;
		    switch (*tmp) {
		    case 'a': case 'A':
			if (strncasecmp(tmp, "auth=", 5) != 0) {
			    goto badparam;
			}
			tmp += 5;
			msg->authuser = parseautheq(&tmp);
			if (msg->authuser) {
			    msg->authstate = auth_newstate(msg->authuser, NULL);
			} else {
			    /* do we want to bounce mail because of this? */
			    /* i guess not. accept with no auth user */
			    msg->authstate = NULL;
			}
			break;

		    case 'b': case 'B':
			if (strncasecmp(tmp, "body=", 5) != 0) {
			    goto badparam;
			}
			tmp += 5;
			/* just verify it's one of 
			   body-value ::= "7BIT" / "8BITMIME" */
			if (!strncasecmp(tmp, "7bit", 4)) {
			    tmp += 4;
			} else if (!strncasecmp(tmp, "8bitmime", 8)) {
			    tmp += 8;
			} else {
			    prot_printf(pout, 
			      "501 5.5.4 Unrecognized BODY type\r\n");
			    goto nextcmd;
			}
			break;

		    case 's': case 'S':
			if (strncasecmp(tmp, "size=", 5) != 0) {
			    goto badparam;
			}
			tmp += 5;
			/* make sure we have a value */
			if (!isdigit((int) *tmp)) {
				prot_printf(pout, 
					    "501 5.5.2 SIZE requires a value\r\n");
				goto nextcmd;
			}
			msg->size = strtoul(tmp, &p, 10);
			tmp = p;
			/* make sure the value is in range */
			if (errno == ERANGE || msg->size < 0 ||
			    msg->size > max_msgsize) {
			    prot_printf(pout, 
					"552 5.2.3 Message SIZE exceeds fixed "
					"maximum message size (%d)\r\n",
					max_msgsize);
			    goto nextcmd;
			}
			break;

		    default: 
		    badparam:
			prot_printf(pout, 
				    "501 5.5.4 Unrecognized parameters\r\n");
			goto nextcmd;
		    }
		} 
		if (*tmp != '\0') {
		    prot_printf(pout, 
				"501 5.5.4 Syntax error in parameters\r\n");  
		    continue;
		}

		prot_printf(pout, "250 2.1.0 ok\r\n");
		continue;
	    }
	    goto syntaxerr;

      case 'n':
      case 'N':
	    if (!strcasecmp(buf, "noop")) {
		prot_printf(pout,"250 2.0.0 ok\r\n");
		continue;
	    }
	    goto syntaxerr;

      case 'q':
      case 'Q':
	    if (!strcasecmp(buf, "quit")) {
		prot_printf(pout,"221 2.0.0 bye\r\n");
		prot_flush(pout);
		goto cleanup;
	    }
	    goto syntaxerr;
	    
      case 'r':
      case 'R':
	    if (!strncasecmp(buf, "rcpt ", 5)) {
		char *rcpt = NULL;
		int ignorequota = 0;
		char *tmp;

		if (!msg->return_path) {
		    prot_printf(pout, "503 5.5.1 Need MAIL command\r\n");
		    continue;
		}
		if (!(msg->rcpt_num % RCPT_GROW)) { /* time to alloc more */
		    msg->rcpt = (address_data_t **)
			xrealloc(msg->rcpt, (msg->rcpt_num + RCPT_GROW + 1) * 
				 sizeof(address_data_t *));
		}
		if (strncasecmp(buf+5, "to:", 3) != 0 ||
		    !(rcpt = parseaddr(buf+8))) {
		    prot_printf(pout,
				"501 5.5.4 Syntax error in parameters\r\n");
		    continue;
		}

		tmp = buf+8+strlen(rcpt);
		while (*tmp == ' ') {
		    tmp++;
		    switch (*tmp) {
		    case 'i': case 'I':
			if (strncasecmp(tmp, "ignorequota", 12) != 0) {
			    goto badrparam;
			}
			tmp += 12;
			ignorequota = 1;
			break;

		    default: 
		    badrparam:
			prot_printf(pout, 
				    "501 5.5.4 Unrecognized parameters\r\n");
			goto nextcmd;
		    }
		} 
		if (*tmp != '\0') {
		    prot_printf(pout, 
				"501 5.5.4 Syntax error in parameters\r\n");  
		    continue;
		}

		r = process_recipient(rcpt,
				      ignorequota,
				      func->verify_user,
				      msg);
		if (rcpt) free(rcpt); /* malloc'd in parseaddr() */
		if (r) {
		    send_lmtp_error(pout, r);
		    continue;
		}
		msg->rcpt_num++;
		msg->rcpt[msg->rcpt_num] = NULL;
		prot_printf(pout, "250 2.1.5 ok\r\n");
		continue;
	    }
	    else if (!strcasecmp(buf, "rset")) {
		prot_printf(pout, "250 2.0.0 ok\r\n");

	      rset:
		if (msg) msg_free(msg);
		msg_new(&msg);
		
		continue;
	    }
	    goto syntaxerr;

      case 's':
      case 'S':
#ifdef HAVE_SSL
	    if (!strcasecmp(buf, "starttls") && tls_enabled("lmtp") &&
		!func->preauth) { /* don't need TLS for preauth'd connect */
		int *layerp;
		sasl_ssf_t ssf;
		char *auth_id;

		/* SASL and openssl have different ideas
		   about whether ssf is signed */
		layerp = &ssf;

		if (cd.starttls_done == 1) {
		    prot_printf(pout, "454 4.3.3 %s\r\n", 
				"Already successfully executed STARTTLS");
		    continue;
		}
		if (msg->rcpt_num != 0) {
		    prot_printf(pout,
				"503 5.5.0 STARTTLS not permitted now\r\n");
		    continue;
		}

		r=tls_init_serverengine("lmtp",
					5,   /* depth to verify */
					1,   /* can client auth? */
					0,   /* require client to auth? */
					1);   /* TLS only? */

		if (r == -1) {

		    syslog(LOG_ERR, "[lmtpd] error initializing TLS");

		    prot_printf(pout, "454 4.3.3 %s\r\n", "Error initializing TLS");
		    continue;
		}

		prot_printf(pout, "220 %s\r\n", "Begin TLS negotiation now");
		/* must flush our buffers before starting tls */
		prot_flush(pout);
  
		r=tls_start_servertls(0, /* read */
				      1, /* write */
				      layerp,
				      &auth_id,
				      &(cd.tls_conn));

		/* if error */
		if (r==-1) {
		    prot_printf(pout, "454 4.3.3 STARTTLS failed\r\n");
		    syslog(LOG_NOTICE, "[lmtpd] STARTTLS failed: %s", clienthost);
		    continue;
		}

		/* tell SASL about the negotiated layer */
		r=sasl_setprop(cd.conn, SASL_SSF_EXTERNAL, &ssf);
		if (r != SASL_OK)
		    fatal("sasl_setprop(SASL_SSF_EXTERNAL) failed: STARTTLS",
			  EC_TEMPFAIL);
		saslprops.ssf = ssf;

		r=sasl_setprop(cd.conn, SASL_AUTH_EXTERNAL, auth_id);
		if (r != SASL_OK)
		    fatal("sasl_setprop(SASL_AUTH_EXTERNAL) failed: STARTTLS",
			  EC_TEMPFAIL);
		if(saslprops.authid) {
		    free(saslprops.authid);
		    saslprops.authid = NULL;
		}
		if(auth_id)
		    saslprops.authid = xstrdup(auth_id);		

		/* tell the prot layer about our new layers */
		prot_settls(pin, cd.tls_conn);
		prot_settls(pout, cd.tls_conn);

		cd.starttls_done = 1;

		continue;
	    }
#endif /* HAVE_SSL*/
	    goto syntaxerr;

      case 'v':
      case 'V':
	    if (!strncasecmp(buf, "vrfy ", 5)) {
		prot_printf(pout,
			    "252 2.3.3 try RCPT to attempt delivery\r\n");
		continue;
	    }
	    goto syntaxerr;

      default:
      syntaxerr:
	    prot_printf(pout, "500 5.5.2 Syntax error\r\n");
	    continue;
      }
    }

 cleanup:
    /* free resources and return; this connection has been closed */

    if (msg) msg_free(msg);

    /* security */
    if (cd.conn) sasl_dispose(&cd.conn);

    cd.starttls_done = 0;
#ifdef HAVE_SSL
    if (cd.tls_conn) {
	tls_reset_servertls(&cd.tls_conn);
	cd.tls_conn = NULL;
    }
#endif
}

/************** client-side LMTP ****************/

enum {
    CAPA_PIPELINING  = 1 << 0,
    CAPA_AUTH        = 1 << 1,
    CAPA_IGNOREQUOTA = 1 << 2
};

struct lmtp_conn {
    char *host;
    int sock;
    struct protstream *pin, *pout;
    sasl_conn_t *saslconn;

    /* lmtp specific properties */
    int capability;
    char *mechs;
};

#define ISGOOD(r) (((r) / 100) == 2)
#define TEMPFAIL(r) (((r) / 100) == 4)
#define PERMFAIL(r) (((r) / 100) == 5)
#define ISCONT(s) (s && (s[3] == '-'))

static int revconvert_lmtp(const char *code)
{
    int c = atoi(code);
    switch (c) {
    case 250:
    case 251:
	return 0;
    case 451:
	if (code[4] == '4' && code[6] == '3') {
	    if (code[8] == '0') {
		return IMAP_IOERROR;
	    } else if (code[8] == '1') {
		return IMAP_NOSPACE;
	    } else {
		return IMAP_IOERROR;
	    }
	}
	else if (code[4] == '4' && code [6] == '4') {
	    return IMAP_SERVER_UNAVAILABLE;
	}
	else {
	    return IMAP_IOERROR;
	}
    case 452:
	return IMAP_QUOTA_EXCEEDED;
    case 550:
	if (code[4] == '5' && code[6] == '7') {
	    return IMAP_PERMISSION_DENIED;
	} else if (code[4] == '5' && code[6] == '1') {
	    return IMAP_MAILBOX_NONEXISTENT;
	}
	return IMAP_PERMISSION_DENIED;
    case 554:
	return IMAP_MESSAGE_BADHEADER; /* sigh, pick one */

    default:
	if (ISGOOD(c)) return 0;
	else if (TEMPFAIL(c)) return IMAP_AGAIN;
	else if (PERMFAIL(c)) return IMAP_PROTOCOL_ERROR;
	else return IMAP_AGAIN;
    }
}

static int ask_code(const char *s)
{
    int ret = 0;
    
    if (s==NULL) return -1;

    if (strlen(s) < 3) return -1;

    /* check to make sure 0-2 are digits */
    if ((isdigit((int) s[0])==0) ||
	(isdigit((int) s[1])==0) ||
	(isdigit((int) s[2])==0))
    {
	return -1;
    }

    ret = ((s[0]-'0')*100)+((s[1]-'0')*10)+(s[2]-'0');
    
    return ret;
}

static void chop(char *s)
{
    char *p;

    assert(s);
    p = s + strlen(s) - 1;
    if (p[0] == '\n') {
	*p-- = '\0';
    }
    if (p >= s && p[0] == '\r') {
	*p-- = '\0';
    }
}

static int mysasl_getauthline(struct protstream *p, char **line, 
			      unsigned int *linelen)
{
    char buf[2096];
    char *str = (char *) buf;
    
    if (!prot_fgets(str, sizeof(buf), p)) {
	return SASL_FAIL;
    }
    if (str[0] == '2') { return SASL_OK; }
    if (str[0] == '5') { return SASL_BADAUTH; }
    if (str[0] != '3') { return SASL_BADPROT; }
    else {
	size_t len;
	str += 4; /* jump past the "334 " */

	len = strlen(str) + 1;

	*line = xmalloc(strlen(str) + 1);
	if (*str != '\r') {	/* decode it */
	    int r;
	    
	    r = sasl_decode64(str, strlen(str), *line, len, linelen);
	    if (r != SASL_OK) {
		return r;
	    }
	    
	    return SASL_CONTINUE;
	} else {		/* blank challenge */
	    *line = NULL;
	    *linelen = 0;

	    return SASL_CONTINUE;
	}
    }
}

/* getlastresp reads from 'pin' until we get an LMTP that isn't a continuation.
   it puts it in 'buf', which must be at least 'len' big.

   '*code' will contain the integer three digit response code.
   if a read failed, '*code == 400', a temporary failure. 

   returns an IMAP error code. */
static int getlastresp(char *buf, int len, int *code, struct protstream *pin)
{
    do {
	if (!prot_fgets(buf, len, pin)) {
	    *code = 400;
	    return IMAP_SERVER_UNAVAILABLE;
	}
    } while (ISCONT(buf));
    *code = ask_code(buf);

    return 0;
}

/* perform authentication against connection 'conn'
   returns the SMTP error code from the AUTH attempt */
static int do_auth(struct lmtp_conn *conn)
{
    int r;
    sasl_security_properties_t *secprops = NULL;
    struct sockaddr_in saddr_l;
    struct sockaddr_in saddr_r;
    socklen_t addrsize;
    char buf[2048];
    char *in;
    const char *out;
    unsigned int inlen, outlen;
    const char *mechusing;
    unsigned b64len;
    char localip[60], remoteip[60];

    secprops = mysasl_secprops(0);
    r = sasl_setprop(conn->saslconn, SASL_SEC_PROPS, secprops);
    if (r != SASL_OK) {
	return r;
    }

    /* set the IP addresses */
    addrsize=sizeof(struct sockaddr_in);
    if (getpeername(conn->sock, (struct sockaddr *)&saddr_r, &addrsize) != 0)
	return SASL_FAIL;
    addrsize=sizeof(struct sockaddr_in);
    if (getsockname(conn->sock, (struct sockaddr *)&saddr_l,&addrsize)!=0)
	return SASL_FAIL;

    if (iptostring((struct sockaddr *)&saddr_r,
		   sizeof(struct sockaddr_in), remoteip, 60) != 0)
	return SASL_FAIL;
    if (iptostring((struct sockaddr *)&saddr_l,
		   sizeof(struct sockaddr_in), localip, 60) != 0)
	return SASL_FAIL;

    r = sasl_setprop(conn->saslconn, SASL_IPLOCALPORT, localip);
    if (r != SASL_OK) return r;
    r = sasl_setprop(conn->saslconn, SASL_IPREMOTEPORT, remoteip);
    if (r != SASL_OK) return r;

    /* we now do the actual SASL exchange */
    r = sasl_client_start(conn->saslconn, 
			  conn->mechs,
			  NULL, &out, &outlen, &mechusing);
    if ((r != SASL_OK) && (r != SASL_CONTINUE)) {
	return r;
    }
    if (out == NULL || outlen == 0) {
	prot_printf(conn->pout, "AUTH %s\r\n", mechusing);
    } else {
	/* send initial challenge */
	r = sasl_encode64(out, outlen, buf, sizeof(buf), &b64len);
	if (r != SASL_OK)
	    return r;
	prot_printf(conn->pout, "AUTH %s %s\r\n", mechusing, buf);
    }

    in = NULL;
    inlen = 0;
    r = mysasl_getauthline(conn->pin, &in, &inlen);
    while (r == SASL_CONTINUE) {
	r = sasl_client_step(conn->saslconn, in, inlen, NULL, &out, &outlen);
	if (in) { 
	    free(in);
	}
	if (r != SASL_OK && r != SASL_CONTINUE) {
	    return r;
	}

	r = sasl_encode64(out, outlen, buf, sizeof(buf), &b64len);
	if (r != SASL_OK) {
	    return r;
	}

	prot_write(conn->pout, buf, b64len);
	prot_printf(conn->pout, "\r\n");

	r = mysasl_getauthline(conn->pin, &in, &inlen);
    }

    if (r == SASL_OK) {
	prot_setsasl(conn->pin, conn->saslconn);
	prot_setsasl(conn->pout, conn->saslconn);
    }

    /* success */
    return 250;
}

/* establish connection, LHLO, and AUTH if possible */
int lmtp_connect(const char *phost, 
		 sasl_callback_t *cb, 
		 struct lmtp_conn **ret)
{
    int sock = -1;
    char *host = xstrdup(phost);
    struct lmtp_conn *conn;
    char buf[8192];
    int code;
    int unix_socket = 0;
    
    assert(host);
    assert(ret);

    if (host[0] == '/') {
	struct sockaddr_un addr;

	/* open unix socket */
	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	    syslog(LOG_ERR, "socket() failed %m");
	    goto donesock;
	}
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, host);
	if (connect(sock, (struct sockaddr *) &addr, 
		    sizeof(addr.sun_family) + strlen(addr.sun_path) + 1) < 0) {
	    syslog(LOG_ERR, "connect(%s) failed: %m", addr.sun_path);
	    goto donesock;
	}

	/* set that we are preauthed */
	unix_socket = 1;

	/* change host to 'config_servername' */
	free(host);
	host = xstrdup(config_servername);
    } else {
	struct hostent *hp;
	struct sockaddr_in addr;
	struct servent *service;
	char *p;

	p = strchr(host, ':');
	if (p) {
	    *p++ = '\0';
	} else {
	    p = "lmtp";
	}

	if ((hp = gethostbyname(host)) == NULL) {
	    syslog(LOG_ERR, "gethostbyname(%s) failed", host);
	    goto donesock;
	}

	/* open inet socket */
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	    syslog(LOG_ERR, "socket() failed: %m");
	    goto donesock;
	}

	addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
	service = getservbyname(p, "tcp");
	if (service) {
	    addr.sin_port = service->s_port;
	} else {
	    int pn = atoi(p);
	    if (pn == 0) {
		syslog(LOG_ERR, "couldn't find valid lmtp port");
		goto donesock;
	    }
	    addr.sin_port = htons(pn);
	}

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
	    syslog(LOG_ERR, "connect(%s:%s) failed: %m", host, p);
	    goto donesock;
	}	    
    }

 donesock:
    if (sock == -1) {
	/* error during connection */
	free(host);
	return IMAP_IOERROR;
    }
    
    conn = xmalloc(sizeof(struct lmtp_conn));
    conn->host = host;
    conn->sock = sock;
    conn->capability = 0;
    conn->mechs = NULL;
    conn->saslconn = NULL;
    /* setup prot layers */
    conn->pin = prot_new(sock, 0);
    conn->pout = prot_new(sock, 1);
    prot_setflushonread(conn->pin, conn->pout);

    /* read greeting */
    getlastresp(buf, sizeof(buf)-1, &code, conn->pin);
    if (!ISGOOD(code)) goto done;

    /* LHLO */
    prot_printf(conn->pout, "LHLO %s\r\n", config_servername);
    /* read responses */
    for (;;) {
	if (prot_fgets(buf, sizeof(buf)-1, conn->pin)) {
	    code = ask_code(buf);
	    if (code == 250) {
		chop(buf);
		/* check capability */
		if (!strcasecmp(buf + 4, "PIPELINING")) {
		    conn->capability |= CAPA_PIPELINING;
		}
		if (!strncasecmp(buf + 4, "AUTH ", 5)) {
		    conn->capability |= CAPA_AUTH;
		    /* save mechanisms for later */
		    conn->mechs = xstrdup(buf + 9);
		}
		if (!strcasecmp(buf + 4, "IGNOREQUOTA")) {
		    conn->capability |= CAPA_IGNOREQUOTA;
		}
	    }

	    if (ISCONT(buf) && ISGOOD(code)) {
		continue;
	    } else {
		break;
	    }
	}
	/* can't read response */
	code = 400; 
	break;
    }
    /* check status code */
    if (!ISGOOD(code)) goto done;

    /* AUTH (but only if we're not preauthed as postman!) */
    if (!unix_socket && (conn->capability & CAPA_AUTH) && (conn->mechs)) {
	sasl_client_new("lmtp", host, NULL, NULL, cb, 0, &conn->saslconn);
	code = do_auth(conn);
    }

 done:
    if (ISGOOD(code)) {
	/* return connection */
	*ret = conn;
	return 0;
    } else {
	/* not a successful connection; tear it down and return failure */
	if (conn) {
	    if (conn->host) free(conn->host);
	    if (conn->mechs) free(conn->mechs);
	    if (conn->saslconn) sasl_dispose(&conn->saslconn);
	    if (conn->sock) close(conn->sock);
	    free(conn);
	}
	return IMAP_SERVER_UNAVAILABLE;
    }
}

static void pushmsg(struct protstream *in, struct protstream *out,
		    int isdotstuffed)
{
    char buf[8192], *p;
    int lastline_hadendline = 1;

    while (prot_fgets(buf, sizeof(buf)-1, in)) {
	/* dot stuff */
	if (!isdotstuffed && (lastline_hadendline == 1) && (buf[0]=='.')) {
	    prot_putc('.', out);
	}
	p = buf + strlen(buf) - 1;
	if (*p == '\n') {
	    if (p == buf || p[-1] != '\r') {
		p[0] = '\r';
		p[1] = '\n';
		p[2] = '\0';
	    }
	    lastline_hadendline = 1;
	}
	else if (*p == '\r') {
	    if (buf[0] == '\r' && buf[1] == '\0') {
		/* The message contained \r\0, and fgets is confusing us.
		   XXX ignored
		 */
		lastline_hadendline = 1;
	    } else {
		/*
		 * We were unlucky enough to get a CR just before we ran
		 * out of buffer--put it back.
		 */
		prot_ungetc('\r', in);
		*p = '\0';
		lastline_hadendline = 0;
	    }
	} else {
	    lastline_hadendline = 0;
	}

	/* Remove any lone CR characters */
	while ((p = strchr(buf, '\r')) && p[1] != '\n') {
	    strcpy(p, p+1);
	}

	prot_write(out, buf, strlen(buf));
    }

    if (!isdotstuffed) {
	/* signify end of message */
	prot_printf(out, "\r\n.\r\n");
    }
}

int lmtp_runtxn(struct lmtp_conn *conn, struct lmtp_txn *txn)
{
    int j, code, r = 0;
    char buf[8192];
    int onegood;

    assert(conn && txn);
    /* pipelining v. no pipelining? */

    /* here's the straightforward non-pipelining version */

    /* rset */
    prot_printf(conn->pout, "RSET\r\n");
    r = getlastresp(buf, sizeof(buf)-1, &code, conn->pin);
    if (!ISGOOD(code)) {
	goto failall;
    }

    /* mail from */
    prot_printf(conn->pout, "MAIL FROM:<%s>", txn->from ? txn->from : "<>");
    if (conn->capability & CAPA_AUTH) {
	prot_printf(conn->pout, " AUTH=%s", txn->auth ? txn->auth : "<>");
    }
    prot_printf(conn->pout, "\r\n");
    r = getlastresp(buf, sizeof(buf)-1, &code, conn->pin);
    if (!ISGOOD(code)) {
	goto failall;
    }

    /* rcpt to */
    onegood = 0;
    for (j = 0; j < txn->rcpt_num; j++) {
	prot_printf(conn->pout, "RCPT TO:<%s>", txn->rcpt[j].addr);
	if (txn->ignorequota && (conn->capability & CAPA_IGNOREQUOTA)) {
	    prot_printf(conn->pout, " IGNOREQUOTA");
	}
	prot_printf(conn->pout, "\r\n");
	r = getlastresp(buf, sizeof(buf)-1, &code, conn->pin);
	if (r) {
	    goto failall;
	}
	txn->rcpt[j].r = revconvert_lmtp(buf);
	if (ISGOOD(code)) {
	    onegood = 1;
	    txn->rcpt[j].result = RCPT_GOOD;
	} else if (TEMPFAIL(code)) {
	    txn->rcpt[j].result = RCPT_TEMPFAIL;
	} else if (PERMFAIL(code)) {
	    txn->rcpt[j].result = RCPT_PERMFAIL;
	} else {
	    /* yikes?!? */
	    code = 400;
	    goto failall;
	}
    }
    if (!onegood) {
	/* all recipients failed! */
	return 0;
    }

    /* data */
    prot_printf(conn->pout, "DATA\r\n");
    r = getlastresp(buf, sizeof(buf)-1, &code, conn->pin);
    if (r) {
	goto failall;
    }
    if (code != 354) {
	/* erg? */
	if (ISGOOD(code)) code = 400;
	r = IMAP_PROTOCOL_ERROR;
	goto failall;
    }

    /* send the data, dot-stuffing as needed */
    pushmsg(txn->data, conn->pout, txn->isdotstuffed);

    /* read the response codes, one for each accepted RCPT TO */
    for (j = 0; j < txn->rcpt_num; j++) {
	if (txn->rcpt[j].result == RCPT_GOOD) {
	    /* expecting a status code for this recipient */
	    r = getlastresp(buf, sizeof(buf)-1, &code, conn->pin);
	    if (r) {
		/* technically, some recipients might've succeeded here, 
		   but we'll be paranoid */
		goto failall;
	    }
	    txn->rcpt[j].r = revconvert_lmtp(buf);
	    if (ISGOOD(code)) {
		onegood = 1;
		txn->rcpt[j].result = RCPT_GOOD;
	    } else if (TEMPFAIL(code)) {
		txn->rcpt[j].result = RCPT_TEMPFAIL;
	    } else if (PERMFAIL(code)) {
		txn->rcpt[j].result = RCPT_PERMFAIL;
	    } else {
		/* yikes?!? */
		txn->rcpt[j].result = RCPT_TEMPFAIL;
	    }
	}
    }
    
    /* done with txn */
    return 0;
    
 failall:
    /* something fatal happened during the transaction; we should assign
       'code' to all recipients and return */
    for (j = 0; j < txn->rcpt_num; j++) {
	if (ISGOOD(code)) {
	    txn->rcpt[j].r = 0;
	    txn->rcpt[j].result = RCPT_GOOD;
	} else if (TEMPFAIL(code)) {
	    txn->rcpt[j].r = IMAP_AGAIN;
	    txn->rcpt[j].result = RCPT_TEMPFAIL;
	} else if (PERMFAIL(code)) {
	    txn->rcpt[j].r = IMAP_PROTOCOL_ERROR;
	    txn->rcpt[j].result = RCPT_PERMFAIL;
	} else {
	    /* code should have been a valid number */
	    abort();
	}
    }

    /* return overall error code already set */
    return r;
}

/* send a NOOP to the conn to verify it's still ok */
int lmtp_verify_conn(struct lmtp_conn *conn)
{
    char buf[8192];
    int r = 0;
    int code = 0;

    /* noop me */
    prot_printf(conn->pout, "NOOP\r\n");
    r = getlastresp(buf, sizeof(buf)-1, &code, conn->pin);
    if (!r && !ISGOOD(code)) {
	r = IMAP_SERVER_UNAVAILABLE;
    }

    return r;
}

int lmtp_disconnect(struct lmtp_conn *conn)
{
    /* quit */
    prot_printf(conn->pout, "QUIT\r\n");
    /* wait for any response */
    prot_getc(conn->pin);

    /* close connection */
    close(conn->sock);

    /* free 'conn' */
    free(conn->host);
    prot_free(conn->pin);
    prot_free(conn->pout);
    if (conn->saslconn) sasl_dispose(&conn->saslconn);
    if (conn->mechs) free(conn->mechs);

    return 0;
}

/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(sasl_conn_t **conn) 
{
    int ret, secflags;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(conn);
    /* do initialization typical of service_main */
    ret = sasl_server_new("lmtp", config_servername,
                         NULL, NULL, NULL,
                         NULL, 0, conn);
    if(ret != SASL_OK) return ret;

    if(saslprops.ipremoteport)
       ret = sasl_setprop(*conn, SASL_IPREMOTEPORT,
                          saslprops.ipremoteport);
    if(ret != SASL_OK) return ret;
    
    if(saslprops.iplocalport)
       ret = sasl_setprop(*conn, SASL_IPLOCALPORT,
                          saslprops.iplocalport);
    if(ret != SASL_OK) return ret;
    
    secflags = SASL_SEC_NOANONYMOUS;
    if (!config_getswitch("allowplaintext", 1)) {
	secflags |= SASL_SEC_NOPLAINTEXT;
    }
    secprops = mysasl_secprops(secflags);
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if(ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if(saslprops.ssf) {
       ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &saslprops.ssf);
    }
    if(ret != SASL_OK) return ret;

    if(saslprops.authid) {
       ret = sasl_setprop(*conn, SASL_AUTH_EXTERNAL, saslprops.authid);
       if(ret != SASL_OK) return ret;
    }
    /* End TLS/SSL Info */

    return SASL_OK;
}
