/* lmtpengine.c: LMTP protocol engine
 * $Id: lmtpengine.c,v 1.29 2001/08/18 01:13:42 ken3 Exp $
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
#include <sys/wait.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sasl.h>
#include <saslutil.h>

#include "assert.h"
#include "util.h"
#include "auth.h"
#include "prot.h"
#include "imapconf.h"
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

static char *convert_lmtp(int r)
{
    switch (r) {
    case 0:
	return "250 2.1.5 Ok";
	
    case IMAP_IOERROR:
	return "451 4.3.0 System I/O error";

    case IMAP_SERVER_UNAVAILABLE:
	return "451 4.4.0 Remote server unavailable";

    case IMAP_NOSPACE:
	return "451 4.3.1 cannot create file: out of space";

    case IMAP_AGAIN:
	return "451 4.3.0 transient system error";
		
    case IMAP_PERMISSION_DENIED:
	return "550 5.7.1 Permission denied";

    case IMAP_QUOTA_EXCEEDED:
	return "452 4.2.2 Over quota";

    case IMAP_MAILBOX_BADFORMAT:
    case IMAP_MAILBOX_NOTSUPPORTED:
	return "451 4.2.0 Mailbox has an invalid format";

    case IMAP_MESSAGE_CONTAINSNULL:
	return "554 5.6.0 Message contains NUL characters";
	
    case IMAP_MESSAGE_CONTAINSNL:
	return "554 5.6.0 Message contains bare newlines";

    case IMAP_MESSAGE_CONTAINS8BIT:
	return "554 5.6.0 Message contains non-ASCII characters in headers";

    case IMAP_MESSAGE_BADHEADER:
	return "554 5.6.0 Message contains invalid header";

    case IMAP_MESSAGE_NOBLANKLINE:
	return "554 5.6.0 Message has no header/body separator";

    case IMAP_MAILBOX_NONEXISTENT:
	/* XXX Might have been moved to other server */
	return "550 5.1.1 User unknown";
    }

    /* Some error we're not expecting. */
    return "554 5.0.0 Unexpected internal error";
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
static int savemsg(struct protstream *pin, 
		   struct protstream *pout, 
		   const char *addheaders,
		   message_data_t *m)
{
    FILE *f;
    struct stat sbuf;
    const char **body;
    int r;
    int nrcpts = m->rcpt_num;

    /* Copy to temp file */
    f = tmpfile();
    if (!f) {
	prot_printf(pout, "451 4.3.%c cannot create temporary file: %s\r\n",
		    (
#ifdef EDQUOT
			errno == EDQUOT ||
#endif
			errno == ENOSPC) ? '1' : '2',
		    error_message(errno));
	return IMAP_IOERROR;
    }

    prot_printf(pout, "354 go ahead\r\n");

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

    /* add any requested headers */
    if (addheaders) {
	fputs(addheaders, f);
    }

    /* fill the cache */
    r = fill_cache(pin, f, m);
    if (r) {
	fclose(f);
	while (nrcpts--) {
	    prot_printf(pout, "%s\r\n", convert_lmtp(r));
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
	    prot_printf(pout,
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
	    prot_printf(pout,
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
   on failure, return an error message. */
static char *process_recipient(char *addr,
			       int (*verify_user)(const char *),
			       address_data_t **ad)
{
    char *dest;
    char *user;
    int r, sl;
    address_data_t *ret = (address_data_t *) xmalloc(sizeof(address_data_t));

    assert(addr != NULL && ad != NULL);

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
	    return "501 5.5.4 Syntax error in parameters";
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
	
    r = verify_user(user);
    if (r) {
	/* we lost */
	free(ret->all);
	free(ret);
	return convert_lmtp(r);
    }
    ret->user = xstrdup(user);

    *ad = ret;

    return NULL;
}    

#ifdef HAVE_SSL
static int starttls_enabled(void)
{
    if (!config_getstring("tls_lmtp_cert_file",
			 config_getstring("tls_cert_file", NULL))) return 0;
    if (!config_getstring("tls_lmtp_key_file",
			  config_getstring("tls_key_file", NULL))) return 0;
    return 1;
}
#else
static void starttls_enabled(void)
{
    return 0;
}
#endif /* HAVE_SSL */

void lmtpmode(struct lmtp_func *func,
	      struct protstream *pin, 
	      struct protstream *pout,
	      int fd)
{
    message_data_t *msg = NULL;
    char buf[4096];
    char *p;
    int r;
    char *err;

    struct sockaddr_in localaddr, remoteaddr;
    socklen_t salen;
    struct hostent *hp;
    char clienthost[250];

    sasl_conn_t *conn = NULL;
    int secflags = 0;
    sasl_security_properties_t *secprops = NULL;
    sasl_external_properties_t *extprops = NULL;
    int authenticated = 0;	/* -1: external auth'd, but no AUTH issued
				    0: no auth
				    1: did AUTH */
    char *authuser = NULL;
    struct auth_state *authstate = NULL;

#ifdef HAVE_SSL
    static SSL *tls_conn = NULL;
#endif /* HAVE_SSL */
    int starttls_done = 0;


    msg_new(&msg);
    if (sasl_server_new("lmtp", NULL, NULL, NULL, 0, &conn) != SASL_OK) {
	fatal("SASL failed initializing: sasl_server_new()", EC_TEMPFAIL);
    }

    /* set my allowable security properties */
    secflags = SASL_SEC_NOANONYMOUS;
    if (!config_getswitch("allowplaintext", 1)) {
	secflags |= SASL_SEC_NOPLAINTEXT;
    }
    secprops = mysasl_secprops(secflags);
    sasl_setprop(conn, SASL_SEC_PROPS, secprops);

    /* determine who we're talking to */
    salen = sizeof(remoteaddr);
    r = getpeername(fd, (struct sockaddr *)&remoteaddr, &salen);
    if (!r && remoteaddr.sin_family == AF_INET) {
	/* connected to an internet socket */

	hp = gethostbyaddr((char *)&remoteaddr.sin_addr,
			   sizeof(remoteaddr.sin_addr), AF_INET);
	if (hp != NULL) {
	    strncpy(clienthost, hp->h_name, sizeof(clienthost)-30);
	    clienthost[sizeof(clienthost)-30] = '\0';
	} else {
	    clienthost[0] = '\0';
	}
	strcat(clienthost, "[");
	strcat(clienthost, inet_ntoa(remoteaddr.sin_addr));
	strcat(clienthost, "]");

	salen = sizeof(localaddr);
	if (!getsockname(fd, (struct sockaddr *)&localaddr, &salen)) {
	    /* set the ip addresses here */
	    sasl_setprop(conn, SASL_IP_REMOTE, &remoteaddr);  
	    sasl_setprop(conn, SASL_IP_LOCAL,  &localaddr );
	} else {
	    fatal("can't get local addr", EC_SOFTWARE);
	}

	syslog(LOG_DEBUG, "connection from [%s]%s", 
	       inet_ntoa(remoteaddr.sin_addr),
	       func->preauth ? " preauth'd as postman" : "");
    } else {
	/* we're not connected to a internet socket! */
	func->preauth = 1;
	strcpy(clienthost, "[local]");
	syslog(LOG_DEBUG, "lmtp connection preauth'd as postman");
    }

    if (func->preauth) {
	authenticated = -1;	/* we'll allow commands, 
				   but we still accept the AUTH command */
	extprops = (sasl_external_properties_t *) 
	    xmalloc(sizeof(sasl_external_properties_t));
	extprops->ssf = 2;
	extprops->auth_id = "postman";
	sasl_setprop(conn, SASL_SSF_EXTERNAL, extprops);
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
	      char *in = NULL, *out = NULL;
	      unsigned int inlen, outlen;
	      const char *errstr;
	      char *user;
	      
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
	      if (p != NULL) {
		  in = xmalloc(strlen(p));
		  r = sasl_decode64(p, strlen(p), in, &inlen);
		  if (r != SASL_OK) {
		      prot_printf(pout,
				  "501 5.5.4 cannot base64 decode\r\n");
		      if (in) { free(in); in = NULL; }
		      continue;
		  }
	      } else {
		  in = NULL;
		  inlen = 0;
	      }
	      
	      r = sasl_server_start(conn, mech,
				    in, inlen,
				    &out, &outlen,
				    &errstr);
	      if (in) { free(in); in = NULL; }
	      if (r == SASL_NOMECH) {
		  prot_printf(pout, 
			      "504 Unrecognized authentication type.\r\n");
		  continue;
	      }
	      
	      while (r == SASL_CONTINUE) {
		  char inbase64[4096];
		  
		  r = sasl_encode64(out, outlen, 
				    inbase64, sizeof(inbase64), NULL);
	  if (r != SASL_OK) break;

		  /* send out */
		  prot_printf(pout,"334 %s\r\n", inbase64);
		  
		  /* read a line */
		  if (!prot_fgets(buf, sizeof(buf)-1, pin)) {
		      goto cleanup;
		  }
		  p = buf + strlen(buf) - 1;
		  if (p >= buf && *p == '\n') *p-- = '\0';
		  if (p >= buf && *p == '\r') *p-- = '\0';
		  
		  in = xmalloc(strlen(buf));
		  r = sasl_decode64(buf, strlen(buf), in, &inlen);
		  if (r != SASL_OK) {
		      prot_printf(pout,
				  "501 5.5.4 cannot base64 decode\r\n");
		      goto nextcmd; /* what's the state of our sasl_conn_t? */
		  }

		  if (out) { free(out); out = NULL; }
		  r = sasl_server_step(conn,
				       in, inlen,
				       &out, &outlen,
				       &errstr);
		  if (in) { free(in); in = NULL; }
	      }
	      
	      if (in) { free(in); in = NULL; }
	      if (out) { free(out); out = NULL; }
	      if ((r != SASL_OK) && (r != SASL_CONTINUE)) {
		  if (errstr) {
		      syslog(LOG_ERR, "badlogin: %s %s %s [%s]",
			     remoteaddr.sin_family == AF_INET ?
			        inet_ntoa(remoteaddr.sin_addr) :
			        "[unix socket]",
			     mech,
			     sasl_errstring(r, NULL, NULL), 
			     errstr);
		  } else {
		      syslog(LOG_ERR, "badlogin: %s %s %s",
			     remoteaddr.sin_family == AF_INET ?
			        inet_ntoa(remoteaddr.sin_addr) :
			        "[unix socket]",
			     mech,
			     sasl_errstring(r, NULL, NULL));
		  }
		  
		  snmp_increment_args(AUTHENTICATION_NO, 1,
				      VARIABLE_AUTH, hash_simple(mech), 
				      VARIABLE_LISTEND);

		  prot_printf(pout, "501 5.5.4 %s\r\n",
			      sasl_errstring(sasl_usererr(r), NULL, NULL));
		  continue;
	      }
	      r = sasl_getprop(conn, SASL_USERNAME, (void **) &user);
	      if (r != SASL_OK) user = "[sasl error]";

	      /* authenticated successfully! */
	      snmp_increment_args(AUTHENTICATION_YES,1,
				  VARIABLE_AUTH, hash_simple(mech), 
				  VARIABLE_LISTEND);
	      syslog(LOG_NOTICE, "login: %s %s %s%s %s",
		     remoteaddr.sin_family == AF_INET ?
		        inet_ntoa(remoteaddr.sin_addr) :
		        "[unix socket]",
		     user, mech, starttls_done ? "+TLS" : "", "User logged in");

	      authenticated += 2;
	      prot_printf(pout, "235 Authenticated!\r\n");

	      /* set protection layers */
	      prot_setsasl(pin,  conn);
	      prot_setsasl(pout, conn);
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
		r = savemsg(pin, pout, func->addheaders, msg);
		if (r) continue;

		snmp_increment(mtaReceivedMessages, 1);
		snmp_increment(mtaReceivedVolume, roundToK(msg->size));
		snmp_increment(mtaReceivedRecipients, msg->rcpt_num);

		/* do delivery, report status */
		r = func->deliver(msg, authuser, authstate);
		for (j = 0; j < msg->rcpt_num; j++) {
		    if (!msg->rcpt[j]->status) delivered++;
		    prot_printf(pout, "%s\r\n", 
				convert_lmtp(msg->rcpt[j]->status));
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
	      char *mechs;
	      
	      prot_printf(pout, "250-%s\r\n"
			  "250-IGNOREQUOTA\r\n"
			  "250-8BITMIME\r\n"
			  "250-ENHANCEDSTATUSCODES\r\n",
			  config_servername);
	      if (starttls_enabled() && !func->preauth) {
		  prot_printf(pout, "250-STARTTLS\r\n");
	      }
	      if (sasl_listmech(conn, NULL, "AUTH ", " ", "", &mechs, 
				NULL, &mechcount) == SASL_OK && 
		  mechcount > 0) {
		  prot_printf(pout,"250-%s\r\n", mechs);
		  free(mechs);
	      }
	      prot_printf(pout, "250 PIPELINING\r\n");
	      
	      continue;
	  }
	  goto syntaxerr;
    
      case 'm':
      case 'M':
	    if (!authenticated) {
		prot_printf(pout, 
			    "530 Authentication required\r\n");
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
			authuser = parseautheq(&tmp);
			if (authuser) {
			    authstate = auth_newstate(authuser, NULL);
			} else {
			    /* do we want to bounce mail because of this? */
			    /* i guess not. accept with no auth user */
			    authstate = NULL;
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

		err = process_recipient(rcpt, 
					func->verify_user,
					&msg->rcpt[msg->rcpt_num]);
		if (rcpt) free(rcpt); /* malloc'd in parseaddr() */
		if (err != NULL) {
		    prot_printf(pout, "%s\r\n", err);
		    continue;
		}
		msg->rcpt[msg->rcpt_num]->ignorequota = ignorequota;
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
		if (authuser) {
		    free(authuser);
		    authuser = NULL;
		}
		if (authstate) {
		    auth_freestate(authstate);
		    authstate = NULL;
		}
		
		continue;
	    }
	    goto syntaxerr;

      case 's':
      case 'S':
#ifdef HAVE_SSL
	    if (!strcasecmp(buf, "starttls") && starttls_enabled() &&
		!func->preauth) { /* don't need TLS for preauth'd connect */
		char *tls_cert, *tls_key;
		int *layerp;
		sasl_external_properties_t external;


		/* SASL and openssl have different ideas
		   about whether ssf is signed */
		layerp = (int *) &(external.ssf);

		if (starttls_done == 1) {
		    prot_printf(pout, "454 4.3.3 %s\r\n", 
				"Already successfully executed STARTTLS");
		    continue;
		}
		if (msg->rcpt_num != 0) {
		    prot_printf(pout,
				"503 5.5.0 STARTTLS not permitted now\r\n");
		    continue;
		}

		tls_cert = (char *)config_getstring("tls_lmtp_cert_file",
						    config_getstring("tls_cert_file", ""));
		tls_key = (char *)config_getstring("tls_lmtp_key_file",
						   config_getstring("tls_key_file", ""));

		r=tls_init_serverengine(5,   /* depth to verify */
					1,   /* can client auth? */
					0,   /* require client to auth? */
					1,   /* TLS only? */
					(char *)config_getstring("tls_ca_file", ""),
					(char *)config_getstring("tls_ca_path", ""),
					tls_cert, tls_key);

		if (r == -1) {

		    syslog(LOG_ERR, "[lmtpd] error initializing TLS: "
			   "[CA_file: %s] [CA_path: %s] [cert_file: %s] [key_file: %s]",
			   (char *) config_getstring("tls_ca_file", ""),
			   (char *) config_getstring("tls_ca_path", ""),
			   tls_cert, tls_key);

		    prot_printf(pout, "454 4.3.3 %s\r\n", "Error initializing TLS");
		    continue;
		}

		prot_printf(pout, "220 %s\r\n", "Begin TLS negotiation now");
		/* must flush our buffers before starting tls */
		prot_flush(pout);
  
		r=tls_start_servertls(0, /* read */
				      1, /* write */
				      layerp,
				      &(external.auth_id),
				      &tls_conn);

		/* if error */
		if (r==-1) {
		    prot_printf(pout, "454 4.3.3 STARTTLS failed\r\n");
		    syslog(LOG_NOTICE, "[lmtpd] STARTTLS failed: %s", clienthost);
		    continue;
		}

		/* tell SASL about the negotiated layer */
		r = sasl_setprop(conn, SASL_SSF_EXTERNAL, &external);

		if (r != SASL_OK) {
		    fatal("sasl_setprop() failed: STARTTLS", EC_TEMPFAIL);
		}

		/* tell the prot layer about our new layers */
		prot_settls(pin, tls_conn);
		prot_settls(pout, tls_conn);

		starttls_done = 1;

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
    if (conn) sasl_dispose(&conn);
    if (extprops) free(extprops);
    if (authuser) free(authuser);
    if (authstate) auth_freestate(authstate);

    starttls_done = 0;
#ifdef HAVE_SSL
    if (tls_conn) {
	tls_reset_servertls(&tls_conn);
	tls_conn = NULL;
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

/* xxx fill in this function 

   perform authentication against connection 'conn'
   returns the SMTP error code from the AUTH attempt */
static int do_auth(struct lmtp_conn *conn)
{
    /* pretend success for now */
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
    sasl_external_properties_t *extprops = NULL;

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

	/* set external properties */
	extprops = (sasl_external_properties_t *) 
	    xmalloc(sizeof(sasl_external_properties_t));
	extprops->ssf = 2;
	extprops->auth_id = "postman";

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
    for (;;) {
	if (prot_fgets(buf, sizeof(buf)-1, conn->pin)) {
	    code = ask_code(buf);
	    if (ISCONT(buf) && ISGOOD(code)) {
		continue;
	    }
	} else {
	    /* can't read greeting */
	    code = 400;
	}
	break;
    }
    /* check status code */
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

    /* AUTH */
    if ((conn->capability & CAPA_AUTH) && (conn->mechs)) {
	sasl_client_new("lmtp", host, cb, 0, &conn->saslconn);
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
    if (!prot_fgets(buf, sizeof(buf)-1, conn->pin)) {
	code = 400;
	r = IMAP_SERVER_UNAVAILABLE;
	goto failall;
    }
    code = ask_code(buf);
    if (!ISGOOD(code)) {
	goto failall;
    }

    /* mail from */
    prot_printf(conn->pout, "MAIL FROM:<%s>", txn->from ? txn->from : "<>");
    if (conn->capability & CAPA_AUTH) {
	prot_printf(conn->pout, " AUTH=%s", txn->auth ? txn->auth : "<>");
    }
    prot_printf(conn->pout, "\r\n");
    if (!prot_fgets(buf, sizeof(buf)-1, conn->pin)) {
	code = 400;
	r = IMAP_SERVER_UNAVAILABLE;
	goto failall;
    }
    code = ask_code(buf);
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
	if (!prot_fgets(buf, sizeof(buf)-1, conn->pin)) {
	    code = 400;
	    r = IMAP_SERVER_UNAVAILABLE;
	    goto failall;
	}
	code = ask_code(buf);
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
    if (!prot_fgets(buf, sizeof(buf)-1, conn->pin)) {
	code = 400;
	r = IMAP_SERVER_UNAVAILABLE;
	goto failall;
    }
    code = ask_code(buf);
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
	    if (!prot_fgets(buf, sizeof(buf)-1, conn->pin)) {
		/* technically, some recipients might've succeeded here, 
		   but we'll be paranoid */
		code = 400;
		r = IMAP_SERVER_UNAVAILABLE;
		goto failall;
	    }
	    code = ask_code(buf);
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

    /* noop me */
    prot_printf(conn->pout, "NOOP\r\n");
    if (prot_fgets(buf, sizeof(buf)-1, conn->pin)) {
	int code = ask_code(buf);

	if (!ISGOOD(code)) r = IMAP_SERVER_UNAVAILABLE;
    } else {
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
