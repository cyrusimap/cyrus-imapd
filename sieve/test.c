/*NEW
  
 * test.c -- tester for libsieve
 * Larry Greenfield
 *
 * usage: "test message script"
 */
/*
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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
 * $Id: test.c,v 1.29 2008/03/24 20:08:46 murch Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "sieve_interface.h"
#include "bytecode.h"
#include "comparator.h"
#include "tree.h"
#include "sieve.h"
#include "imap/message.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

/* XXX so we can link against imap/message.o */
unsigned mailbox_cached_header_inline(const char *text __attribute__((unused)))
{ return BIT32_MAX; }
void message_guid_generate(struct message_guid *guid __attribute__((unused)),
			   const char *msg_base __attribute__((unused)),
			   unsigned long msg_len __attribute__((unused)))
{ return; }
void message_guid_copy(struct message_guid *dst __attribute__((unused)),
		       struct message_guid *src __attribute__((unused)))
{ return; }
int message_guid_isnull(struct message_guid *guid __attribute__((unused)))
{ return 0; }

#define HEADERCACHESIZE 1019

typedef struct Header {
    char *name;
    int ncontents;
    char *contents[1];
} header_t;

typedef struct message_data {
    char *name;
    FILE *data;
    int size;
    struct message_content content;

    int cache_full;
    header_t *cache[HEADERCACHESIZE];
} message_data_t;

int hashheader(char *header)
{
    int x = 0;
    /* any CHAR except ' ', :, or a ctrl char */
    for (; !iscntrl(*header) && (*header != ' ') && (*header != ':'); 
	 header++) {
	x *= 256;
	x += *header;
	x %= HEADERCACHESIZE;
    }
    return x;
}

/* take a list of headers, pull the first one out and return it in
   name and contents.

   returns 0 on success, negative on failure */
typedef enum {
    HDR_NAME_START,
    HDR_NAME,
    COLON,
    HDR_CONTENT_START,
    HDR_CONTENT
} state;

int parseheader(FILE *f, char **headname, char **contents) {
    char c;
    char name[80], body[1024];
    int off = 0;
    state s = HDR_NAME_START;


    /* there are two ways out of this loop, both via gotos:
       either we successfully read a character (got_header)
       or we hit an error (ph_error) */
    while ((c = getc(f))) {	/* examine each character */
	switch (s) {
	case HDR_NAME_START:
	    if (c == '\r' || c == '\n') {
		/* no header here! */
		goto ph_error;
	    }
	    if (!isalpha(c))
		goto ph_error;
	    name[0] = tolower(c);
	    off = 1;
	    s = HDR_NAME;
	    break;

	case HDR_NAME:
	    if (c == ' ' || c == '\t' || c == ':') {
		name[off] = '\0';
		s = (c == ':' ? HDR_CONTENT_START : COLON);
		break;
	    }
	    if (iscntrl(c)) {
		goto ph_error;
	    }
	    name[off++] = tolower(c);
	    break;
	
	case COLON:
	    if (c == ':') {
		s = HDR_CONTENT_START;
	    } else if (c != ' ' && c != '\t') {
		goto ph_error;
	    }
	    break;

	case HDR_CONTENT_START:
	    if (c == ' ' || c == '\t') /* eat the whitespace */
		break;
	    off = 0;
	    s = HDR_CONTENT;
	    /* falls through! */
	case HDR_CONTENT:
	    if (c == '\r' || c == '\n') {
		int peek = getc(f);

		/* we should peek ahead to see if it's folded whitespace */
		if (c == '\r' && peek == '\n') {
		    c = getc(f);
		} else {
		    c = peek; /* single newline seperator */
		}
		if (c != ' ' && c != '\t') {
		    /* this is the end of the header */
		    body[off] = '\0';
		    ungetc(c, f);
		    goto got_header;
		}
		/* ignore this whitespace, but we'll copy all the rest in */
		break;
	    } else {
		/* just an ordinary character */
		body[off++] = c;
	    }
	}
    }

    /* if we fall off the end of the loop, we hit some sort of error
       condition */

 ph_error:
    if (headname != NULL) *headname = NULL;
    if (contents != NULL) *contents = NULL;
    return -1;

 got_header:
    if (headname != NULL) *headname = strdup(name);
    if (contents != NULL) *contents = strdup(body);

    return 0;
}

void fill_cache(message_data_t *m)
{
    rewind(m->data);

    /* let's fill that header cache */
    for (;;) {
	char *name, *body;
	int cl, clinit;

	if (parseheader(m->data, &name, &body) < 0) {
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
		    realloc(m->cache[cl],sizeof(header_t) +
			    ((8 + m->cache[cl]->ncontents) * sizeof(char *)));
		if (m->cache[cl] == NULL) {
		    fprintf(stderr, "realloc() returned NULL\n");
		    exit(1);
		}
	    }

	} else {
	    /* create a new entry in the hash table */
	    m->cache[cl] = (header_t *) malloc(sizeof(header_t) + 
					       8 * sizeof(char*));
	    if (m->cache[cl] == NULL) {
		fprintf(stderr, "malloc() returned NULL\n");
		exit(1);
	    }
	    m->cache[cl]->name = name;
	    m->cache[cl]->contents[0] = body;
	    m->cache[cl]->ncontents = 1;
	}

	/* we always want a NULL at the end */
	m->cache[cl]->contents[m->cache[cl]->ncontents] = NULL;
    }

    m->cache_full = 1;
}

/* gets the header "head" from msg. */
int getheader(void *v, const char *phead, const char ***body)
{
    message_data_t *m = (message_data_t *) v;
    int cl, clinit;
    char *h;
    char *head;

    *body = NULL;

    if (!m->cache_full) {
	fill_cache(m);
    }

    /* copy header parameter so we can mangle it */
    head = malloc(strlen(phead)+1);
    if (!head) return SIEVE_FAIL;
    strcpy(head, phead);

    h = head;
    while (*h != '\0') {
	*h = tolower(*h);
	h++;
    }

    /* check the cache */
    clinit = cl = hashheader(head);
    while (m->cache[cl] != NULL) {
	if (!strcmp(head, m->cache[cl]->name)) {
	    *body = (const char **) m->cache[cl]->contents;
	    break;
	}
	cl++; /* try next hash bin */
	cl %= HEADERCACHESIZE;
	if (cl == clinit) break; /* gone all the way around */
    }

    free(head);

    if (*body) {
  	return SIEVE_OK;
    } else {
	return SIEVE_FAIL;
    }
}

message_data_t *new_msg(FILE *msg, int size, char *name)
{
    int i;
    message_data_t *m;

    m = (message_data_t *) malloc(sizeof(message_data_t));
    if (m == NULL) {
	fprintf(stderr, "malloc() returned NULL\n");
	exit(1);
    }
    m->data = msg;
    m->size = size;
    m->name = name;
    m->content.base = NULL;
    m->content.len = 0;
    m->content.body = NULL;
    for (i = 0; i < HEADERCACHESIZE; i++) {
	m->cache[i] = NULL;
    }
    m->cache_full = 0;

    return m;
}

int getsize(void *mc, int *size)
{
    message_data_t *m = (message_data_t *) mc;

    *size = m->size;
    return SIEVE_OK;
}

int getenvelope(void *v __attribute__((unused)),
		const char *head, const char ***body)
{
    static const char *buf[2];

    if (buf[0] == NULL) { buf[0] = malloc(sizeof(char) * 256); buf[1] = NULL; }
    printf("Envelope body of '%s'? ", head);
    scanf("%s", (char*) buf[0]);
    *body = buf;

    return SIEVE_OK;
}

int getbody(void *mc, const char **content_types, sieve_bodypart_t ***parts)
{
    message_data_t *m = (message_data_t *) mc;
    int r = 0;

    if (!m->content.body) {
	/* parse the message body if we haven't already */
	r = message_parse_file(m->data, &m->content.base,
			       &m->content.len, &m->content.body);
    }

    /* XXX currently struct bodypart as defined in message.h is the same as
       sieve_bodypart_t as defined in sieve_interface.h, so we can typecast */
    if (!r) message_fetch_part(&m->content, content_types,
			       (struct bodypart ***) parts);
    return (!r ? SIEVE_OK : SIEVE_FAIL);
}

int getinclude(void *sc __attribute__((unused)),
	       const char *script,
	       int isglobal __attribute__((unused)),
	       char *fpath, size_t size)
{
    strlcpy(fpath, script, size);
    strlcat(fpath, ".bc", size);

    return SIEVE_OK;
}

int redirect(void *ac, void *ic, void *sc __attribute__((unused)),
	     void *mc, const char **errmsg __attribute__((unused)))
{
    sieve_redirect_context_t *rc = (sieve_redirect_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("redirecting message '%s' to '%s'\n", m->name, rc->addr);

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

int discard(void *ac __attribute__((unused)),
	    void *ic, void *sc __attribute__((unused)),
	    void *mc, const char **errmsg __attribute__((unused)))
{
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("discarding message '%s'\n", m->name);

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

int reject(void *ac, void *ic, void *sc __attribute__((unused)),
	   void *mc, const char **errmsg __attribute__((unused)))
{
    sieve_reject_context_t *rc = (sieve_reject_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("rejecting message '%s' with '%s'\n", m->name, rc->msg);

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

int fileinto(void *ac, void *ic, void *sc __attribute__((unused)),
	     void *mc, const char **errmsg __attribute__((unused)))
{
    sieve_fileinto_context_t *fc = (sieve_fileinto_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("filing message '%s' into '%s'\n", m->name, fc->mailbox);

    if (fc->imapflags->flag) {
	int n;
	printf("\twith flags");
	for (n = 0; n < fc->imapflags->nflags; n++)
	    printf(" '%s'", fc->imapflags->flag[n]);
	printf("\n");
    }

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

int keep(void *ac, void *ic, void *sc __attribute__((unused)),
	 void *mc, const char **errmsg __attribute__((unused)))
{
    sieve_keep_context_t *kc = (sieve_keep_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("keeping message '%s'\n", m->name);
    if (kc->imapflags->flag) {
	int n;
	printf("\twith flags");
	for (n = 0; n < kc->imapflags->nflags; n++)
	    printf(" '%s'", kc->imapflags->flag[n]);
	printf("\n");
    }

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

int notify(void *ac, void *ic, void *sc __attribute__((unused)),
	   void *mc __attribute__((unused)),
	   const char **errmsg __attribute__((unused)))
{
    sieve_notify_context_t *nc = (sieve_notify_context_t *) ac;
    int *force_fail = (int*) ic;
    int flag = 0;

    printf("notify ");
    if (nc->method) {
	const char **opts = nc->options;

	printf("%s(", nc->method);
	while (opts && *opts) {
	    if (flag) printf(", ");
	    printf("%s", *opts);
	    opts++;
	    flag = 1;
	}
	printf("), ");
    }
    printf("msg = '%s' with priority = %s\n",nc->message, nc->priority);

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}
 
int mysieve_error(int lineno, const char *msg, void *i __attribute__((unused)),
		  void *s __attribute__((unused)))
{
    fprintf(stderr, "line %d: %s\r\n", lineno, msg);

    return SIEVE_OK;
}

int mysieve_execute_error(const char *msg, void *i __attribute__((unused)),
			  void *s __attribute__((unused)),
			  void *m __attribute__((unused)))
{
    fprintf(stderr, "%s\r\n", msg);
 
    return SIEVE_OK;
}


int autorespond(void *ac, void *ic __attribute__((unused)),
		void *sc __attribute__((unused)),
		void *mc __attribute__((unused)),
		const char **errmsg __attribute__((unused)))
{
    sieve_autorespond_context_t *arc = (sieve_autorespond_context_t *) ac;
    char yn;
    int i;

    printf("Have I already responded to '");
    for (i = 0; i < SIEVE_HASHLEN; i++) {
	printf("%x", arc->hash[i]);
    }
    printf("' in %d days? ", arc->days);
    scanf(" %c", &yn);

    if (tolower(yn) == 'y') return SIEVE_DONE;
    if (tolower(yn) == 'n') return SIEVE_OK;

    return SIEVE_FAIL;
}

int send_response(void *ac, void *ic, void *sc __attribute__((unused)),
		  void *mc, const char **errmsg __attribute__((unused)))
{
    sieve_send_response_context_t *src = (sieve_send_response_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("echo '%s' | mail -s '%s' '%s' for message '%s' (from: %s)\n",
	   src->msg, src->subj, src->addr, m->name, src->fromaddr);

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

sieve_vacation_t vacation = {
    0,				/* min response */
    0,				/* max response */
    &autorespond,		/* autorespond() */
    &send_response		/* send_response() */
};

char *markflags[] = { "\\flagged" };
sieve_imapflags_t mark = { markflags, 1 };

struct testcase {
    int comp; 
    int mode;
    const char *pat;
    const char *text;
    int result;
};

struct testcase tc[] =
{ { B_OCTET, B_IS, "", "", 1 },
  { B_OCTET, B_IS, "a", "", 0 },
  { B_OCTET, B_IS, "", "a", 0 },
  { B_OCTET, B_IS, "a", "a", 1 },
  { B_OCTET, B_IS, "a", "A", 0 },

  { B_ASCIICASEMAP, B_IS, "", "", 1 },
  { B_ASCIICASEMAP, B_IS, "a", "", 0 },
  { B_ASCIICASEMAP, B_IS, "", "a", 0 },
  { B_ASCIICASEMAP, B_IS, "a", "a", 1 },
  { B_ASCIICASEMAP, B_IS, "a", "A", 1 },

  { B_ASCIINUMERIC, B_IS, "123", "123", 1 },
  { B_ASCIINUMERIC, B_IS, "123", "-123", 0 },
  { B_ASCIINUMERIC, B_IS, "abc", "123", 0 },
  { B_ASCIINUMERIC, B_IS, "abc", "abc", 1 },
  { B_ASCIINUMERIC, B_IS, "12345678900", "3755744308", 0 },    /* test for 32bit overflow */
  { B_ASCIINUMERIC, B_IS, "1567", "1567pounds", 1 },
  { B_ASCIINUMERIC, B_IS, "", "", 1 },
  { B_ASCIINUMERIC, B_IS, "123456789", "567", 0 },
  { B_ASCIINUMERIC, B_IS, "567", "123456789", 0 },
  { B_ASCIINUMERIC, B_IS, "123456789", "00000123456789", 1 },
  { B_ASCIINUMERIC, B_IS, "102", "1024", 0 },
  { B_ASCIINUMERIC, B_IS, "1567M", "1567 arg", 1 },

  { B_OCTET, B_CONTAINS, "", "", 1 },
  { B_OCTET, B_CONTAINS, "", "a", 1 },
  { B_OCTET, B_CONTAINS, "a", "", 0 },
  { B_OCTET, B_CONTAINS, "a", "a", 1 },
  { B_OCTET, B_CONTAINS, "a", "ab", 1 },
  { B_OCTET, B_CONTAINS, "a", "ba", 1 },
  { B_OCTET, B_CONTAINS, "a", "aba", 1 },
  { B_OCTET, B_CONTAINS, "a", "bab", 1 },
  { B_OCTET, B_CONTAINS, "a", "bb", 0 },
  { B_OCTET, B_CONTAINS, "a", "bbb", 0 },

  { B_OCTET, B_MATCHES, "", "", 1 },
  { B_OCTET, B_MATCHES, "", "a", 0 },
  { B_OCTET, B_MATCHES, "a", "", 0 },
  { B_OCTET, B_MATCHES, "a", "a", 1 },
  { B_OCTET, B_MATCHES, "a", "ab", 0 },
  { B_OCTET, B_MATCHES, "a", "ba", 0 },
  { B_OCTET, B_MATCHES, "a", "aba", 0 },
  { B_OCTET, B_MATCHES, "a", "bab", 0 },
  { B_OCTET, B_MATCHES, "a", "bb", 0 },
  { B_OCTET, B_MATCHES, "a", "bbb", 0 },

  { B_OCTET, B_MATCHES, "*", "", 1 },
  { B_OCTET, B_MATCHES, "*", "a", 1 },
  { B_OCTET, B_MATCHES, "*a*", "", 0 },
  { B_OCTET, B_MATCHES, "*a*", "a", 1 },
  { B_OCTET, B_MATCHES, "*a*", "ab", 1 },
  { B_OCTET, B_MATCHES, "*a*", "ba", 1 },
  { B_OCTET, B_MATCHES, "*a*", "aba", 1 },
  { B_OCTET, B_MATCHES, "*a*", "bab", 1 },
  { B_OCTET, B_MATCHES, "*a*", "bb", 0 },
  { B_OCTET, B_MATCHES, "*a*", "bbb", 0 },

  { B_OCTET, B_MATCHES, "*a", "", 0 },
  { B_OCTET, B_MATCHES, "*a", "a", 1 },
  { B_OCTET, B_MATCHES, "*a", "ab", 0 },
  { B_OCTET, B_MATCHES, "*a", "ba", 1 },
  { B_OCTET, B_MATCHES, "*a", "aba", 1 },
  { B_OCTET, B_MATCHES, "*a", "bab", 0 },
  { B_OCTET, B_MATCHES, "*a", "bb", 0 },
  { B_OCTET, B_MATCHES, "*a", "bbb", 0 },

  { B_OCTET, B_MATCHES, "a*", "", 0 },
  { B_OCTET, B_MATCHES, "a*", "a", 1 },
  { B_OCTET, B_MATCHES, "a*", "ab", 1 },
  { B_OCTET, B_MATCHES, "a*", "ba", 0 },
  { B_OCTET, B_MATCHES, "a*", "aba", 1 },
  { B_OCTET, B_MATCHES, "a*", "bab", 0 },
  { B_OCTET, B_MATCHES, "a*", "bb", 0 },
  { B_OCTET, B_MATCHES, "a*", "bbb", 0 },

  { B_OCTET, B_MATCHES, "a*b", "", 0 },
  { B_OCTET, B_MATCHES, "a*b", "a", 0 },
  { B_OCTET, B_MATCHES, "a*b", "ab", 1 },
  { B_OCTET, B_MATCHES, "a*b", "ba", 0 },
  { B_OCTET, B_MATCHES, "a*b", "aba", 0 },
  { B_OCTET, B_MATCHES, "a*b", "bab", 0 },
  { B_OCTET, B_MATCHES, "a*b", "bb", 0 },
  { B_OCTET, B_MATCHES, "a*b", "bbb", 0 },
  { B_OCTET, B_MATCHES, "a*b", "abbb", 1 },
  { B_OCTET, B_MATCHES, "a*b", "acb", 1 },
  { B_OCTET, B_MATCHES, "a*b", "acbc", 0 },

  { B_OCTET, B_MATCHES, "a?b", "", 0 },
  { B_OCTET, B_MATCHES, "a?b", "a", 0 },
  { B_OCTET, B_MATCHES, "a?b", "ab", 0 },
  { B_OCTET, B_MATCHES, "a?b", "ba", 0 },
  { B_OCTET, B_MATCHES, "a?b", "aba", 0 },
  { B_OCTET, B_MATCHES, "a?b", "bab", 0 },
  { B_OCTET, B_MATCHES, "a?b", "bb", 0 },
  { B_OCTET, B_MATCHES, "a?b", "bbb", 0 },
  { B_OCTET, B_MATCHES, "a?b", "abbb", 0 },
  { B_OCTET, B_MATCHES, "a?b", "acb", 1 },
  { B_OCTET, B_MATCHES, "a?b", "acbc", 0 },

  { B_OCTET, B_MATCHES, "a*?b", "", 0 },
  { B_OCTET, B_MATCHES, "a*?b", "a", 0 },
  { B_OCTET, B_MATCHES, "a*?b", "ab", 0 },
  { B_OCTET, B_MATCHES, "a*?b", "ba", 0 },
  { B_OCTET, B_MATCHES, "a*?b", "aba", 0 },
  { B_OCTET, B_MATCHES, "a*?b", "bab", 0 },
  { B_OCTET, B_MATCHES, "a*?b", "bb", 0 },
  { B_OCTET, B_MATCHES, "a*?b", "bbb", 0 },
  { B_OCTET, B_MATCHES, "a*?b", "abbb", 1 },
  { B_OCTET, B_MATCHES, "a*?b", "acb", 1 },
  { B_OCTET, B_MATCHES, "a*?b", "acbc", 0 },

  { B_OCTET, B_MATCHES, "a?*b", "", 0 },
  { B_OCTET, B_MATCHES, "a?*b", "a", 0 },
  { B_OCTET, B_MATCHES, "a?*b", "ab", 0 },
  { B_OCTET, B_MATCHES, "a?*b", "ba", 0 },
  { B_OCTET, B_MATCHES, "a?*b", "aba", 0 },
  { B_OCTET, B_MATCHES, "a?*b", "bab", 0 },
  { B_OCTET, B_MATCHES, "a?*b", "bb", 0 },
  { B_OCTET, B_MATCHES, "a?*b", "bbb", 0 },
  { B_OCTET, B_MATCHES, "a?*b", "abbb", 1 },
  { B_OCTET, B_MATCHES, "a?*b", "acb", 1 },
  { B_OCTET, B_MATCHES, "a?*b", "acbc", 0 },

  { B_OCTET, B_MATCHES, "a*?*b", "", 0 },
  { B_OCTET, B_MATCHES, "a*?*b", "a", 0 },
  { B_OCTET, B_MATCHES, "a*?*b", "ab", 0 },
  { B_OCTET, B_MATCHES, "a*?*b", "ba", 0 },
  { B_OCTET, B_MATCHES, "a*?*b", "aba", 0 },
  { B_OCTET, B_MATCHES, "a*?*b", "bab", 0 },
  { B_OCTET, B_MATCHES, "a*?*b", "bb", 0 },
  { B_OCTET, B_MATCHES, "a*?*b", "bbb", 0 },
  { B_OCTET, B_MATCHES, "a*?*b", "abbb", 1 },
  { B_OCTET, B_MATCHES, "a*?*b", "acb", 1 },
  { B_OCTET, B_MATCHES, "a*?*b?", "acbc", 1 },

  { B_ASCIICASEMAP, B_MATCHES, "a*b", "", 0 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "a", 0 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "ab", 1 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "ba", 0 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "aba", 0 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "bab", 0 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "bb", 0 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "bbb", 0 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "abbb", 1 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "acb", 1 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "acbc", 0 },

  { B_ASCIICASEMAP, B_MATCHES, "a*b", "", 0 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "A", 0 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "Ab", 1 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "BA", 0 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "ABA", 0 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "BAb", 0 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "BB", 0 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "BBB", 0 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "aBBB", 1 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "ACB", 1 },
  { B_ASCIICASEMAP, B_MATCHES, "a*b", "ACBC", 0 },

  { 0, 0, NULL, NULL, 0 } };

static int test_comparator(void)
{
    struct testcase *t;
    int didfail = 0;

    for (t = tc; t->comp != 0; t++) {
	void *comprock = NULL;
	comparator_t *c = lookup_comp(t->comp, t->mode, -1, &comprock);
	int res;
	char *comp, *mode;

	if (t->comp == B_OCTET) comp = "i;octet";
	else if (t->comp == B_ASCIICASEMAP) comp = "i;ascii-casemap";
	else if (t->comp == B_ASCIINUMERIC) comp = "i;ascii-numeric";
	else comp = "<unknown comp>";

	if (t->mode == B_IS) mode = "IS";
	else if (t->mode == B_CONTAINS) mode = "CONTAINS";
	else if (t->mode == B_MATCHES) mode = "MATCHES";
	else if (t->mode == B_REGEX) mode = "REGEX";
	else mode = "<unknown mode>";
	
	if (!c) {
	    printf("FAIL: can't find a comparator %s/%s\n", 
		   comp, mode);
	    didfail++;
	    continue;
	}
	res = c(t->text, strlen(t->text), t->pat, comprock);
	if (res != t->result) {
	    printf("FAIL: %s/%s(%s, %s) = %d, not %d\n", 
		   comp, mode, t->pat, t->text, res, t->result);
	    didfail++;
	}
    }
    if (didfail) {
	fprintf(stderr, "failed %d tests\n", didfail);
	exit(1);
    } else {
	exit(0);
    }
}

int config_need_data = 0;

int main(int argc, char *argv[])
{
    sieve_interp_t *i;
    sieve_execute_t *exe = NULL;
    message_data_t *m;
    char *script = NULL, *message = NULL;
    int c, force_fail = 0, usage_error = 0;
    /* (crom cvs update) FILE *f;
    */
    int fd, res;
    struct stat sbuf;

    while ((c = getopt(argc, argv, "v:cf")) != EOF)
	switch (c) {
	case 'v':
	    script = optarg;
	    break;
	case 'c':
	    test_comparator();
	    /* test_comparator exits for us */
	    break;
	case 'f':
	    force_fail = 1;
	    break;
	default:
	    usage_error = 1;
	    break;
	}

    if (!script) {
	if ((argc - optind) < 2)
	    usage_error = 1;
	else {
	    message = argv[optind];
	    script = argv[optind+1];
	}
    }

    if (usage_error) {
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "%s message script\n", argv[0]);
	fprintf(stderr, "%s -v script\n", argv[0]);
	exit(1);
    }

    res = sieve_interp_alloc(&i, &force_fail);
    if (res != SIEVE_OK) {
	printf("sieve_interp_alloc() returns %d\n", res);
	exit(1);
    }

    res = sieve_register_redirect(i, &redirect);
    if (res != SIEVE_OK) {
	printf("sieve_register_redirect() returns %d\n", res);
	exit(1);
    }
    res = sieve_register_discard(i, &discard);
    if (res != SIEVE_OK) {
	printf("sieve_register_discard() returns %d\n", res);
	exit(1);
    }
    res = sieve_register_reject(i, &reject);
    if (res != SIEVE_OK) {
	printf("sieve_register_reject() returns %d\n", res);
	exit(1);
    }
    res = sieve_register_fileinto(i, &fileinto);
    if (res != SIEVE_OK) {
	printf("sieve_register_fileinto() returns %d\n", res);
	exit(1);
    }
    res = sieve_register_keep(i, &keep);
    if (res != SIEVE_OK) {
	printf("sieve_register_keep() returns %d\n", res);
	exit(1);
    }

    res = sieve_register_size(i, &getsize);
    if (res != SIEVE_OK) {
	printf("sieve_register_size() returns %d\n", res);
	exit(1);
    }

    res = sieve_register_header(i, &getheader);
    if (res != SIEVE_OK) {
	printf("sieve_register_header() returns %d\n", res);
	exit(1);
    }

    res = sieve_register_envelope(i, &getenvelope);
    if (res != SIEVE_OK) {
	printf("sieve_register_envelope() returns %d\n", res);
	exit(1);
    }

    res = sieve_register_body(i, &getbody);
    if (res != SIEVE_OK) {
	printf("sieve_register_body() returns %d\n", res);
	exit(1);
    }

    res = sieve_register_include(i, &getinclude);
    if (res != SIEVE_OK) {
	printf("sieve_register_include() returns %d\n", res);
	exit(1);
    }

    res = sieve_register_vacation(i, &vacation);
    if (res != SIEVE_OK) {
	printf("sieve_register_vacation() returns %d\n", res);
	exit(1);
    }

    res = sieve_register_imapflags(i, &mark);

    if (res != SIEVE_OK) {
	printf("sieve_register_imapflags() returns %d\n", res);
	exit(1);
    }

    res = sieve_register_notify(i, &notify);
    if (res != SIEVE_OK) {
	printf("sieve_register_notify() returns %d\n", res);
	exit(1);
    }
 
    res = sieve_register_parse_error(i, &mysieve_error);
    if (res != SIEVE_OK) {
	printf("sieve_register_parse_error() returns %d\n", res);
	exit(1);
    }
    
    res = sieve_register_execute_error(i, &mysieve_execute_error);
    if (res != SIEVE_OK) {
	printf("sieve_register_execute_error() returns %d\n", res);
        exit(1);
    }   

    res = sieve_script_load(argv[2], &exe);
    if (res != SIEVE_OK) {
	printf("sieve_script_load() returns %d\n", res);
	exit(1);
    }

    if (message) {
	FILE *f;

	fd = open(message, O_RDONLY);
	res = fstat(fd, &sbuf);
	if (res != 0) {
	    perror("fstat");
	}

	f = fdopen(fd, "r");
	if (f) m = new_msg(f, sbuf.st_size, message);
	if (!f || !m) {
	    printf("can not open message '%s'\n", message);
	    exit(1);
	}

	res = sieve_execute_bytecode(exe, i, NULL, m);
	if (res != SIEVE_OK) {
	    printf("sieve_execute_bytecode() returns %d\n", res);
	    exit(1);
	}
	
	fclose(f);
	close(fd);
    }
    /*used to be sieve_script_free*/
    res = sieve_script_unload(&exe);
    if (res != SIEVE_OK) {
	printf("sieve_script_unload() returns %d\n", res);
	exit(1);
    }
    res = sieve_interp_free(&i);
    if (res != SIEVE_OK) {
	printf("sieve_interp_free() returns %d\n", res);
	exit(1);
    }

    return 0;
}

void fatal(char* message, int rc) {
    fprintf(stderr, "fatal error: %s\n", message);
    exit(rc);
}
