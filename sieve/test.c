/* test.c -- tester for libsieve
 * Larry Greenfield
 * $Id: test.c,v 1.14 2000/12/18 04:53:43 leg Exp $
 *
 * usage: "test message script"
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

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
    NAME_START,
    NAME,
    COLON,
    BODY_START,
    BODY
} state;

int parseheader(FILE *f, char **headname, char **contents) {
    char c;
    char name[80], body[1024];
    int off = 0;
    state s = NAME_START;


    /* there are two ways out of this loop, both via gotos:
       either we successfully read a character (got_header)
       or we hit an error (ph_error) */
    while (c = getc(f)) {	/* examine each character */
	switch (s) {
	case NAME_START:
	    if (c == '\r' || c == '\n') {
		/* no header here! */
		goto ph_error;
	    }
	    if (!isalpha(c))
		goto ph_error;
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
	    break;
	
	case COLON:
	    if (c == ':') {
		s = BODY_START;
	    } else if (c != ' ' && c != '\t') {
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

int getenvelope(void *v, const char *head, const char ***body)
{
    static const char *buf[2];

    if (buf[0] == NULL) { buf[0] = malloc(sizeof(char) * 256); buf[1] = NULL; }
    printf("Envelope body of '%s'? ", head);
    scanf("%s", buf[0]);
    *body = buf;

    return SIEVE_OK;
}

int redirect(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    sieve_redirect_context_t *rc = (sieve_redirect_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    printf("redirecting message '%s' to '%s'\n", m->name, rc->addr);
    return SIEVE_OK;
}

int discard(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    message_data_t *m = (message_data_t *) mc;
    printf("discarding message '%s'\n", m->name);
    return SIEVE_OK;
}

int reject(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    sieve_reject_context_t *rc = (sieve_reject_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    printf("rejecting message '%s' with '%s'\n", m->name, rc->msg);
    return SIEVE_OK;
}

int fileinto(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    sieve_fileinto_context_t *fc = (sieve_fileinto_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;

    printf("filing message '%s' into '%s'\n", m->name, fc->mailbox);

    if (fc->imapflags->flag) {
	int n;
	printf("\twith flags");
	for (n = 0; n < fc->imapflags->nflags; n++)
	    printf(" '%s'", fc->imapflags->flag[n]);
	printf("\n");
    }

    return SIEVE_OK;
}

int keep(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    sieve_keep_context_t *kc = (sieve_keep_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;

    printf("keeping message '%s'\n", m->name);

    if (kc->imapflags->flag) {
	int n;
	printf("\twith flags");
	for (n = 0; n < kc->imapflags->nflags; n++)
	    printf(" '%s'", kc->imapflags->flag[n]);
	printf("\n");
    }

    return SIEVE_OK;
}

int notify(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    sieve_notify_context_t *nc = (sieve_notify_context_t *) ac;

    printf("notify msg = '%s' with priority = %s\n",nc->message, nc->priority);

    return SIEVE_OK;
}
 
int mysieve_error(int lineno, const char *msg, void *i, void *s)
{
    fprintf(stderr, "line %d: %s\r\n", lineno, msg);

    return SIEVE_OK;
}

int mysieve_execute_error(const char *msg, void *i, void *s, void *m)
{
    fprintf(stderr, "%s\r\n", msg);
 
    return SIEVE_OK;
}


int autorespond(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    sieve_autorespond_context_t *arc = (sieve_autorespond_context_t *) ac;
    char yn;
    int i;

    printf("Have I already responded to '");
    for (i = 0; i < arc->len; i++) {
	printf("%x", arc->hash[i]);
    }
    printf("' in %d days? ", arc->days);
    scanf(" %c", &yn);

    if (tolower(yn) == 'y') return SIEVE_DONE;
    if (tolower(yn) == 'n') return SIEVE_OK;

    return SIEVE_FAIL;
}

int send_response(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    sieve_send_response_context_t *src = (sieve_send_response_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    printf("echo '%s' | mail -s '%s' '%s' for message '%s'\n",
	   src->msg, src->subj, src->addr, m->name);
    return SIEVE_OK;
}

sieve_vacation_t vacation = {
    0,				/* min response */
    0,				/* max response */
    &autorespond,		/* autorespond() */
    &send_response		/* send_response() */
};

char *markflags[] = { "\\flagged", "myflag" };
sieve_imapflags_t mark = { markflags, 2 };

int main(int argc, char *argv[])
{
    sieve_interp_t *i;
    sieve_script_t *s;
    message_data_t *m;
    FILE *f;
    int fd, res;
    struct stat sbuf;

    if (argc != 3) {
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "%s message script\n", argv[0]);
	fprintf(stderr, "%s -v script\n", argv[0]);
	exit(1);
    }

    res = sieve_interp_alloc(&i, NULL);
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


    f = fopen(argv[2], "r");
    if (!f) {
	printf("can not open script '%s'\n", argv[2]);
	exit(1);
    }

    res = sieve_script_parse(i, f, NULL, &s);
    if (res != SIEVE_OK) {
	exit(1);
    }

    fclose(f);

    if (strcmp(argv[1], "-v") != 0) {
	fd = open(argv[1], O_RDONLY);
	res = fstat(fd, &sbuf);
	if (res != 0) {
	    perror("fstat");
	}

	m = new_msg(fdopen(fd, "r"), sbuf.st_size, argv[1]);
	if (res != SIEVE_OK) {
	    printf("sieve_msg_parse() returns %d\n", res);
	    exit(1);
	}

	res = sieve_execute_script(s, m);
	if (res != SIEVE_OK) {
	    printf("sieve_execute_script() returns %d\n", res);
	    exit(1);
	}
	
	close(fd);
    }

    res = sieve_script_free(&s);
    if (res != SIEVE_OK) {
	printf("sieve_script_free() returns %d\n", res);
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
