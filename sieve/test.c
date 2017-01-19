/*NEW

 * test.c -- tester for libcyrus_sieve
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "assert.h"
#include "sieve_interface.h"
#include "bytecode.h"
#include "comparator.h"
#include "tree.h"
#include "sieve/sieve.h"
#include "imap/mailbox.h"
#include "imap/message.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "hash.h"
#include "times.h"

static char vacation_answer;

typedef struct {
    char *name;
    FILE *data;
    int size;
    struct message_content content;

    int cache_full;
    struct hash_table cache;
    strarray_t *env_from;
    strarray_t *env_to;
} message_data_t;

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

static int parseheader(FILE *f, char **headname, char **contents)
{
    int c;
    static struct buf name = BUF_INITIALIZER;
    static struct buf body = BUF_INITIALIZER;
    state s = HDR_NAME_START;

    buf_reset(&name);
    buf_reset(&body);

    /* there are two ways out of this loop, both via gotos:
       either we successfully read a character (got_header)
       or we hit an error (ph_error) */
    while ((c = getc(f))) {     /* examine each character */
        switch (s) {
        case HDR_NAME_START:
            if (c == '\r' || c == '\n') {
                /* no header here! */
                goto ph_error;
            }
            if (!isalpha(c))
                goto ph_error;
            buf_putc(&name, TOLOWER(c));
            s = HDR_NAME;
            break;

        case HDR_NAME:
            if (c == ' ' || c == '\t' || c == ':') {
                buf_cstring(&name);
                s = (c == ':' ? HDR_CONTENT_START : COLON);
                break;
            }
            if (iscntrl(c)) {
                goto ph_error;
            }
            buf_putc(&name, TOLOWER(c));
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
            buf_reset(&body);
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
                    buf_cstring(&body);
                    ungetc(c, f);
                    goto got_header;
                }
                /* http://www.faqs.org/rfcs/rfc2822.html
                 *
                 * > Unfolding is accomplished by simply removing any CRLF
                 * > that is immediately followed by WSP
                 *
                 * So keep the actual WSP character
                 */
            }
            /* just an ordinary character */
            buf_putc(&body, c);
            break;
        }
    }

    /* if we fall off the end of the loop, we hit some sort of error
       condition */

 ph_error:
    if (headname != NULL) *headname = NULL;
    if (contents != NULL) *contents = NULL;
    return -1;

 got_header:
    if (headname != NULL) *headname = xstrdup(name.s);
    if (contents != NULL) *contents = xstrdup(body.s);

    return 0;
}

static void fill_cache(message_data_t *m)
{
    rewind(m->data);

    /* let's fill that header cache */
    for (;;) {
        char *name, *body;
        strarray_t *contents;

        if (parseheader(m->data, &name, &body) < 0) {
            break;
        }
        /* put it in the hash table */
        contents = (strarray_t *)hash_lookup(name, &m->cache);
        if (!contents)
            contents = hash_insert(name, strarray_new(), &m->cache);
        strarray_appendm(contents, body);
        free(name);
    }

    m->cache_full = 1;
}

/* we use the temp field in message_data to avoid having to malloc memory
   to return, and we also can't expose our the receipients to the message */
static int getenvelope(void *mc, const char *field, const char ***contents)
{
    message_data_t *m = (message_data_t *)mc;

    if (!strcasecmp(field, "from")) {
        *contents = (const char **)m->env_from->data;
        return SIEVE_OK;
    } else if (!strcasecmp(field, "to")) {
        *contents = (const char **)m->env_to->data;
        return SIEVE_OK;
    } else {
        *contents = NULL;
        return SIEVE_FAIL;
    }
}

/* gets the header "head" from msg. */
static int getheader(void *v, const char *phead, const char ***body)
{
    message_data_t *m = (message_data_t *) v;
    strarray_t *contents;
    char *head;

    *body = NULL;

    if (!m->cache_full) {
        fill_cache(m);
    }

    /* copy header parameter so we can mangle it */
    head = xstrdup(phead);
    lcase(head);

    /* check the cache */
    contents = (strarray_t *)hash_lookup(head, &m->cache);
    if (contents)
        *body = (const char **) contents->data;

    free(head);

    if (*body) {
        return SIEVE_OK;
    } else {
        return SIEVE_FAIL;
    }
}

static message_data_t *new_msg(FILE *msg, int size, const char *name)
{
    message_data_t *m;

    m = xmalloc(sizeof(message_data_t));
    m->data = msg;
    m->size = size;
    m->name = xstrdup(name);
    m->content.base = NULL;
    m->content.len = 0;
    m->content.body = NULL;
    construct_hash_table(&m->cache, 1000, 0);
    m->cache_full = 0;

    return m;
}

static void free_msg(message_data_t *m)
{
    free_hash_table(&m->cache, (void(*)(void*))strarray_free);
    free(m->name);
    free(m);
}

static int getsize(void *mc, int *size)
{
    message_data_t *m = (message_data_t *) mc;

    *size = m->size;
    return SIEVE_OK;
}

static int getbody(void *mc, const char **content_types, sieve_bodypart_t ***parts)
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

static int getinclude(void *sc __attribute__((unused)),
                      const char *script,
                      int isglobal __attribute__((unused)),
                      char *fpath, size_t size)
{
    strlcpy(fpath, script, size);
    strlcat(fpath, ".bc", size);

    return SIEVE_OK;
}

static int redirect(void *ac, void *ic, void *sc __attribute__((unused)),
                    void *mc, const char **errmsg __attribute__((unused)))
{
    sieve_redirect_context_t *rc = (sieve_redirect_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("redirecting message '%s' to '%s'\n", m->name, rc->addr);

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

static int discard(void *ac __attribute__((unused)),
                   void *ic, void *sc __attribute__((unused)),
                   void *mc, const char **errmsg __attribute__((unused)))
{
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("discarding message '%s'\n", m->name);

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

static int reject(void *ac, void *ic, void *sc __attribute__((unused)),
                  void *mc, const char **errmsg __attribute__((unused)))
{
    sieve_reject_context_t *rc = (sieve_reject_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    if (rc->is_extended)
        printf("LMTP rejecting message '%s' with '%s'\n", m->name, rc->msg);
    else
        printf("rejecting message '%s' with '%s'\n", m->name, rc->msg);

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

static int fileinto(void *ac, void *ic, void *sc __attribute__((unused)),
                    void *mc, const char **errmsg __attribute__((unused)))
{
    sieve_fileinto_context_t *fc = (sieve_fileinto_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("filing message '%s' into '%s'\n", m->name, fc->mailbox);

    if (fc->imapflags->count) {
        char *s = strarray_join(fc->imapflags, "' '");
        if (s) {
            printf("\twith flags '%s'\n", s);
            free(s);
        }
    }

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

static int keep(void *ac, void *ic, void *sc __attribute__((unused)),
                void *mc, const char **errmsg __attribute__((unused)))
{
    sieve_keep_context_t *kc = (sieve_keep_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("keeping message '%s'\n", m->name);
    if (kc->imapflags->count) {
        char *s = strarray_join(kc->imapflags, "' '");
        if (s) {
            printf("\twith flags '%s'\n", s);
            free(s);
        }
    }

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

static int notify(void *ac, void *ic, void *sc __attribute__((unused)),
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

static int mysieve_error(int lineno, const char *msg,
                         void *i __attribute__((unused)),
                         void *s __attribute__((unused)))
{
    fprintf(stderr, "line %d: %s\r\n", lineno, msg);

    return SIEVE_OK;
}

static int mysieve_execute_error(const char *msg,
                                 void *i __attribute__((unused)),
                                 void *s __attribute__((unused)),
                                 void *m __attribute__((unused)))
{
    fprintf(stderr, "%s\r\n", msg);

    return SIEVE_OK;
}


static int autorespond(void *ac, void *ic __attribute__((unused)),
                       void *sc __attribute__((unused)),
                       void *mc __attribute__((unused)),
                       const char **errmsg __attribute__((unused)))
{
    sieve_autorespond_context_t *arc = (sieve_autorespond_context_t *) ac;
    char yn;
    int i;

    if (vacation_answer)
        yn = vacation_answer;
    else {
    printf("Have I already responded to '");
    for (i = 0; i < SIEVE_HASHLEN; i++) {
        printf("%x", arc->hash[i]);
    }
    if (arc->seconds % DAY2SEC)
        printf("' in %d seconds? ", arc->seconds);
    else
        printf("' in %d days? ", arc->seconds / DAY2SEC);
    scanf(" %c", &yn);
    }

    if (TOLOWER(yn) == 'y') return SIEVE_DONE;
    if (TOLOWER(yn) == 'n') return SIEVE_OK;

    return SIEVE_FAIL;
}

static int send_response(void *ac, void *ic, void *sc __attribute__((unused)),
                         void *mc, const char **errmsg __attribute__((unused)))
{
    sieve_send_response_context_t *src = (sieve_send_response_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("echo '%s' | mail -s '%s' '%s' for message '%s' (from: %s)\n",
           src->msg, src->subj, src->addr, m->name, src->fromaddr);

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

static sieve_vacation_t vacation = {
    0,                          /* min response */
    0,                          /* max response */
    &autorespond,               /* autorespond() */
    &send_response              /* send_response() */
};

static int usage(const char *argv0) __attribute__((noreturn));
static int usage(const char *argv0)
{
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "%s -v script\n", argv0);
    fprintf(stderr, "%s [opts] message script\n", argv0);
    fprintf(stderr, "\n");
    fprintf(stderr, "   -e envelope_from\n");
    fprintf(stderr, "   -t envelope_to\n");
    fprintf(stderr, "   -r y|n - have sent vacation response already? (if required)\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    sieve_interp_t *i;
    sieve_execute_t *exe = NULL;
    message_data_t *m = NULL;
    char *script = NULL, *message = NULL;
    int c, force_fail = 0;
    int fd, res;
    struct stat sbuf;
    static strarray_t mark = STRARRAY_INITIALIZER;
    static strarray_t e_from = STRARRAY_INITIALIZER;
    static strarray_t e_to = STRARRAY_INITIALIZER;
    /* prevent crashes if -e or -t aren't specified */
    strarray_append(&e_from, "");
    strarray_append(&e_to, "");

    while ((c = getopt(argc, argv, "v:fe:t:r:")) != EOF)
        switch (c) {
        case 'v':
            script = optarg;
            break;
        case 'f':
            force_fail = 1;
            break;
        case 'e':
            strarray_fini(&e_from);
            strarray_append(&e_from, optarg);
            break;
        case 't':
            strarray_fini(&e_to);
            strarray_append(&e_to, optarg);
            break;
        case 'r':
            vacation_answer = optarg[0];
            break;
        default:
            usage(argv[0]);
            break;
        }

    if (!script) {
        if ((argc - optind) < 2)
            usage(argv[0]);
        else {
            message = argv[optind];
            script = argv[optind+1];
        }
    }

    i = sieve_interp_alloc(&force_fail);
    assert(i != NULL);

    sieve_register_redirect(i, redirect);
    sieve_register_discard(i, discard);
    sieve_register_reject(i, reject);
    sieve_register_fileinto(i, fileinto);
    sieve_register_keep(i, keep);
    sieve_register_size(i, getsize);
    sieve_register_header(i, getheader);
    sieve_register_envelope(i, getenvelope);
    sieve_register_body(i, getbody);
    sieve_register_include(i, getinclude);

    res = sieve_register_vacation(i, &vacation);
    if (res != SIEVE_OK) {
        printf("sieve_register_vacation() returns %d\n", res);
        exit(1);
    }

    strarray_append(&mark, "\\flagged");
    sieve_register_imapflags(i, &mark);

    sieve_register_notify(i, notify);
    sieve_register_parse_error(i, mysieve_error);
    sieve_register_execute_error(i, mysieve_execute_error);

    res = sieve_script_load(script, &exe);
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

        m->env_from = &e_from;
        m->env_to = &e_to;

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

    if (m)
        free_msg(m);
    strarray_fini(&e_from);
    strarray_fini(&e_to);
    strarray_fini(&mark);

    return 0;
}

EXPORTED void fatal(const char* message, int rc)
{
    fprintf(stderr, "fatal error: %s\n", message);
    exit(rc);
}
