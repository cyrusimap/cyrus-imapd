/* spool.c -- Routines for spooling/parsing messages from a prot stream
 *
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

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>

#include "assert.h"
#include "spool.h"
#include "util.h"
#include "xmalloc.h"
#include "global.h"
#include "strarray.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

hdrcache_t spool_new_hdrcache(void)
{
    hash_table *ht = xmalloc(sizeof(*ht));
    return construct_hash_table(ht, 4000, 0);
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

/* we don't have to worry about dotstuffing here, since it's illegal
   for a header to begin with a dot!

   returns 0 on success, filling in 'headname' and 'contents' with a static
   pointer (blech).
   on end of headers, returns 0 with NULL 'headname' and NULL 'contents'

   on error, returns < 0
*/
static int parseheader(struct protstream *fin, FILE *fout,
                       char **headname, char **contents,
                       const char **skipheaders)
{
    int c;
    static struct buf name = BUF_INITIALIZER;
    static struct buf body = BUF_INITIALIZER;
    state s = NAME_START;
    int r = 0;
    int reject8bit = config_getswitch(IMAPOPT_REJECT8BIT);
    int munge8bit = config_getswitch(IMAPOPT_MUNGE8BIT);
    const char **skip = NULL;

    buf_reset(&name);
    buf_reset(&body);

    /* there are two ways out of this loop, both via gotos:
       either we successfully read a header (got_header)
       or we hit an error (ph_error) */
    while ((c = prot_getc(fin)) != EOF) { /* examine each character */
        /* reject \0 */
        if (!c) {
            r = IMAP_MESSAGE_CONTAINSNULL;
            goto ph_error;
        }

        switch (s) {
        case NAME_START:
            if (c == '.') {
                int peek;

                peek = prot_getc(fin);
                prot_ungetc(peek, fin);

                if (peek == '\r' || peek == '\n') {
                    /* just reached the end of message */
                    r = 0;
                    goto ph_error;
                }
            }
            if (c == '\r' || c == '\n') {
                /* just reached the end of headers */
                r = 0;
                goto ph_error;
            }
            /* field-name      =       1*ftext
               ftext           =       %d33-57 / %d59-126
                                       ; Any character except
                                       ;  controls, SP, and
                                       ;  ":". */
            if (!((c >= 33 && c <= 57) || (c >= 59 && c <= 126))) {
                /* invalid header name */
                r = IMAP_MESSAGE_BADHEADER;
                goto ph_error;
            }
            buf_putc(&name, c);
            s = NAME;
            break;

        case NAME:
            if (c == ' ' || c == '\t' || c == ':') {
                buf_cstring(&name);
                /* see if this header is in our skip list */
                for (skip = skipheaders;
                     skip && *skip && strcasecmp(name.s, *skip); skip++);
                if (!skip || !*skip) {
                    /* write the header name to the output */
                    if (fout) fputs(name.s, fout);
                    skip = NULL;
                }
                s = (c == ':' ? BODY_START : COLON);
                break;
            }
            if (!((c >= 33 && c <= 57) || (c >= 59 && c <= 126))) {
                r = IMAP_MESSAGE_BADHEADER;
                goto ph_error;
            }
            buf_putc(&name, c);
            break;

        case COLON:
            if (c == ':') {
                s = BODY_START;
            } else if (c != ' ' && c != '\t') {
                /* i want to avoid confusing dot-stuffing later */
                while (c == '.') {
                    if (fout && !skip) fputc(c, fout);
                    c = prot_getc(fin);
                }
                r = IMAP_MESSAGE_BADHEADER;
                goto ph_error;
            }
            break;

        case BODY_START:
            if (c == ' ' || c == '\t') /* eat the whitespace */
                break;
            buf_reset(&body);
            s = BODY;
            /* falls through! */
        case BODY:
            /* now we want to convert all newlines into \r\n */
            if (c == '\r' || c == '\n') {
                int peek;

                peek = prot_getc(fin);

                if (fout && !skip) {
                    fputc('\r', fout);
                    fputc('\n', fout);
                }
                /* we should peek ahead to see if it's folded whitespace */
                if (c == '\r' && peek == '\n') {
                    c = prot_getc(fin);
                } else {
                    c = peek; /* single newline seperator */
                }
                if (c != ' ' && c != '\t') {
                    /* this is the end of the header */
                    buf_cstring(&body);
                    prot_ungetc(c, fin);
                    goto got_header;
                }
            }
            if (c >= 0x80) {
                if (reject8bit) {
                    /* We have been configured to reject all mail of this
                       form. */
                    r = IMAP_MESSAGE_CONTAINS8BIT;
                    goto ph_error;
                } else if (munge8bit) {
                    /* We have been configured to munge all mail of this
                       form. */
                    c = 'X';
                }
            }
            /* just an ordinary character */
            buf_putc(&body, c);
        }

        /* copy this to the output */
        if (fout && s != NAME && !skip) fputc(c, fout);
    }

    /* if we fall off the end of the loop, we hit some sort of error
       condition */

 ph_error:
    /* put the last character back; we'll copy it later */
    if (c != EOF) prot_ungetc(c, fin);

    /* and we didn't get a header */
    if (headname != NULL) *headname = NULL;
    if (contents != NULL) *contents = NULL;
    return r;

 got_header:
    /* Note: xstrdup()ing the string ensures we return
     * a minimal length string with no allocation slack
     * at the end */
    if (headname != NULL) *headname = xstrdup(name.s);
    if (contents != NULL) *contents = xstrdup(body.s);

    return 0;
}

EXPORTED void spool_cache_header(char *name, char *body, hdrcache_t cache)
{
    strarray_t *contents;

    lcase(name);

    contents = (strarray_t *)hash_lookup(name, cache);
    if (!contents)
        contents = hash_insert(name, strarray_new(), cache);
    strarray_appendm(contents, body);
    free(name);
}

EXPORTED void spool_replace_header(char *name, char *body, hdrcache_t cache)
{
    strarray_t *contents;

    lcase(name);

    contents = (strarray_t *)hash_lookup(name, cache);
    if (!contents)
        contents = hash_insert(name, strarray_new(), cache);
    else
        strarray_truncate(contents, 0);
    strarray_appendm(contents, body);
    free(name);
}

EXPORTED void spool_remove_header(char *name, hdrcache_t cache)
{
    strarray_t *contents;

    lcase(name);

    contents = (strarray_t *)hash_del(name, cache);
    if (contents) strarray_free(contents);
    free(name);
}

EXPORTED int spool_fill_hdrcache(struct protstream *fin, FILE *fout, hdrcache_t cache,
                        const char **skipheaders)
{
    int r = 0;

    /* let's fill that header cache */
    for (;;) {
        char *name = NULL, *body = NULL;

        if ((r = parseheader(fin, fout, &name, &body, skipheaders)) < 0) {
            break;
        }
        if (!name) {
            /* reached the end of headers */
            free(body);
            break;
        }

        /* put it in the hash table */
        spool_cache_header(name, body, cache);
    }

    return r;
}

EXPORTED const char **spool_getheader(hdrcache_t cache, const char *phead)
{
    strarray_t *contents;

    assert(cache && phead);

    /* check the cache */
    contents = (strarray_t *) hash_lookup(phead, cache);

    return contents ? (const char **)contents->data : NULL;
}

EXPORTED void spool_free_hdrcache(hdrcache_t cache)
{
    if (!cache) return;

    free_hash_table(cache, (void (*)(void *))strarray_free);
    free(cache);
}

struct spool_enum_rock {
    void (*proc)(const char *, const char *, void *);
    void *rock;
};

static void spool_enum_cb(const char *key, void *data, void *rock)
{
    struct spool_enum_rock *c = (struct spool_enum_rock *)rock;
    strarray_t *d = (strarray_t *)data;
    int i;

    for (i = 0; i < d->count; i++) {
        const char *val = strarray_nth(d, i);
        c->proc(key, val, c->rock);
    }
}

EXPORTED void spool_enum_hdrcache(hdrcache_t cache,
                         void (*proc)(const char *, const char *, void *),
                         void *rock)
{
    struct spool_enum_rock cbrock;

    if (!cache) return;

    cbrock.proc = proc;
    cbrock.rock = rock;

    hash_enumerate(cache, spool_enum_cb, &cbrock);
}

/* copies the message from fin to fout, massaging accordingly:
   . newlines are fiddled to \r\n
   . "." terminates
   . embedded NULs are rejected
   . bare \r are removed
*/
EXPORTED int spool_copy_msg(struct protstream *fin, FILE *fout)
{
    char buf[8192], *p;
    int r = 0;

    /* -2: Might need room to add a \r\n\0 set */
    while (prot_fgets(buf, sizeof(buf)-2, fin)) {
        p = buf + strlen(buf) - 1;
        if (p < buf) {
            /* buffer start with a \0 */
            r = IMAP_MESSAGE_CONTAINSNULL;
            continue; /* need to eat the rest of the message */
        }
        else if (buf[0] == '\r' && buf[1] == '\0') {
            /* The message contained \r\0, and fgets is confusing us. */
            r = IMAP_MESSAGE_CONTAINSNULL;
            continue; /* need to eat the rest of the message */
        }
        else if (p[0] == '\r') {
            /*
             * We were unlucky enough to get a CR just before we ran
             * out of buffer--put it back.
             */
            prot_ungetc('\r', fin);
            *p = '\0';
        }
        else if (p[0] == '\n' && (p == buf || p[-1] != '\r')) {
            /* found an \n without a \r */
            p[0] = '\r';
            p[1] = '\n';
            p[2] = '\0';
        }
        else if (p[0] != '\n' && (strlen(buf) < sizeof(buf)-3)) {
            /* line contained a \0 not at the end */
            r = IMAP_MESSAGE_CONTAINSNULL;
            continue;
        }

        /* Remove any lone CR characters */
        while ((p = strchr(buf, '\r')) && p[1] != '\n') {
            /* Src/Target overlap, use memmove */
            /* strlen(p) will result in copying the NUL byte as well */
            memmove(p, p+1, strlen(p));
        }

        if (buf[0] == '.') {
            if (buf[1] == '\r' && buf[2] == '\n') {
                /* End of message */
                goto dot;
            }
            /* Remove the dot-stuffing */
            if (fout) fputs(buf+1, fout);
        } else {
            if (fout) fputs(buf, fout);
        }
    }

    /* wow, serious error---got a premature EOF. */
    return IMAP_IOERROR;

  dot:
    return r;
}
