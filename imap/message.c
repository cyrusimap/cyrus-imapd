/* message.c -- Message manipulation/parsing
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
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdlib.h>

#include "arrayu64.h"
#include "assert.h"
#include "crc32.h"
#include "dlist.h"
#include "prot.h"
#include "hash.h"
#include "map.h"
#include "mailbox.h"
#include "message.h"
#include "message_priv.h"
#include "message_guid.h"
#include "parseaddr.h"
#include "charset.h"
#include "stristr.h"
#include "user.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "strarray.h"
#include "ptrarray.h"
#include "global.h"
#include "retry.h"
#include "rfc822tok.h"
#include "times.h"
#include "xstrnchr.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
#include "imap/rfc822_header.h"

static int message_map_file(message_t *m, const char *fname);
static int message_parse_cbodystructure(message_t *m);

#define DEBUG 0

/* Message being parsed */
struct msg {
    const char *base;
    unsigned long len;
    unsigned long offset;
    int encode;
};

#define MAX_FIELDNAME_LENGTH   256

/* Default MIME Content-type */
#define DEFAULT_CONTENT_TYPE "TEXT/PLAIN; CHARSET=us-ascii"

static int message_parse_body(struct msg *msg,
                              struct body *body,
                              const char *defaultContentType,
                              strarray_t *boundaries,
                              const char *efname);
static int message_parse_headers(struct msg *msg,
                                 struct body *body,
                                 const char *defaultContentType,
                                 strarray_t *boundaries,
                                 const char *efname);

static void message_parse_address(const char *hdr, struct address **addrp);
static void message_parse_encoding(const char *hdr, char **hdrp);
static void message_parse_charset(const struct body *body,
                                  int *encoding, charset_t *charset);
static void message_parse_header(const char *hdr, struct buf *buf);
static void message_parse_bodytype(const char *hdr, struct body *body);
static void message_parse_bodydisposition(const char *hdr, struct body *body);
static void message_parse_params(const char *hdr, struct param **paramp);
static void message_fold_params(struct param **paramp);
static void message_parse_language(const char *hdr, struct param **paramp);
static void message_parse_rfc822space(const char **s);
static void message_parse_received_date(const char *hdr, char **hdrp);

static void message_parse_multipart(struct msg *msg,
                                    struct body *body,
                                    strarray_t *boundaries,
                                    const char *efname);
static void message_parse_content(struct msg *msg,
                                  struct body *body,
                                  strarray_t *boundaries,
                                  const char *efname);

static char *message_getline(struct buf *, struct msg *msg);
static int message_pendingboundary(const char *s, int slen, strarray_t *);

static void message_write_envelope(struct buf *buf, const struct body *body);
static void message_write_address(struct buf *buf,
                                  const struct address *addrlist);
static void message_write_text_lcase(struct buf *buf, const char *s);
static void message_write_section(struct buf *buf, const struct body *body);
static void message_write_charset(struct buf *buf, const struct body *body);
static void message_write_searchaddr(struct buf *buf,
                                     const struct address *addrlist);
static int message_need(const message_t *m, unsigned int need);
static void message_yield(message_t *m, unsigned int yield);

/*
 * Convert a string to uppercase.  Returns the string.
 *
 * This differs from the ucase() function in lib/util.c by using the
 * libc tolower() instead of our hardcoded builtin lookup table.
 * Whether this is a good thing is unclear, but that's what the old code
 * did so I'm going to preserve it - gnb
 */
static char *message_ucase(char *s)
{
    char *p;

    for (p = s ; *p ; p++)
        if (Uislower(*p))
            *p = toupper((int) *p);
    return s;
}

/*
 * Check a message 'from' of 'size' bytes for minimal RFC 822 compliance.
 * The message is read from 'from'. If 'to' is not NULL, the message
 * is copied to 'to', otherwise an in-memory buffer of 'from' is checked.
 *
 * Caller must have initialized config_* routines (with cyrus_init) to read
 * imapd.conf before calling.
 */
EXPORTED int message_copy_strict(struct protstream *from, FILE *to,
                                 unsigned size, int allow_null)
{
    char buf[4096+1];
    unsigned char *p, *endp;
    int r = 0;
    size_t n;
    int sawcr = 0, sawnl;
    int reject8bit = config_getswitch(IMAPOPT_REJECT8BIT);
    int munge8bit = config_getswitch(IMAPOPT_MUNGE8BIT);
    int inheader = 1, blankline = 1;
    struct buf tmp = BUF_INITIALIZER;

    while (size) {
        n = prot_read(from, buf, size > 4096 ? 4096 : size);
        if (!n) {
            xsyslog(LOG_ERR, "IOERROR: reading message: unexpected end of file",
                             NULL);
            return IMAP_IOERROR;
        }

        buf[n] = '\0';

        /* Quick check for NUL in entire buffer, if we're not allowing it */
        if (!allow_null && (n != strlen(buf))) {
            r = IMAP_MESSAGE_CONTAINSNULL;
        }

        size -= n;
        if (r) continue;

        for (p = (unsigned char *)buf, endp = p + n; p < endp; p++) {
            if (!*p && inheader) {
                /* NUL in header is always bad */
                r = IMAP_MESSAGE_CONTAINSNULL;
            }
            else if (*p == '\n') {
                if (!sawcr && (inheader || !allow_null))
                    r = IMAP_MESSAGE_CONTAINSNL;
                sawcr = 0;
                if (blankline) {
                    inheader = 0;
                }
                blankline = 1;
            }
            else if (*p == '\r') {
                sawcr = 1;
            }
            else {
                sawcr = 0;
                blankline = 0;
                if (inheader && *p >= 0x80) {
                    if (reject8bit) {
                        /* We have been configured to reject all mail of this
                           form. */
                        if (!r) r = IMAP_MESSAGE_CONTAINS8BIT;
                    } else if (munge8bit) {
                        /* We have been configured to munge all mail of this
                           form. */
                        *p = 'X';
                    }
                }
            }
        }

        if (to)
            fwrite(buf, 1, n, to);
        else
            buf_appendmap(&tmp, buf, n);
    }

    if (r) goto done;

    if (to) {
        fflush(to);
        if (ferror(to) || fsync(fileno(to))) {
            xsyslog(LOG_ERR, "IOERROR: writing message", NULL);
            r = IMAP_IOERROR;
            goto done;
        }
        rewind(to);
    }

    /* Go back and check headers */
    sawnl = 1;
    const char *cur = buf_base(&tmp);
    const char *top = buf_base(&tmp) + buf_len(&tmp);
    for (;;) {
        /* Read headers into buffer */
        if (to) {
            if (!fgets(buf, sizeof(buf), to)) {
                r = sawnl ? 0 : IMAP_MESSAGE_BADHEADER;
                goto done;
            }
        }
        else {
            if (cur >= top) {
                r = sawnl ? 0 : IMAP_MESSAGE_BADHEADER;
                goto done;
            }
            const char *q = strchr(cur, '\n');
            if (q == NULL) {
                q = cur + sizeof(buf);
                if (q > top) q = top;
            }
            else {
                q++;
            }
            if (q > cur + sizeof(buf) - 1) {
                q = cur + sizeof(buf) - 1;
            }
            memcpy(buf, cur, q - cur);
            buf[q-cur] = '\0';
            cur = q;
        }

        /* End of header section */
        if (sawnl && buf[0] == '\r') {
            r = 0;
            goto done;
        }

        /* Check for valid header name */
        if (sawnl && buf[0] != ' ' && buf[0] != '\t') {
            if (buf[0] == ':') {
                r = IMAP_MESSAGE_BADHEADER;
                goto done;
            }
            if (strstr(buf, "From ") != buf) {
                for (p = (unsigned char *)buf; *p && *p != ':'; p++) {
                    if (*p <= ' ') {
                        r = IMAP_MESSAGE_BADHEADER;
                        goto done;
                    }
                }
            }
        }

        /* Used to be some 8bit checks here but those were moved above so that
           we could do something other than refuse the message.
           Unfortunately, we still need to look for the end of the string. */
        for(p = (unsigned char*) buf; *p; p++);

        sawnl = (p > (unsigned char *)buf) && (p[-1] == '\n');
    }
done:
    buf_free(&tmp);
    return r;
}

EXPORTED int message_parse(const char *fname, struct index_record *record)
{
    struct body *body = NULL;
    FILE *f;
    int r;

    f = fopen(fname, "r");
    if (!f) return IMAP_IOERROR;

    r = message_parse_file(f, NULL, NULL, &body, fname);
    if (!r) r = message_create_record(record, body);

    fclose(f);

    if (body) {
        message_free_body(body);
        free(body);
    }

    return r;
}

/*
 * Parse the message 'infile'.
 *
 * The caller MUST free the allocated body struct.
 *
 * If msg_base/msg_len are non-NULL, the file will remain memory-mapped
 * and returned to the caller.  The caller MUST unmap the file.
 */
EXPORTED int message_parse_file(FILE *infile,
                                const char **msg_base, size_t *msg_len,
                                struct body **body,
                                const char *efname)
{
    int fd = fileno(infile);
    struct stat sbuf;
    const char *tmp_base;
    size_t tmp_len;
    int unmap = 0, r;

    if (!msg_base) {
        unmap = 1;
        msg_base = &tmp_base;
        msg_len = &tmp_len;
    }
    *msg_base = NULL;
    *msg_len = 0;

    if (fstat(fd, &sbuf) == -1) {
        if (efname)
            xsyslog(LOG_ERR, "IOERROR: fstat on new message in spool",
                             "filename=<%s>",
                             efname);
        else
            xsyslog(LOG_ERR, "IOERROR: fstat on new message in spool", NULL);
        fatal("can't fstat message file", EX_OSFILE);
    }
    map_refresh(fd, 1, msg_base, msg_len, sbuf.st_size,
                "new message", 0);

    if (!*msg_base || !*msg_len)
        return IMAP_IOERROR; /* zero length file? */

    if (!*body) *body = (struct body *) xzmalloc(sizeof(struct body));
    r = message_parse_mapped(*msg_base, *msg_len, *body, efname);

    if (unmap) map_free(msg_base, msg_len);

    return r;
}

/*
 * Parse the message 'infile'.
 *
 * The caller MUST free the allocated body struct.
 *
 * If msg_base/msg_len are non-NULL, the file will remain memory-mapped
 * and returned to the caller.  The caller MUST unmap the file.
 */
EXPORTED int message_parse_file_buf(FILE *infile,
                                    struct buf *buf,
                                    struct body **body,
                                    const char *efname)
{
    int fd = fileno(infile);
    struct stat sbuf;

    // unmap or clear space
    buf_free(buf);

    if (fstat(fd, &sbuf) == -1) {
        if (efname)
            xsyslog(LOG_ERR, "IOERROR: fstat on new message in spool",
                             "filename=<%s>",
                             efname);
        else
            xsyslog(LOG_ERR, "IOERROR: fstat on new message in spool", NULL);
        fatal("can't fstat message file", EX_OSFILE);
    }
    buf_refresh_mmap(buf, 1, fd, efname, sbuf.st_size, "new message");

    if (!*body) *body = (struct body *) xzmalloc(sizeof(struct body));
    return message_parse_mapped(buf_base(buf), buf_len(buf), *body, efname);
}


/*
 * Parse the message 'infile'.
 *
 * The caller MUST free the allocated body struct.
 *
 * This function differs from message_parse_file() in that we create a
 * writable buffer rather than memory-mapping the file, so that binary
 * data can be encoded into the buffer.  The file is rewritten upon
 * completion.
 *
 * XXX can we do this with mmap()?
 */
EXPORTED int message_parse_binary_file(FILE *infile, struct body **body,
                                       const char *efname)
{
    int fd = fileno(infile);
    struct stat sbuf;
    struct msg msg;
    size_t n;

    if (fstat(fd, &sbuf) == -1) {
        if (efname)
            xsyslog(LOG_ERR, "IOERROR: fstat on new message in spool",
                             "filename=<%s>",
                             efname);
        else
            xsyslog(LOG_ERR, "IOERROR: fstat on new message in spool", NULL);
        fatal("can't fstat message file", EX_OSFILE);
    }
    msg.len = sbuf.st_size;
    msg.base = xmalloc(msg.len);
    msg.offset = 0;
    msg.encode = 1;

    lseek(fd, 0L, SEEK_SET);

    n = retry_read(fd, (char*) msg.base, msg.len);
    if (n != msg.len) {
        if (efname)
            xsyslog(LOG_ERR, "IOERROR: reading binary file in spool",
                             "filename=<%s>",
                             efname);
        else
            xsyslog(LOG_ERR, "IOERROR: reading binary file in spool", NULL);
        return IMAP_IOERROR;
    }

    if (!*body) *body = (struct body *) xzmalloc(sizeof(struct body));
    message_parse_body(&msg, *body,
                       DEFAULT_CONTENT_TYPE, NULL, efname);

    (*body)->filesize = msg.len;

    message_guid_generate(&(*body)->guid, msg.base, msg.len);

    lseek(fd, 0L, SEEK_SET);
    n = retry_write(fd, msg.base, msg.len);

    free((char*) msg.base);

    if (n != msg.len || fsync(fd)) {
        if (efname)
            xsyslog(LOG_ERR, "IOERROR: rewriting binary file in spool",
                             "filename=<%s>",
                             efname);
        else
            xsyslog(LOG_ERR, "IOERROR: rewriting binary file in spool", NULL);
        return IMAP_IOERROR;
    }

    return 0;
}

/*
 * Parse the message at 'msg_base' of length 'msg_len'.
 */
EXPORTED int message_parse_mapped(const char *msg_base, unsigned long msg_len,
                                  struct body *body, const char *efname)
{
    struct msg msg;

    msg.base = msg_base;
    msg.len = msg_len;
    msg.offset = 0;
    msg.encode = 0;

    message_parse_body(&msg, body, DEFAULT_CONTENT_TYPE, NULL, efname);

    body->filesize = msg_len;

    message_guid_generate(&body->guid, msg_base, msg_len);

    if (body->filesize != body->header_size + body->content_size) {
        if (efname)
            /* XXX IOERROR but only LOG_NOTICE?? */
            xsyslog(LOG_NOTICE, "IOERROR: size mismatch on parse",
                                "guid=<%s> filename=<%s> "
                                "filesize=<%" PRIu32 "> bodysize=<%" PRIu32 ">",
                                message_guid_encode(&body->guid), efname,
                                body->filesize,
                                body->header_size + body->content_size);
        else
            xsyslog(LOG_NOTICE, "IOERROR: size mismatch on parse",
                                "guid=<%s> "
                                "filesize=<%" PRIu32 "> bodysize=<%" PRIu32 ">",
                                message_guid_encode(&body->guid), body->filesize,
                                body->header_size + body->content_size);
    }

    return 0;
}

/*
 * Prune the header section in buf to include only those headers
 * listed in headers or (if headers_not is non-empty) those headers
 * not in headers_not.
 */
HIDDEN void message_pruneheader(char *buf, const strarray_t *headers,
                         const strarray_t *headers_not)
{
    char *p, *colon, *nextheader;
    int goodheader;
    char *endlastgood = buf;
    char **l;
    int count = 0;
    int maxlines = config_getint(IMAPOPT_MAXHEADERLINES);

    p = buf;
    while (*p && *p != '\r') {
        colon = strchr(p, ':');
        if (colon && headers_not && headers_not->count) {
            goodheader = 1;
            for (l = headers_not->data ; *l ; l++) {
                if ((size_t) (colon - p) == strlen(*l) &&
                    !strncasecmp(p, *l, colon - p)) {
                    goodheader = 0;
                    break;
                }
            }
        } else {
            goodheader = 0;
        }
        if (colon && headers && headers->count) {
            for (l = headers->data ; *l ; l++) {
                if ((size_t) (colon - p) == strlen(*l) &&
                    !strncasecmp(p, *l, colon - p)) {
                    goodheader = 1;
                    break;
                }
            }
        }

        nextheader = p;
        do {
            nextheader = strchr(nextheader, '\n');
            if (nextheader) nextheader++;
            else nextheader = p + strlen(p);
        } while (*nextheader == ' ' || *nextheader == '\t');

        if (goodheader) {
            if (endlastgood != p) {
                /* memmove and not strcpy since this is all within a
                 * single buffer */
                memmove(endlastgood, p, strlen(p) + 1);
                nextheader -= p - endlastgood;
            }
            endlastgood = nextheader;
        }
        p = nextheader;

        /* stop giant headers causing massive loops */
        if (maxlines) {
            count++;
            if (count > maxlines) break;
        }
    }

    *endlastgood = '\0';
}

static void message_find_part(struct body *body, const char *section,
                              const char **content_types,
                              const char *msg_base, unsigned long msg_len,
                              struct bodypart ***parts, int *n)
{
    int match;
    const char **type;
    char nextsection[128];

    for (match = 0, type = content_types; !match && *type; type++) {
        const char *subtype = strchr(*type, '/');
        size_t tlen = subtype ? (size_t) (subtype++ - *type) : strlen(*type);

        if ((!(*type)[0] || (tlen == strlen(body->type) &&
                             !strncasecmp(body->type, *type, tlen))) &&
            (!subtype || !subtype[0] || !strcasecmp(body->subtype, subtype))) {
            match = 1;
        }
    }

    if (match) {
        /* matching part, sanity check the size against the mmap'd file */
        if (body->content_offset + body->content_size > msg_len) {
            xsyslog(LOG_ERR, "IOERROR: body part exceeds size of message file",
                             NULL);
            fatal("body part exceeds size of message file", EX_OSFILE);
        }

        if (!body->decoded_body) {
            int encoding;
            charset_t charset = CHARSET_UNKNOWN_CHARSET;
            message_parse_charset(body, &encoding, &charset);
            if (charset == CHARSET_UNKNOWN_CHARSET)
                /* try ASCII */
                charset = charset_lookupname("us-ascii");
            body->decoded_body = charset_to_utf8(
                msg_base + body->content_offset, body->content_size,
                charset, encoding); /* returns a cstring */
            charset_free(&charset);
        }

        /* grow the array and add the new part */
        *parts = xrealloc(*parts, (*n+2)*sizeof(struct bodypart *));
        (*parts)[*n] = xzmalloc(sizeof(struct bodypart));
        strlcpy((*parts)[*n]->section, section, sizeof((*parts)[*n]->section));
        (*parts)[*n]->decoded_body = body->decoded_body;
        (*parts)[++(*n)] = NULL;
    }
    else if (!strcmp(body->type, "MULTIPART")) {
        int i;

        for (i = 0; i < body->numparts; i++) {
            snprintf(nextsection, sizeof(nextsection), "%s.%d", section, i+1);
            message_find_part(&body->subpart[i], nextsection, content_types,
                              msg_base, msg_len, parts, n);
        }
    }
    else if (!strcmp(body->type, "MESSAGE") &&
             !strcmp(body->subtype, "RFC822")) {
        snprintf(nextsection, sizeof(nextsection), "%s.1", section);
        message_find_part(body->subpart, nextsection, content_types,
                          msg_base, msg_len, parts, n);
    }
}

/*
 * Fetch the bodypart(s) which match the given content_type and return
 * them as an allocated array.
 *
 * The caller MUST free the array of allocated bodypart(s).
 */
EXPORTED void message_fetch_part(struct message_content *msg,
                                 const char **content_types,
                                 struct bodypart ***parts)
{
    int n = 0;  /* running count of the number of matching parts */

    *parts = NULL;
    message_find_part(msg->body, "1", content_types,
                      buf_base(&msg->map), buf_len(&msg->map), parts, &n);
}

/*
 * Appends the message's cache information to the cache file
 * and fills in appropriate information in the index record pointed to
 * by 'record'.
 */
HIDDEN int message_create_record(struct index_record *record,
                          const struct body *body)
{
    /* used for sent time searching, truncated to day with no TZ */
    if (time_from_rfc5322(body->date, &record->sentdate, DATETIME_DATE_ONLY) < 0)
        record->sentdate = 0;

    /* used for sent time sorting, full gmtime of Date: header */
    if (time_from_rfc5322(body->date, &record->gmtime, DATETIME_FULL) < 0)
        record->gmtime = 0;

    record->size = body->filesize;
    record->header_size = body->header_size;
    message_guid_copy(&record->guid, &body->guid);

    message_write_cache(record, body);

    return 0;
}

static enum rfc822_header
message_header_lookup(const char *buf, const char **valp)
{
    unsigned int len = strcspn(buf, ":\r\n");
    if (buf[len] != ':')
        return RFC822_BAD;
    if (valp)
        *valp = buf+len+1;
    return rfc822_header_from_string_len(buf, len);
}


static void body_add_content_guid(const char *base, struct body *body)
{
    int encoding = ENCODING_NONE;
    char *decbuf = NULL;
    charset_t cs = NULL;
    size_t len = body->content_size;
    message_parse_charset(body, &encoding, &cs);
    base = charset_decode_mimebody(base, len, encoding, &decbuf, &len);
    if (base) {
        message_guid_generate(&body->content_guid, base, len);
        body->decoded_content_size = len;
    }
    else {
        message_guid_set_null(&body->content_guid);
        body->decoded_content_size = 0;
    }
    charset_free(&cs);
    free(decbuf);
}


/*
 * Parse a body-part
 */
static int message_parse_body(struct msg *msg, struct body *body,
                              const char *defaultContentType,
                              strarray_t *boundaries,
                              const char *efname)
{
    strarray_t newboundaries = STRARRAY_INITIALIZER;
    int sawboundary;

    memset(body, 0, sizeof(struct body));

    /* No passed-in boundary structure, create a new, empty one */
    if (!boundaries) {
        boundaries = &newboundaries;
        /* We're at top-level--preallocate space to store cached headers */
        buf_ensure(&body->cacheheaders, 1024);
    }


    sawboundary = message_parse_headers(msg, body, defaultContentType,
                                        boundaries, efname);

    /* Charset id and encoding id are stored in the binary
     * bodystructure, but we don't have that one here. */
    struct param *param = body->params;
    while (param) {
        if (!strcasecmp(param->attribute, "CHARSET")) {
            body->charset_id = xstrdupnull(param->value);
            break;
        }
        param = param->next;
    }

    body->charset_enc = encoding_lookupname(body->encoding);

    /* Recurse according to type */
    if (strcmp(body->type, "MULTIPART") == 0) {
        if (!sawboundary) {
            message_parse_multipart(msg, body, boundaries, efname);
        }
    }
    else if (strcmp(body->type, "MESSAGE") == 0 &&
        strcmp(body->subtype, "RFC822") == 0) {
        const char *base = msg->base + msg->offset;
        body->subpart = (struct body *)xzmalloc(sizeof(struct body));

        if (sawboundary) {
            memset(body->subpart, 0, sizeof(struct body));
            message_parse_bodytype(DEFAULT_CONTENT_TYPE, body->subpart);
        }
        else {
            message_parse_body(msg, body->subpart,
                               DEFAULT_CONTENT_TYPE, boundaries, efname);

            /* Calculate our size/lines information */
            body->content_size = body->subpart->header_size +
              body->subpart->content_size;
            body->content_lines = body->subpart->header_lines +
              body->subpart->content_lines;

            /* Move any enclosing boundary information up to our level */
            body->boundary_size = body->subpart->boundary_size;
            body->boundary_lines = body->subpart->boundary_lines;

            /* it's nice to have a GUID for the message/rfc822 itself */
            body_add_content_guid(base, body);
        }
    }
    else {
        if (!sawboundary) {
            message_parse_content(msg, body, boundaries, efname);
        }
    }

    /* Free up boundary storage if necessary */
    strarray_fini(&newboundaries);

    return 0;
}

/*
 * Parse the headers of a body-part
 */
static int message_parse_headers(struct msg *msg, struct body *body,
                                 const char *defaultContentType,
                                 strarray_t *boundaries,
                                 const char *efname)
{
    struct buf headers = BUF_INITIALIZER;
    char *next;
    int len;
    int sawboundary = 0;
    uint32_t maxlines = config_getint(IMAPOPT_MAXHEADERLINES);
    int have_max = 0;
    const char *value;

    body->header_offset = msg->offset;

    buf_putc(&headers, '\n');   /* Leading newline to prime the pump */

    /* Slurp up all of the headers into 'headers' */
    while ((next = message_getline(&headers, msg)) &&
           (next[-1] != '\n' ||
            (*next != '\r' || next[1] != '\n'))) {

        len = strlen(next);

        if (next[-1] == '\n' && *next == '-' &&
            message_pendingboundary(next, len, boundaries)) {
            body->boundary_size = len;
            body->boundary_lines++;
            if (next - 1 > headers.s) {
                body->boundary_size += 2;
                body->boundary_lines++;
                next[-2] = '\0';
            }
            else {
                *next = '\0';
            }
            sawboundary = 1;
            break;
        }
    }

    body->content_offset = msg->offset;
    body->header_size = strlen(headers.s+1);

    /* Scan over the slurped-up headers for interesting header information */
    body->header_lines = -1;    /* Correct for leading newline */
    for (next = headers.s; *next; next++) {
        if (*next == '\n') {
            body->header_lines++;

            /* if we're skipping, skip now */
            if (have_max) continue;

            /* check if we've hit a limit and flag it */
            if (maxlines && body->header_lines > maxlines) {
                if (efname)
                    syslog(LOG_ERR, "ERROR: message (%s) has more than %d header lines "
                                    "not caching any more",
                           efname, maxlines);
                else
                    syslog(LOG_ERR, "ERROR: message has more than %d header lines "
                                    "not caching any more",
                           maxlines);
                have_max = 1;
                continue;
            }

            if (/* space preallocated, i.e. must be top-level body */
                body->cacheheaders.s &&
                /* this is not a continuation line */
                (next[1] != ' ') && (next[1] != '\t') &&
                /* this header is supposed to be cached */
                mailbox_cached_header_inline(next+1) != BIT32_MAX) {
                    /* append to the headers cache */
                    message_parse_header(next+1, &body->cacheheaders);
            }

            switch (message_header_lookup(next+1, &value)) {
            case RFC822_BCC:
                message_parse_address(value, &body->bcc);
                break;
            case RFC822_CC:
                message_parse_address(value, &body->cc);
                break;
            case RFC822_CONTENT_DESCRIPTION:
                message_parse_string(value, &body->description);
                break;
            case RFC822_CONTENT_DISPOSITION:
                message_parse_bodydisposition(value, body);
                break;
            case RFC822_CONTENT_ID:
                message_parse_string(value, &body->id);
                break;
            case RFC822_CONTENT_LANGUAGE:
                message_parse_language(value, &body->language);
                break;
            case RFC822_CONTENT_LOCATION:
                message_parse_string(value, &body->location);
                break;
            case RFC822_CONTENT_MD5:
                message_parse_string(value, &body->md5);
                break;
            case RFC822_CONTENT_TRANSFER_ENCODING:
                message_parse_encoding(value, &body->encoding);

                /* If we're encoding binary, replace "binary"
                   with "base64" in CTE header body */
                if (msg->encode &&
                    !strcmpsafe(body->encoding, "BINARY")) {
                    char *p = (char*)
                        stristr(msg->base + body->header_offset +
                                (next - headers.s) + 27,
                                "binary");
                    memcpy(p, "base64", 6);
                }
                break;
            case RFC822_CONTENT_TYPE:
                message_parse_bodytype(value, body);
                break;
            case RFC822_DATE:
                message_parse_string(value, &body->date);
                break;
            case RFC822_FROM:
                message_parse_address(value, &body->from);
                break;
            case RFC822_IN_REPLY_TO:
                message_parse_string(value, &body->in_reply_to);
                break;
            case RFC822_MESSAGE_ID:
                message_parse_string(value, &body->message_id);
                break;
            case RFC822_REPLY_TO:
                message_parse_address(value, &body->reply_to);
                break;
            case RFC822_RECEIVED:
                message_parse_received_date(value, &body->received_date);
                break;
            case RFC822_REFERENCES:
                message_parse_string(value, &body->references);
                break;
            case RFC822_SUBJECT:
                message_parse_string(value, &body->subject);
                break;
            case RFC822_SENDER:
                message_parse_address(value, &body->sender);
                break;
            case RFC822_TO:
                message_parse_address(value, &body->to);
                break;
            case RFC822_X_DELIVEREDINTERNALDATE:
                /* Explicit x-deliveredinternaldate overrides received: headers */
                message_parse_string(value, &body->x_deliveredinternaldate);
                break;
            case RFC822_X_ME_MESSAGE_ID:
                message_parse_string(value, &body->x_me_message_id);
                break;
            default:
                break;
            } /* switch() */
        } /* if (*next == '\n') */
    }

    /* If didn't find Content-Type: header, use the passed-in default type */
    if (!body->type) {
        message_parse_bodytype(defaultContentType, body);
    }
    buf_free(&headers);
    return sawboundary;
}

/*
 * Parse a list of RFC 822 addresses from a header
 */
static void message_parse_address(const char *hdr, struct address **addrp)
{
    char *hdrend, hdrendchar = '\0';

    /* If we saw this header already, discard the earlier value */
    if (*addrp) {
        parseaddr_free(*addrp);
        *addrp = NULL;
    }

    /* Find end of header */
    hdrend = (char *)hdr;
    do {
        hdrend = strchr(hdrend+1, '\n');
    } while (hdrend && (hdrend[1] == ' ' || hdrend[1] == '\t'));

    /* Put a NUL character at the end of header */
    /* gnb:TODO this is evil and should be stopped */
    if (hdrend) {
        if (hdrend > hdr && hdrend[-1] == '\r') hdrend--;
        hdrendchar = *hdrend;
        *hdrend = '\0';
    }

    parseaddr_list(hdr, addrp);

    /* Put character at end of header back */
    if (hdrend) *hdrend = hdrendchar;
}

/*
 * Parse a Content-Transfer-Encoding from a header.
 */
static void message_parse_encoding(const char *hdr, char **hdrp)
{
    int len;
    const char *p;

    /* If we saw this header already, discard the earlier value */
    if (*hdrp) {
        free(*hdrp);
        *hdrp = NULL;
    }

    /* Skip leading whitespace, ignore header if blank */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    /* Find end of encoding token */
    for (p = hdr; *p && !Uisspace(*p) && *p != '('; p++) {
        if (*p < ' ' || strchr(MIME_TSPECIALS, *p)) return;
    }
    len = p - hdr;

    /* Skip trailing whitespace, ignore header if trailing garbage */
    message_parse_rfc822space(&p);
    if (p) return;

    /* Save encoding token */
    *hdrp = message_ucase(xstrndup(hdr, len));
}

/*
 * parse a charset and encoding out of a body structure
 */
static void message_parse_charset(const struct body *body,
                                  int *e_ptr, charset_t *c_ptr)
{

    int encoding = ENCODING_NONE;
    charset_t charset = charset_lookupname("us-ascii");
    struct param *param;


    if (body->encoding) {
        switch (body->encoding[0]) {
        case '7':
        case '8':
            if (!strcmp(body->encoding+1, "BIT"))
                encoding = ENCODING_NONE;
            else
                encoding = ENCODING_UNKNOWN;
            break;

        case 'B':
            if (!strcmp(body->encoding, "BASE64"))
                encoding = ENCODING_BASE64;
            else if (!strcmp(body->encoding, "BINARY"))
                encoding = ENCODING_NONE;
            else
                encoding = ENCODING_UNKNOWN;
            break;

        case 'Q':
            if (!strcmp(body->encoding, "QUOTED-PRINTABLE"))
                encoding = ENCODING_QP;
            else
                encoding = ENCODING_UNKNOWN;
            break;

        default:
            encoding = ENCODING_UNKNOWN;
        }
    }

    if (!body->type || !strcmp(body->type, "TEXT")) {
        for (param = body->params; param; param = param->next) {
            if (!strcasecmp(param->attribute, "charset")) {
                if (param->value && *param->value) {
                    charset_free(&charset);
                    charset = charset_lookupname(param->value);
                    if (charset == CHARSET_UNKNOWN_CHARSET)
                        syslog(LOG_NOTICE, "message_parse_charset: unknown charset %s for text/%s", param->value, body->subtype);
                }
                break;
            }
        }
    }
    else if (!strcmp(body->type, "MESSAGE")) {
        if (!strcmp(body->subtype, "RFC822")) {
            charset_free(&charset);
            charset = CHARSET_UNKNOWN_CHARSET;
        }
        encoding = ENCODING_NONE;
    }
    else {
        charset_free(&charset);
        charset = CHARSET_UNKNOWN_CHARSET;
    }

    if (e_ptr) *e_ptr = encoding;
    if (c_ptr) *c_ptr = charset;
    else charset_free(&charset);
}

/*
 * Parse an uninterpreted header
 */
EXPORTED void message_parse_string(const char *hdr, char **hdrp)
{
    const char *hdrend;
    char *he;

    /* If we saw this header already, discard the earlier value */
    if (*hdrp) {
        free(*hdrp);
        *hdrp = NULL;
    }

    /* Skip initial whitespace */
    while (*hdr == ' ' || *hdr == '\t') hdr++;

    /* Find end of header */
    hdrend = hdr;
    do {
        hdrend = strchr(hdrend+1, '\n');
    } while (hdrend && (hdrend[1] == ' ' || hdrend[1] == '\t'));
    if (hdrend) {
        if (hdrend > hdr && hdrend[-1] == '\r') hdrend--;
    }
    else {
        hdrend = hdr + strlen(hdr);
    }

    /* Save header value */
    *hdrp = xstrndup(hdr, (hdrend - hdr));

    /* Un-fold header (overlapping buffers, use memmove) */
    he = *hdrp;
    while ((he = strchr(he, '\n'))!=NULL) {
        if (he > *hdrp && he[-1] == '\r') {
            he--;
            memmove(he, he+2, strlen(he+2)+1);
        }
        else {
            memmove(he, he+1, strlen(he+1)+1);
        }
    }
}

/*
 * Cache a header
 */
static void
message_parse_header(const char *hdr, struct buf *buf)
{
    int len;
    const char *hdrend;

    /* Find end of header */
    hdrend = hdr;
    do {
        hdrend = strchr(hdrend+1, '\n');
    } while (hdrend && (hdrend[1] == ' ' || hdrend[1] == '\t'));
    if (hdrend) {
        if (hdrend > hdr && hdrend[-1] == '\r') hdrend--;
    }
    else {
        hdrend = hdr + strlen(hdr);
    }

    /* Save header value */
    len = hdrend - hdr;
    buf_appendmap(buf, hdr, len);
    buf_putc(buf, '\r');
    buf_putc(buf, '\n');
}

/*
 * Parse a Content-Type from a header.
 */
EXPORTED void message_parse_type(const char *hdr, char **typep, char **subtypep, struct param **paramp)
{
    const char *type;
    int typelen;
    const char *subtype;
    int subtypelen;
    char *decbuf = NULL;

    /* Skip leading whitespace, ignore header if blank */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    /* Very old versions of macOS Mail.app encode the Content-Type header
     * in MIME words, if the attachment name contains non-ASCII characters */
    if (strlen(hdr) > 2 && hdr[0] == '=' && hdr[1] == '?') {
        int flags = CHARSET_KEEPCASE;
        decbuf = charset_decode_mimeheader(hdr, flags);
        if (strcmpsafe(decbuf, hdr)) hdr = decbuf;
    }

    /* Find end of type token */
    type = hdr;
    for (; *hdr && !Uisspace(*hdr) && *hdr != '/' && *hdr != '('; hdr++) {
        if (*hdr < ' ' || strchr(MIME_TSPECIALS, *hdr)) goto done;
    }
    typelen = hdr - type;

    /* Skip whitespace after type */
    message_parse_rfc822space(&hdr);
    if (!hdr) goto done;

    /* Ignore header if no '/' character */
    if (*hdr++ != '/') goto done;

    /* Skip whitespace before subtype, ignore header if no subtype */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    /* Find end of subtype token */
    subtype = hdr;
    for (; *hdr && !Uisspace(*hdr) && *hdr != ';' && *hdr != '('; hdr++) {
        if (*hdr < ' ' || strchr(MIME_TSPECIALS, *hdr)) goto done;
    }
    subtypelen = hdr - subtype;

    /* Skip whitespace after subtype */
    message_parse_rfc822space(&hdr);

    /* Ignore header if not at end of header or parameter delimiter */
    if (hdr && *hdr != ';') goto done;

    /* Save content type & subtype */
    *typep = message_ucase(xstrndup(type, typelen));
    *subtypep = message_ucase(xstrndup(subtype, subtypelen));

    /* Parse parameter list */
    if (hdr) {
        message_parse_params(hdr+1, paramp);
        message_fold_params(paramp);
        if (decbuf && paramp && *paramp) {
            /* The type header was erroneously encoded as a RFC 2407 encoded word
             * (rather than encoding its attributes), and the parameter values
             * might now contain non-ASCII characters. Let's reencode them. */
            struct param *param = *paramp;
            for (; param; param = param->next) {
                const char *attr = param->attribute;
                /* Skip extended parameters */
                size_t attrlen = strlen(attr);
                if (!attrlen || attr[attrlen-1] == '*') continue;
                /* Check if the parameter value has non-ASCII characters */
                int has_highbit = 0;
                const char *val = param->value;
                for (val = param->value; *val && !has_highbit; val++) {
                    has_highbit = *val & 0x80;
                }
                if (!has_highbit) continue;
                /* Reencode the parameter value */
                char *encvalue = charset_encode_mimeheader(param->value, strlen(param->value), 0);
                if (encvalue) {
                    free(param->value);
                    param->value = encvalue;
                }
            }
        }
    }

done:
    free(decbuf);
}

static void message_parse_bodytype(const char *hdr, struct body *body)
{
    /* If we saw this header already, discard the earlier value */
    if (body->type) {
        free(body->type);
        free(body->subtype);
        body->type = body->subtype = NULL;
        param_free(&body->params);
    }

    message_parse_type(hdr, &body->type, &body->subtype, &body->params);
}

/*
 * Parse a Content-Disposition from a header.
 */
EXPORTED void message_parse_disposition(const char *hdr, char **hdrp, struct param **paramp)
{
    const char *disposition;
    int dispositionlen;

    /* Skip leading whitespace, ignore header if blank */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    /* Find end of disposition token */
    disposition = hdr;
    for (; *hdr && !Uisspace(*hdr) && *hdr != ';' && *hdr != '('; hdr++) {
        if (*hdr < ' ' || strchr(MIME_TSPECIALS, *hdr)) return;
    }
    dispositionlen = hdr - disposition;

    /* Skip whitespace after type */
    message_parse_rfc822space(&hdr);

    /* Ignore header if not at end of header or parameter delimiter */
    if (hdr && *hdr != ';') return;

    /* Save content disposition */
    *hdrp = message_ucase(xstrndup(disposition, dispositionlen));

    /* Parse parameter list */
    if (hdr) {
        message_parse_params(hdr+1, paramp);
        message_fold_params(paramp);
    }
}

/*
 * Parse a Content-Disposition from a header.
 */
static void message_parse_bodydisposition(const char *hdr, struct body *body)
{
    /* If we saw this header already, discard the earlier value */
    if (body->disposition) {
        free(body->disposition);
        body->disposition = NULL;
        param_free(&body->disposition_params);
    }

    message_parse_disposition(hdr, &body->disposition, &body->disposition_params);
}

/*
 * Parse a parameter list from a header.
 *
 * 'hdr' points into the message, and is not expected to
 * be nul-terminated.  Handles continuation headers.
 *
 * Malformed parameters are handled by skipping to the
 * next ';' or end of line, which should mark the next
 * parameter.
 */
static void message_parse_params(const char *hdr, struct param **paramp)
{
    struct param *param;
    const char *attribute;
    int attributelen;
    const char *value;
    int valuelen;
    char *p;

    for (;;) {
        /* Skip over leading whitespace */
        message_parse_rfc822space(&hdr);
        if (!hdr) return;

        /* Find end of attribute */
        attribute = hdr;
        for (; *hdr && !Uisspace(*hdr) && *hdr != '=' && *hdr != '('; hdr++) {
            if (*hdr < ' ' || strchr(MIME_TSPECIALS, *hdr)) goto skip;
        }
        attributelen = hdr - attribute;

        /* Skip whitespace after attribute */
        message_parse_rfc822space(&hdr);
        if (!hdr) return;

        /* Ignore param if no '=' character */
        if (*hdr++ != '=') goto skip;

        /* Skip whitespace before value */
        message_parse_rfc822space(&hdr);
        if (!hdr) return;

        /* Find end of value */
        value = hdr;
        if (*hdr == '\"') {
            /* Parse quoted-string */
            hdr++;
            while (*hdr && *hdr != '\"') {
                if (*hdr == '\\') {
                    hdr++;
                    if (!*hdr) return;
                }
                if (*hdr == '\r') {
                    /* check for continuation headers */
                    if (hdr[1] == '\n' && (hdr[2] == ' ' || hdr[2] == '\t')) hdr += 2;
                    else return;    /* end of header field */
                }
                hdr++;
            }
            if (!*hdr++) return;
        }
        else {
            /* Parse token (leniently allow space and tspecials) */
            const char *endval = hdr;
            while (*hdr && *hdr != ';' && *hdr != '(') {
                if (*hdr == '\r') {
                    /* Skip FWS and stop at CRLF */
                    if (hdr[1] == '\n' && (hdr[2] == ' ' || hdr[2] == '\t')) {
                        hdr += 2;
                        continue;
                    }
                    else break;
                }
                if (*hdr & 0x80) {
                    /* Allow unencoded non-ASCII characters */
                    /* XXX  We should probably make sure this is valid UTF-8 */
                }
                else if (*hdr < ' ' && *hdr != '\t') {
                    /* Reject control characters */
                    goto skip;
                }
                if (*hdr != ' ' && *hdr != '\t') {
                    /* Keep last non-WSP position */
                    endval = hdr;
                }
                hdr++;
            }
            /* Right-strip white space */
            hdr = endval + 1;
        }
        valuelen = hdr - value;

        /* Skip whitespace after value */
        message_parse_rfc822space(&hdr);

        /* Ignore parameter if not at end of header or parameter delimiter */
        if (hdr && *hdr++ != ';') {
skip:
            hdr += strcspn(hdr, ";\r\n");
            if (*hdr == ';') hdr++;
            continue;
        }

        /* Save attribute/value pair */
        *paramp = param = (struct param *)xzmalloc(sizeof(struct param));
        param->attribute = message_ucase(xstrndup(attribute, attributelen));
        param->value = xzmalloc(valuelen + 1);  /* xzmalloc for trailing NUL */
        if (*value == '\"') {
            p = param->value;
            value++;
            while (*value != '\"') {
                if (*value == '\\') value++;
                else if (*value == '\r') value += 2;
                *p++ = *value++;
            }
            *p = '\0';
        }
        else {
            memcpy(param->value, value, valuelen);
        }

        /* Get ready to parse the next parameter */
        paramp = &param->next;
    }
}

/*
 * Decode RFC 2231 parameter continuations
 *
 * Algorithm: Run down the list of parameters looking for
 * an attribute of the form "foo*0" or "foo*0*".  When we find
 * such an attribute, we look for "foo*1"/"foo*1*", "foo*2"/"foo*2*"
 * etc, appending each value to that of "foo*0" and then removing the
 * parameter we just appended from the list.  When appending values,
 * if either parameter has extended syntax, we have to convert the other
 * value from simple to extended syntax.  At the end, we change the name
 * of "foo*0"/"foo*0*" to either "foo" or "foo*", depending on whether
 * the value has extended syntax or not.
 */
static void message_fold_params(struct param **params)
{
    struct param *thisparam;    /* The "foo*1" param we're folding */
    struct param **continuation; /* Pointer to the "foo*2" param */
    struct param *tmpparam;     /* Placeholder for removing "foo*2" */
    char *asterisk;
    int section;
    int is_extended;
    char sectionbuf[5];
    int attributelen, sectionbuflen;
    char *from, *to;

    for (thisparam = *params; thisparam; thisparam = thisparam->next) {
        asterisk = strchr(thisparam->attribute, '*');
        if (asterisk && asterisk[1] == '0' &&
            (!asterisk[2] || (asterisk[2] == '*' && !asterisk[3]))) {
            /* An initial section.  Find and collect the rest */
            is_extended = (asterisk[2] == '*');
            *asterisk = '\0';
            attributelen = asterisk - thisparam->attribute;
            section = 1;
            for (;;) {
                if (section == 100) break;
                sectionbuf[0] = '*';
                if (section > 9) {
                    sectionbuf[1] = section/10 + '0';
                    sectionbuf[2] = section%10 + '0';
                    sectionbuf[3] = '\0';
                    sectionbuflen = 3;
                }
                else {
                    sectionbuf[1] = section + '0';
                    sectionbuf[2] = '\0';
                    sectionbuflen = 2;
                }

                /* Find the next continuation */
                for (continuation = params; *continuation;
                     continuation = &((*continuation)->next)) {
                    if (!strncmp((*continuation)->attribute, thisparam->attribute,
                                 attributelen) &&
                        !strncmp((*continuation)->attribute + attributelen,
                                 sectionbuf, sectionbuflen) &&
                        ((*continuation)->attribute[attributelen+sectionbuflen] == '\0' ||
                         ((*continuation)->attribute[attributelen+sectionbuflen] == '*' && (*continuation)->attribute[attributelen+sectionbuflen+1] == '\0'))) {
                        break;
                    }
                }

                /* No more continuations to find */
                if (!*continuation) break;

                if ((*continuation)->attribute[attributelen+sectionbuflen] == '\0') {
                    /* Continuation is simple */
                    if (is_extended) {
                        /* Have to re-encode continuation value */
                        thisparam->value =
                            xrealloc(thisparam->value,
                                     strlen(thisparam->value) +
                                     3*strlen((*continuation)->value) + 1);
                        from = (*continuation)->value;
                        to = thisparam->value + strlen(thisparam->value);
                        while (*from) {
                            if (*from <= ' ' || *from >= 0x7f ||
                                *from == '*' || *from == '\'' ||
                                *from == '%' || strchr(MIME_TSPECIALS, *from)) {
                                *to++ = '%';
                                to += bin_to_hex(from, 1, to, BH_UPPER);
                            } else {
                                *to++ = *from;
                            }
                            from++;
                        }
                        *to++ = '\0';
                    }
                    else {
                        thisparam->value =
                            xrealloc(thisparam->value,
                                     strlen(thisparam->value) +
                                     strlen((*continuation)->value) + 1);
                        from = (*continuation)->value;
                        to = thisparam->value + strlen(thisparam->value);
                        while ((*to++ = *from++)!= 0)
                            { }
                    }
                }
                else {
                    /* Continuation is extended */
                    if (is_extended) {
                        thisparam->value =
                            xrealloc(thisparam->value,
                                     strlen(thisparam->value) +
                                     strlen((*continuation)->value) + 1);
                        from = (*continuation)->value;
                        to = thisparam->value + strlen(thisparam->value);
                        while ((*to++ = *from++) != 0)
                            { }
                    }
                    else {
                        /* Have to re-encode thisparam value */
                        char *tmpvalue =
                            xmalloc(2 + 3*strlen(thisparam->value) +
                                    strlen((*continuation)->value) + 1);

                        from = thisparam->value;
                        to = tmpvalue;
                        *to++ = '\''; /* Unspecified charset */
                        *to++ = '\''; /* Unspecified language */
                        while (*from) {
                            if (*from <= ' ' || *from >= 0x7f ||
                                *from == '*' || *from == '\'' ||
                                *from == '%' || strchr(MIME_TSPECIALS, *from)) {
                                *to++ = '%';
                                to += bin_to_hex(from, 1, to, BH_UPPER);
                            } else {
                                *to++ = *from;
                            }
                            from++;
                        }
                        from = (*continuation)->value;

                        while ((*to++ = *from++)!=0)
                            { }

                        free(thisparam->value);
                        thisparam->value = tmpvalue;
                        is_extended = 1;
                    }
                }

                /* Remove unneeded continuation */
                free((*continuation)->attribute);
                free((*continuation)->value);
                tmpparam = *continuation;
                *continuation = (*continuation)->next;
                free(tmpparam);
                section++;
            }

            /* Fix up attribute name */
            if (is_extended) {
                asterisk[0] = '*';
                asterisk[1] = '\0';
            } else {
                asterisk[0] = '\0';
            }
        }
    }
}


/*
 * Parse a language list from a header
 */
static void message_parse_language(const char *hdr, struct param **paramp)
{
    struct param *param;
    const char *value;
    int valuelen;

    /* If we saw this header already, discard the earlier value */
    if (*paramp) param_free(paramp);

    for (;;) {
        /* Skip over leading whitespace */
        message_parse_rfc822space(&hdr);
        if (!hdr) return;

        /* Skip whitespace before value */
        message_parse_rfc822space(&hdr);
        if (!hdr) return;

        /* Find end of value */
        value = hdr;
        for (; *hdr && !Uisspace(*hdr) && *hdr != ',' && *hdr != '('; hdr++) {
            if (*hdr != '-' && !Uisalpha((*hdr))) return;
        }
        valuelen = hdr - value;

        /* Skip whitespace after value */
        message_parse_rfc822space(&hdr);

        /* Ignore parameter if not at end of header or language delimiter */
        if (hdr && *hdr++ != ',') return;

        /* Save value pair */
        *paramp = param = (struct param *)xzmalloc(sizeof(struct param));
        param->value = message_ucase(xstrndup(value, valuelen));

        /* Get ready to parse the next parameter */
        paramp = &param->next;
    }
}

/*
 * Skip over RFC 822 whitespace and comments
 */
static void message_parse_rfc822space(const char **s)
{
    const char *p = *s;
    int commentlevel = 0;

    if (!p) return;
    while (*p && (Uisspace(*p) || *p == '(')) {
        if (*p == '\n') {
            p++;
            if (*p != ' ' && *p != '\t') {
                *s = 0;     /* end of header field, no continuation */
                return;
            }
        }
        else if (*p == '(') {
            p++;
            commentlevel++;
            while (commentlevel) {
                switch (*p) {
                case '\n':
                    p++;
                    if (*p == ' ' || *p == '\t') break;
                    /* FALL THROUGH */
                case '\0':
                    *s = 0;
                    return;

                case '\\':
                    p++;
                    break;

                case '(':
                    commentlevel++;
                    break;

                case ')':
                    commentlevel--;
                    break;
                }
                p++;
            }
        }
        else p++;
    }
    if (*p == 0) {
        *s = 0;     /* embedded NUL */
    }
    else {
        *s = p;
    }
}

/*
 * Parse the content of a MIME multipart body-part
 */
static void message_parse_multipart(struct msg *msg, struct body *body,
                                    strarray_t *boundaries, const char *efname)
{
    struct body preamble, epilogue;
    struct param *boundary;
    const char *defaultContentType = DEFAULT_CONTENT_TYPE;
    int i, depth;
    int limit = config_getint(IMAPOPT_BOUNDARY_LIMIT);

    memset(&preamble, 0, sizeof(struct body));
    memset(&epilogue, 0, sizeof(struct body));
    if (strcmp(body->subtype, "DIGEST") == 0) {
        defaultContentType = "MESSAGE/RFC822";
    }

    /* Find boundary id */
    boundary = body->params;
    while (boundary &&
           strcmp(boundary->attribute, "BOUNDARY") != 0 &&
           strcmp(boundary->attribute, "BOUNDARY*") != 0) {
        boundary = boundary->next;
    }

    if (!boundary) {
        /* Invalid MIME--treat as zero-part multipart */
        message_parse_content(msg, body, boundaries, efname);
        return;
    }

    /* Add the new boundary id */
    char *id = NULL;
    if (boundary->attribute[8] == '*') {
        /* Decode boundary id */
        id = charset_parse_mimexvalue(boundary->value, NULL);
    }
    if (!id) id = xstrdup(boundary->value);
    strarray_appendm(boundaries, id);
    depth = boundaries->count;

    /* Parse preamble */
    message_parse_content(msg, &preamble, boundaries, efname);

    /* Parse the component body-parts */
    while (boundaries->count == depth &&
            (limit == 0 ? 1 : boundaries->count < limit)) {
        body->subpart = (struct body *)xrealloc((char *)body->subpart,
                                 (body->numparts+1)*sizeof(struct body));
        message_parse_body(msg, &body->subpart[body->numparts],
                           defaultContentType, boundaries, efname);
        if (msg->offset == msg->len &&
            body->subpart[body->numparts].boundary_size == 0) {
            /* hit the end of the message, therefore end all pending
               multiparts */
            strarray_truncate(boundaries, 0);
        }
        body->numparts++;
    }

    if (boundaries->count == depth-1) {
        /* Parse epilogue */
        message_parse_content(msg, &epilogue, boundaries, efname);
    }
    else if (body->numparts) {
        /*
         * We hit the boundary of an enclosing multipart while parsing
         * a component body-part.  Move the enclosing boundary information
         * up to our level.
         */
        body->boundary_size = body->subpart[body->numparts-1].boundary_size;
        body->boundary_lines = body->subpart[body->numparts-1].boundary_lines;
        body->subpart[body->numparts-1].boundary_size = 0;
        body->subpart[body->numparts-1].boundary_lines = 0;
    }
    else {
        /*
         * We hit the boundary of an enclosing multipart while parsing
         * the preamble.  Move the enclosing boundary information
         * up to our level.
         */
        body->boundary_size = preamble.boundary_size;
        body->boundary_lines = preamble.boundary_lines;
        preamble.boundary_size = 0;
        preamble.boundary_lines = 0;
    }

    /*
     * Calculate our size/lines information
     */
    body->content_size = preamble.content_size + preamble.boundary_size;
    body->content_lines = preamble.content_lines + preamble.boundary_lines;
    for (i=0; i< body->numparts; i++) {
        body->content_size += body->subpart[i].header_size +
          body->subpart[i].content_size +
          body->subpart[i].boundary_size;
        body->content_lines += body->subpart[i].header_lines +
          body->subpart[i].content_lines +
          body->subpart[i].boundary_lines;
    }
    body->content_size += epilogue.content_size;
    body->content_lines += epilogue.content_lines;

    /*
     * Move any enclosing boundary information up to our level.
     */
    body->boundary_size += epilogue.boundary_size;
    body->boundary_lines += epilogue.boundary_lines;

    /* check if we've hit a limit and flag it */
    if (limit && depth == limit) {
        if (efname)
            syslog(LOG_ERR, "ERROR: mime boundary limit %i exceeded, "
                            "not parsing anymore (%s)",
                   limit, efname);
        else
            syslog(LOG_ERR, "ERROR: mime boundary limit %i exceeded, "
                            "not parsing anymore",
                   limit);
    }
}

/*
 * Parse the content of a generic body-part
 */
static void message_parse_content(struct msg *msg, struct body *body,
                                  strarray_t *boundaries,
                                  const char *efname __attribute__((unused)))
{
    const char *line, *endline;
    unsigned long s_offset = msg->offset;
    int encode;
    int len;

    /* Should we encode a binary part? */
    encode = msg->encode &&
        body->encoding && !strcasecmp(body->encoding, "binary");

    while (msg->offset < msg->len) {
        line = msg->base + msg->offset;
        endline = memchr(line, '\n', msg->len - msg->offset);
        if (endline) {
            endline++;
        }
        else {
            endline = msg->base + msg->len;
        }
        len = endline - line;
        msg->offset += len;

        if (line[0] == '-' && line[1] == '-' &&
            message_pendingboundary(line, len, boundaries)) {
            body->boundary_size = len;
            body->boundary_lines++;
            if (body->content_lines) {
                body->content_lines--;
                body->boundary_lines++;
            }
            if (body->content_size > 1) {
                body->content_size -= 2;
                body->boundary_size += 2;
            }
            break;
        }

        body->content_size += len;

        /* Count the content lines, unless we're encoding
           (we always count blank lines) */
        if (endline[-1] == '\n' &&
            (!encode || line[0] == '\r')) {
            body->content_lines++;
        }
    }

    if (encode) {
        size_t b64_size;
        int b64_lines, delta;

        /* Determine encoded size */
        charset_encode_mimebody(NULL, body->content_size, NULL,
                                &b64_size, NULL, 1 /* wrap */);

        delta = b64_size - body->content_size;

        /* Realloc buffer to accomodate encoding overhead */
        msg->base = xrealloc((char*) msg->base, msg->len + delta);

        /* Shift content and remaining data by delta */
        memmove((char*) msg->base + s_offset + delta, msg->base + s_offset,
                msg->len - s_offset);

        /* Encode content into buffer at current position */
        charset_encode_mimebody(msg->base + s_offset + delta,
                                body->content_size,
                                (char*) msg->base + s_offset,
                                NULL, &b64_lines, 1 /* wrap */);

        /* Adjust buffer position and length to account for encoding */
        msg->offset += delta;
        msg->len += delta;

        /* Adjust body structure to account for encoding */
        free(body->encoding);
        body->encoding = xstrdup("BASE64");
        body->content_size = b64_size;
        body->content_lines += b64_lines;
    }

    body_add_content_guid(msg->base + s_offset, body);
}

static void message_parse_received_date(const char *hdr, char **hdrp)
{
  char *curp, *hdrbuf = 0;

  /* Ignore if we already saw one of these headers.
   * We want the date from the first Received header we see.
   */
  if (*hdrp) return;

  /* Copy header to temp buffer */
  message_parse_string(hdr, &hdrbuf);

  /* From rfc2822, 3.6.7
   *   received = "Received:" name-val-list ";" date-time CRLF
   * So scan backwards for ; and assume everything after is a date.
   * Failed parsing will return 0, and we'll use time() elsewhere
   * instead anyway
   */
  curp = hdrbuf + strlen(hdrbuf) - 1;
  while (curp > hdrbuf && *curp != ';')
    curp--;

  /* Didn't find ; - fill in hdrp so we don't look at next received header */
  if (curp == hdrbuf) {
    *hdrp = hdrbuf;
    return;
  }

  /* Found it, copy out date string part */
  curp++;
  message_parse_string(curp, hdrp);
  free(hdrbuf);
}


/*
 * Read a line from @msg into @buf.  Returns a pointer to the start of
 * the line inside @buf, or NULL at the end of @msg.
 */
static char *message_getline(struct buf *buf, struct msg *msg)
{
    unsigned int oldlen = buf_len(buf);
    int c;

    while (msg->offset < msg->len) {
        c = msg->base[msg->offset++];
        buf_putc(buf, c);
        if (c == '\n')
            break;
    }
    buf_cstring(buf);

    if (buf_len(buf) == oldlen)
        return 0;
    return buf->s + oldlen;
}


/*
 * Return nonzero if s is an enclosing boundary delimiter.
 * If we hit a terminating boundary, the integer pointed to by
 * 'boundaryct' is modified appropriately.
 */
static int message_pendingboundary(const char *s, int slen,
                                   strarray_t *boundaries)
{
    int i, len;
    int rfc2046_strict = config_getswitch(IMAPOPT_RFC2046_STRICT);
    const char *bbase;
    int blen;

    /* skip initial '--' */
    if (slen < 2) return 0;
    if (s[0] != '-' || s[1] != '-') return 0;
    bbase = s + 2;
    blen = slen - 2;

    for (i = 0; i < boundaries->count ; ++i) {
        len = strlen(boundaries->data[i]);
        /* basic sanity check and overflow protection */
        if (blen < len) continue;

        if (!strncmp(bbase, boundaries->data[i], len)) {
            /* trailing '--', it's the end of this part */
            if (blen >= len+2 && bbase[len] == '-' && bbase[len+1] == '-')
                strarray_truncate(boundaries, i);
            else if (!rfc2046_strict && blen > len+1 &&
                     bbase[len] && !Uisspace(bbase[len])) {
                /* Allow substring matches in the boundary.
                 *
                 * If rfc2046_strict is enabled, boundaries containing
                 * other boundaries as substrings will be treated as identical
                 * (per RFC 2046 section 5.1.1).  Note that this will
                 * break some messages created by Eudora 5.1 (and earlier).
                 */
                continue;
            }
            return 1;
        }
    }
    return 0;
}


/*
 * Write the cache information for the message parsed to 'body'
 * to 'outfile'.
 */
EXPORTED int message_write_cache(struct index_record *record, const struct body *body)
{
    static struct buf cacheitem_buffer;
    struct buf ib[NUM_CACHE_FIELDS];
    struct body toplevel;
    char *subject;
    int i;

    /* initialise data structures */
    buf_reset(&cacheitem_buffer);
    memset(ib, 0, sizeof(ib));

    toplevel.type = "MESSAGE";
    toplevel.subtype = "RFC822";
    /* we cast away const because we know that we're only using
     * toplevel.subpart as const in message_write_section(). */
    toplevel.subpart = (struct body *)body;

    subject = charset_parse_mimeheader(body->subject, charset_flags);

    /* copy into bufs */
    message_write_envelope(&ib[CACHE_ENVELOPE], body);
    message_write_body(&ib[CACHE_BODYSTRUCTURE], body, 1);
    buf_copy(&ib[CACHE_HEADERS], &body->cacheheaders);
    message_write_body(&ib[CACHE_BODY], body, 0);
    message_write_section(&ib[CACHE_SECTION], &toplevel);
    message_write_searchaddr(&ib[CACHE_FROM], body->from);
    message_write_searchaddr(&ib[CACHE_TO], body->to);
    message_write_searchaddr(&ib[CACHE_CC], body->cc);
    message_write_searchaddr(&ib[CACHE_BCC], body->bcc);
    message_write_nstring(&ib[CACHE_SUBJECT], subject);

    free(subject);

    /* append the records to the buffer */
    for (i = 0; i < NUM_CACHE_FIELDS; i++) {
        record->crec.item[i].len = buf_len(&ib[i]);
        record->crec.item[i].offset = buf_len(&cacheitem_buffer) + sizeof(uint32_t);
        message_write_xdrstring(&cacheitem_buffer, &ib[i]);
        buf_free(&ib[i]);
    }

    /* copy the fields into the message */
    record->cache_offset = 0; /* calculate on write! */
    record->cache_version = MAILBOX_CACHE_MINOR_VERSION;
    record->cache_crc = crc32_buf(&cacheitem_buffer);
    record->crec.buf = &cacheitem_buffer;
    record->crec.offset = 0; /* we're at the start of the buffer */
    record->crec.len = buf_len(&cacheitem_buffer);

    return 0;
}


/*
 * Write the IMAP envelope for 'body' to 'buf'
 */
static void message_write_envelope(struct buf *buf, const struct body *body)
{
    buf_putc(buf, '(');
    message_write_nstring(buf, body->date);
    buf_putc(buf, ' ');
    message_write_nstring(buf, body->subject);
    buf_putc(buf, ' ');
    message_write_address(buf, body->from);
    buf_putc(buf, ' ');
    message_write_address(buf, body->sender ? body->sender : body->from);
    buf_putc(buf, ' ');
    message_write_address(buf, body->reply_to ? body->reply_to : body->from);
    buf_putc(buf, ' ');
    message_write_address(buf, body->to);
    buf_putc(buf, ' ');
    message_write_address(buf, body->cc);
    buf_putc(buf, ' ');
    message_write_address(buf, body->bcc);
    buf_putc(buf, ' ');
    message_write_nstring(buf, body->in_reply_to);
    buf_putc(buf, ' ');
    message_write_nstring(buf, body->message_id);
    buf_putc(buf, ')');
}

/*
 * Write the BODY (if 'newformat' is zero) or BODYSTRUCTURE
 * (if 'newformat' is nonzero) for 'body' to 'buf'.
 */
EXPORTED void message_write_body(struct buf *buf, const struct body *body,
                                 int newformat)
{
    struct param *param;

    if (strcmp(body->type, "MULTIPART") == 0) {
        int i;

        /* 0-part multiparts are illegal--convert to 0-len text parts */
        if (body->numparts == 0) {
            static struct body zerotextbody;

            if (!zerotextbody.type) {
                message_parse_bodytype(DEFAULT_CONTENT_TYPE, &zerotextbody);
            }
            message_write_body(buf, &zerotextbody, newformat);
            return;
        }

        /* Multipart types get a body_multipart */
        buf_putc(buf, '(');
        for (i = 0; i < body->numparts; i++) {
            message_write_body(buf, &body->subpart[i], newformat);
        }
        buf_putc(buf, ' ');
        message_write_nstring(buf, body->subtype);

        if (newformat) {
            buf_putc(buf, ' ');
            if ((param = body->params)!=NULL) {
                buf_putc(buf, '(');
                while (param) {
                    message_write_nstring(buf, param->attribute);
                    buf_putc(buf, ' ');
                    message_write_nstring(buf, param->value);
                    if ((param = param->next)!=NULL) {
                        buf_putc(buf, ' ');
                    }
                }
                buf_putc(buf, ')');
            }
            else message_write_nstring(buf, (char *)0);
            buf_putc(buf, ' ');
            if (body->disposition) {
                buf_putc(buf, '(');
                message_write_nstring(buf, body->disposition);
                buf_putc(buf, ' ');
                if ((param = body->disposition_params)!=NULL) {
                    buf_putc(buf, '(');
                    while (param) {
                        message_write_nstring(buf, param->attribute);
                        buf_putc(buf, ' ');
                        message_write_nstring(buf, param->value);
                        if ((param = param->next)!=NULL) {
                            buf_putc(buf, ' ');
                        }
                    }
                    buf_putc(buf, ')');
                }
                else message_write_nstring(buf, (char *)0);
                buf_putc(buf, ')');
            }
            else {
                message_write_nstring(buf, (char *)0);
            }
            buf_putc(buf, ' ');
            if ((param = body->language)!=NULL) {
                buf_putc(buf, '(');
                while (param) {
                    message_write_nstring(buf, param->value);
                    if ((param = param->next)!=NULL) {
                        buf_putc(buf, ' ');
                    }
                }
                buf_putc(buf, ')');
            }
            else message_write_nstring(buf, (char *)0);
            buf_putc(buf, ' ');
            message_write_nstring(buf, body->location);
        }

        buf_putc(buf, ')');
        return;
    }

    buf_putc(buf, '(');
    message_write_nstring(buf, body->type);
    buf_putc(buf, ' ');
    message_write_nstring(buf, body->subtype);
    buf_putc(buf, ' ');

    if ((param = body->params)!=NULL) {
        buf_putc(buf, '(');
        while (param) {
            message_write_nstring(buf, param->attribute);
            buf_putc(buf, ' ');
            message_write_nstring(buf, param->value);
            if ((param = param->next)!=NULL) {
                buf_putc(buf, ' ');
            }
        }
        buf_putc(buf, ')');
    }
    else message_write_nstring(buf, (char *)0);
    buf_putc(buf, ' ');

    message_write_nstring(buf, body->id);
    buf_putc(buf, ' ');
    message_write_nstring(buf, body->description);
    buf_putc(buf, ' ');
    message_write_nstring(buf, body->encoding ? body->encoding : "7BIT");
    buf_putc(buf, ' ');
    buf_printf(buf, "%u", body->content_size);

    if (strcmp(body->type, "TEXT") == 0) {
        /* Text types get a line count */
        buf_putc(buf, ' ');
        buf_printf(buf, "%u", body->content_lines);
    }
    else if (strcmp(body->type, "MESSAGE") == 0
             && strcmp(body->subtype, "RFC822") == 0) {
        /* Message/rfc822 gets a body_msg */
        buf_putc(buf, ' ');
        message_write_envelope(buf, body->subpart);
        buf_putc(buf, ' ');
        message_write_body(buf, body->subpart, newformat);
        buf_putc(buf, ' ');
        buf_printf(buf, "%u", body->content_lines);
    }

    if (newformat) {
        /* Add additional fields for BODYSTRUCTURE */
        buf_putc(buf, ' ');
        message_write_nstring(buf, body->md5);
        buf_putc(buf, ' ');
        if (body->disposition) {
            buf_putc(buf, '(');
            message_write_nstring(buf, body->disposition);
            buf_putc(buf, ' ');
            if ((param = body->disposition_params)!=NULL) {
                buf_putc(buf, '(');
                while (param) {
                    message_write_nstring(buf, param->attribute);
                    buf_putc(buf, ' ');
                    message_write_nstring(buf, param->value);
                    if ((param = param->next)!=NULL) {
                        buf_putc(buf, ' ');
                    }
                }
                buf_putc(buf, ')');
            }
            else message_write_nstring(buf, (char *)0);
            buf_putc(buf, ')');
        }
        else {
            message_write_nstring(buf, (char *)0);
        }
        buf_putc(buf, ' ');
        if ((param = body->language)!=NULL) {
            buf_putc(buf, '(');
            while (param) {
                message_write_nstring(buf, param->value);
                if ((param = param->next)!=NULL) {
                    buf_putc(buf, ' ');
                }
            }
            buf_putc(buf, ')');
        }
        else message_write_nstring(buf, (char *)0);
        buf_putc(buf, ' ');
        message_write_nstring(buf, body->location);

        if (newformat > 1 && !body->numparts) {
            /* even newer extension fields for annotation callout */
            buf_printf(buf, " (OFFSET %u HEADERSIZE %u)",
                       body->content_offset,
                       body->header_size);
        }
    }

    buf_putc(buf, ')');
}

/*
 * Write the address list 'addrlist' to 'buf'
 */
static void message_write_address(struct buf *buf,
                                  const struct address *addrlist)
{
    /* If no addresses, write out NIL */
    if (!addrlist) {
        message_write_nstring(buf, (char *)0);
        return;
    }

    buf_putc(buf, '(');

    while (addrlist) {
        buf_putc(buf, '(');
        message_write_nstring(buf, addrlist->name);
        buf_putc(buf, ' ');
        message_write_nstring(buf, addrlist->route);
        buf_putc(buf, ' ');
        message_write_nstring(buf, addrlist->mailbox);
        buf_putc(buf, ' ');
        message_write_nstring(buf, addrlist->domain);
        buf_putc(buf, ')');
        addrlist = addrlist->next;
    }

    buf_putc(buf, ')');
}

/*
 * Write the nil-or-string 's' to 'buf'
 */
EXPORTED void message_write_nstring(struct buf *buf, const char *s)
{
    message_write_nstring_map(buf, s, (s ? strlen(s) : 0));
}

EXPORTED void message_write_nstring_map(struct buf *buf,
                               const char *s,
                               unsigned int len)
{
    const char *p;
    int is_literal = 0;

    /* Write null pointer as NIL */
    if (!s) {
        buf_appendcstr(buf, "NIL");
        return;
    }

    if (len >= 1024)
    {
        is_literal = 1;
    }
    else
    {
        /* Look for any non-QCHAR characters */
        for (p = s; (unsigned)(p-s) < len ; p++) {
            if (!*p || *p & 0x80 || *p == '\r' || *p == '\n'
                || *p == '\"' || *p == '%' || *p == '\\') {
                is_literal = 1;
                break;
            }
        }
    }

    if (is_literal) {
        /* Write out as literal */
        buf_printf(buf, "{%u}\r\n", len);
        buf_appendmap(buf, s, len);
    }
    else {
        /* Write out as quoted string */
        buf_putc(buf, '"');
        buf_appendmap(buf, s, len);
        buf_putc(buf, '"');
    }
}

/*
 * Append the string @s to the buffer @buf in a binary
 * format almost exactly
 */
EXPORTED void message_write_xdrstring(struct buf *buf, const struct buf *s)
{
    unsigned padlen;

    /* 32b string length in network order */
    buf_appendbit32(buf, buf_len(s));
    /* bytes of string */
    buf_appendmap(buf, s->s, s->len);
    /* 0 to 3 bytes padding */
    padlen = (4 - (s->len & 3)) & 3;
    buf_appendmap(buf, "\0\0\0", padlen);
}

/*
 * Write the text 's' to 'buf', converting to lower case as we go.
 */
static void message_write_text_lcase(struct buf *buf, const char *s)
{
    const char *p;

    for (p = s; *p; p++) buf_putc(buf, TOLOWER(*p));
}

static void message_write_nocharset(struct buf *buf, const struct body *body)
{
    buf_appendbit32(buf, 0x0000ffff);

    char guidbuf[MESSAGE_GUID_SIZE];
    if (body) message_guid_export(&body->content_guid, guidbuf);
    else memset(&guidbuf, 0, MESSAGE_GUID_SIZE);
    buf_appendmap(buf, guidbuf, MESSAGE_GUID_SIZE);
    buf_appendbit32(buf, body ? body->decoded_content_size : 0);
    buf_appendbit32(buf, body ? body->content_lines : 0);
}

/*
 * Write out the FETCH BODY[section] location/size information to 'buf'.
 */
static void message_write_section(struct buf *buf, const struct body *body)
{
    int part;

    if (strcmp(body->type, "MESSAGE") == 0
        && strcmp(body->subtype, "RFC822") == 0) {
        if (body->subpart->numparts) {
            /*
             * Part 0 of a message/rfc822 is the message header/text.
             * Nested parts of a message/rfc822 containing a multipart
             * are the sub-parts of the multipart.
             */
            buf_appendbit32(buf, body->subpart->numparts+1);
            buf_appendbit32(buf, body->subpart->header_offset);
            buf_appendbit32(buf, body->subpart->header_size);
            buf_appendbit32(buf, body->subpart->content_offset);
            buf_appendbit32(buf, body->subpart->content_size);
            message_write_nocharset(buf, body->subpart);
            for (part = 0; part < body->subpart->numparts; part++) {
                buf_appendbit32(buf, body->subpart->subpart[part].header_offset);
                buf_appendbit32(buf, body->subpart->subpart[part].header_size);
                buf_appendbit32(buf, body->subpart->subpart[part].content_offset);
                if (body->subpart->subpart[part].numparts == 0 &&
                    strcmp(body->subpart->subpart[part].type, "MULTIPART") == 0) {
                    /* Treat 0-part multipart as 0-length text */
                    buf_appendbit32(buf, 0);
                }
                else {
                    buf_appendbit32(buf, body->subpart->subpart[part].content_size);
                }
                message_write_charset(buf, &body->subpart->subpart[part]);
            }
            for (part = 0; part < body->subpart->numparts; part++) {
                message_write_section(buf, &body->subpart->subpart[part]);
            }
        }
        else {
            /*
             * Part 0 of a message/rfc822 is the message header/text.
             * Part 1 of a message/rfc822 containing a non-multipart
             * is the message body.
             */
            buf_appendbit32(buf, 2);
            buf_appendbit32(buf, body->subpart->header_offset);
            buf_appendbit32(buf, body->subpart->header_size);
            buf_appendbit32(buf, body->subpart->content_offset);
            buf_appendbit32(buf, body->subpart->content_size);
            message_write_nocharset(buf, body->subpart);
            buf_appendbit32(buf, body->subpart->header_offset);
            buf_appendbit32(buf, body->subpart->header_size);
            buf_appendbit32(buf, body->subpart->content_offset);
            if (strcmp(body->subpart->type, "MULTIPART") == 0) {
                /* Treat 0-part multipart as 0-length text */
                buf_appendbit32(buf, 0);
                message_write_nocharset(buf, NULL);
            }
            else {
                buf_appendbit32(buf, body->subpart->content_size);
                message_write_charset(buf, body->subpart);
            }
            message_write_section(buf, body->subpart);
        }
    }
    else if (body->numparts) {
        /*
         * Cannot fetch part 0 of a multipart.
         * Nested parts of a multipart are the sub-parts.
         */
        buf_appendbit32(buf, body->numparts+1);
        buf_appendbit32(buf, 0);
        buf_appendbit32(buf, -1);
        buf_appendbit32(buf, 0);
        buf_appendbit32(buf, -1);
        message_write_nocharset(buf, NULL);
        for (part = 0; part < body->numparts; part++) {
            buf_appendbit32(buf, body->subpart[part].header_offset);
            buf_appendbit32(buf, body->subpart[part].header_size);
            buf_appendbit32(buf, body->subpart[part].content_offset);
            if (body->subpart[part].numparts == 0 &&
                strcmp(body->subpart[part].type, "MULTIPART") == 0) {
                /* Treat 0-part multipart as 0-length text */
                buf_appendbit32(buf, 0);
                message_write_nocharset(buf, &body->subpart[part]);
            }
            else {
                buf_appendbit32(buf, body->subpart[part].content_size);
                message_write_charset(buf, &body->subpart[part]);
            }
        }
        for (part = 0; part < body->numparts; part++) {
            message_write_section(buf, &body->subpart[part]);
        }
    }
    else {
        /*
         * Leaf section--no part 0 or nested parts
         */
        buf_appendbit32(buf, 0);
    }
}

/*
 * Write the 32-bit charset/encoding value and the charset identifier
 * for section 'body' to 'buf'
 */
static void message_write_charset(struct buf *buf, const struct body *body)
{
    int encoding;
    charset_t charset;
    size_t len = 0;
    const char *name = NULL;

    message_parse_charset(body, &encoding, &charset);

    /* write charset/encoding preamble */
    if (charset != CHARSET_UNKNOWN_CHARSET) {
        size_t itemsize;

        name = charset_alias_name(charset);
        len = strlen(name);

        /* charset name length is a multiple of cache item size,
         * including the terminating zero byte(s) */
        itemsize = (size_t) CACHE_ITEM_SIZE_SKIP;
        len = ((len / itemsize) + 1) * itemsize;
        if (len > 0xffff) len = 0;
    }
    /* we stored 0x100 here to say that it was a version 4 cache with the
     * charset length stored, which is all very well and nice, but it's
     * useless once we added sha1, so it's been removed again */
    buf_appendbit32(buf, ((len & 0xffff) << 16)|(encoding & 0xff));

    /* write charset identifier */
    if (len) {
        char *tmp = (char*) xcalloc(sizeof(char), len);
        memcpy(tmp, name, strlen(name));
        buf_appendmap(buf, tmp, len);
        free(tmp);
    }
    charset_free(&charset);

    /* NOTE - this stuff doesn't really belong in a method called
     * message_write_charset, but it's the fields that are always
     * written immediately after the charset! */
    char guidbuf[MESSAGE_GUID_SIZE];
    if (body) message_guid_export(&body->content_guid, guidbuf);
    else memset(&guidbuf, 0, MESSAGE_GUID_SIZE);
    buf_appendmap(buf, guidbuf, MESSAGE_GUID_SIZE);
    buf_appendbit32(buf, body ? body->decoded_content_size : 0);
    buf_appendbit32(buf, body ? body->content_lines : 0);
}

/*
 * Unparse the address list 'addrlist' to 'buf'
 */
static void message_write_searchaddr(struct buf *buf,
                                     const struct address *addrlist)
{
    int prevaddr = 0;
    char* tmp;

    while (addrlist) {

        /* Handle RFC 822 group addresses */
        if (!addrlist->domain) {
            if (addrlist->mailbox) {
                if (prevaddr) buf_putc(buf, ',');

                tmp = charset_parse_mimeheader(addrlist->mailbox, charset_flags);
                buf_appendcstr(buf, tmp);
                free(tmp);
                tmp = NULL;
                buf_putc(buf, ':');

                /* Suppress a trailing comma */
                prevaddr = 0;
            }
            else {
                buf_putc(buf, ';');
                prevaddr = 1;
            }
        }
        else {
            if (prevaddr) buf_putc(buf, ',');

            if (addrlist->name) {
                tmp = charset_parse_mimeheader(addrlist->name, charset_flags);
                /* Determine if name is an atext or quoted-string */
                static const char atext_specials[] = "!#$%&'*+-/=?^_`{|}~";
                const char *c;
                for (c = tmp; *c; c++) {
                    // see RFC 5322, section 3.2.3
                    if (!isalpha(*c) && !isdigit(*c) && !isspace(*c) &&
                            !strchr(atext_specials, *c)) {
                        break;
                    }
                }
                int need_quote = *c;
                /* Write name */
                if (need_quote) {
                    struct buf qtext = BUF_INITIALIZER;
                    buf_ensure(&qtext, strlen(tmp) + 2);
                    buf_putc(&qtext, '"');
                    for (c = tmp; *c; c++) {
                        if (*c == '\\' || *c == '"')
                            buf_putc(&qtext, '\\');
                        buf_putc(&qtext, *c);
                    }
                    buf_putc(&qtext, '"');
                    buf_append(buf, &qtext);
                    buf_free(&qtext);
                }
                else {
                    buf_appendcstr(buf, tmp);
                }
                free(tmp); tmp = NULL;
                buf_putc(buf, ' ');
            }

            buf_putc(buf, '<');
            if (addrlist->route) {
                message_write_text_lcase(buf, addrlist->route);
                buf_putc(buf, ':');
            }

            message_write_text_lcase(buf, addrlist->mailbox);
            buf_putc(buf, '@');

            message_write_text_lcase(buf, addrlist->domain);
            buf_putc(buf, '>');
            prevaddr = 1;
        }

        addrlist = addrlist->next;
    }
}

EXPORTED void param_free(struct param **paramp)
{
    struct param *param, *nextparam;

    param = *paramp;
    *paramp = NULL;

    for (; param; param = nextparam) {
        nextparam = param->next;
        if (param->attribute) free(param->attribute);
        if (param->value) free(param->value);
        free(param);
    }
}

/*
 * Free the parsed body-part 'body'
 */
EXPORTED void message_free_body(struct body *body)
{
    int part;

    if (!body) return;

    if (body->type) {
        free(body->type);
        free(body->subtype);
        param_free(&body->params);
    }
    if (body->id) free(body->id);
    if (body->description) free(body->description);
    if (body->encoding) free(body->encoding);
    if (body->md5) free(body->md5);
    if (body->disposition) {
        free(body->disposition);
        param_free(&body->disposition_params);
    }
    param_free(&body->language);
    if (body->location) free(body->location);
    if (body->date) free(body->date);
    if (body->subject) free(body->subject);
    if (body->from) parseaddr_free(body->from);
    if (body->sender) parseaddr_free(body->sender);
    if (body->reply_to) parseaddr_free(body->reply_to);
    if (body->to) parseaddr_free(body->to);
    if (body->cc) parseaddr_free(body->cc);
    if (body->bcc) parseaddr_free(body->bcc);
    if (body->in_reply_to) free(body->in_reply_to);
    if (body->message_id) free(body->message_id);
    if (body->x_me_message_id) free(body->x_me_message_id);
    if (body->references) free(body->references);
    if (body->received_date) free(body->received_date);
    if (body->x_deliveredinternaldate) free(body->x_deliveredinternaldate);
    if (body->charset_id) free(body->charset_id);
    if (body->part_id) free(body->part_id);

    if (body->subpart) {
        if (body->numparts) {
            for (part=0; part < body->numparts; part++) {
                message_free_body(&body->subpart[part]);
            }
        }
        else {
            message_free_body(body->subpart);
        }
        free(body->subpart);
    }

    buf_free(&body->cacheheaders);

    if (body->decoded_body) free(body->decoded_body);
}

/*
 * Parse a cached envelope into individual tokens
 *
 * When inside a list (ncom > 0), we parse the individual tokens but don't
 * isolate them -- we return the entire list as a single token.
 */
HIDDEN void parse_cached_envelope(char *env, char *tokens[], int tokens_size)
{
    char *c;
    int i = 0, ncom = 0, len;

    /*
     * We have no way of indicating that we parsed less than
     * the requested number of tokens, but we can at least
     * ensure that the array is correctly initialised to NULL.
     */
    memset(tokens, 0, tokens_size*sizeof(char*));

    c = env;
    while (*c != '\0') {
        switch (*c) {
        case ' ':                       /* end of token */
            if (!ncom) *c = '\0';       /* mark end of token */
            c++;
            break;
        case 'N':                       /* "NIL" */
        case 'n':
            if (!ncom) {
                if(i>=tokens_size) break;
                tokens[i++] = NULL;     /* empty token */
            }
            c += 3;                     /* skip "NIL" */
            break;
        case '"':                       /* quoted string */
            c++;                        /* skip open quote */
            if (!ncom) {
                if(i>=tokens_size) break;
                tokens[i++] = c;        /* start of string */
            }
            while (*c && *c != '"') {           /* find close quote */
                if (*c == '\\') c++;    /* skip quoted-specials */
                if (*c) c++;
            }
            if (*c) {
                if (!ncom) *c = '\0';   /* end of string */
                c++;                    /* skip close quote */
            }
            break;
        case '{':                       /* literal */
            c++;                        /* skip open brace */
            len = 0;                    /* determine length of literal */
            while (cyrus_isdigit((int) *c)) {
                len = len*10 + *c - '0';
                c++;
            }
            c += 3;                     /* skip close brace & CRLF */
            if (!ncom){
                if(i>=tokens_size) break;
                tokens[i++] = c;        /* start of literal */
            }
            c += len;                   /* skip literal */
            break;
        case '(':                       /* start of address */
            c++;                        /* skip open paren */
            if (!ncom) {
                if(i>=tokens_size) break;
                tokens[i++] = c;        /* start of address list */
            }
            ncom++;                     /* new open - inc counter */
            break;
        case ')':                       /* end of address */
            c++;                        /* skip close paren */
            if (ncom) {                 /* paranoia */
                ncom--;                 /* close - dec counter */
                if (!ncom)              /* all open paren are closed */
                    *(c-1) = '\0';      /* end of list - trim close paren */
            }
            break;
        default:
            /* yikes! unparsed junk, just skip it */
            c++;
            break;
        }
    }
}

EXPORTED char *parse_nstring(char **str)
{
    char *cp = *str, *val;

    if (*cp == '"') { /* quoted string */
        val = cp+1; /* skip " */
        do {
            cp = strchr(cp+1, '"');
            if (!cp) return NULL; /* whole thing is broken */
        } while (*(cp-1) == '\\'); /* skip escaped " */
        *cp++ = '\0';
    }
    else if (*cp == '{') {
        int len = 0;
        /* yeah, it may be a literal too */
        cp++;
        while (cyrus_isdigit((int) *cp)) {
            len = len*10 + *cp - '0';
            cp++;
        }
        cp += 3;                /* skip close brace & CRLF */
        val = cp;
        val[len] = '\0';
        cp += len;
    }
    else { /* NIL */
        val = NULL;
        cp += 3;
    }

    *str = cp;
    return val;
}

EXPORTED void message_parse_env_address(char *str, struct address *addr)
{
    if (*str == '(') str++; /* skip ( */
    addr->name = parse_nstring(&str);
    str++; /* skip SP */
    addr->route = parse_nstring(&str);
    str++; /* skip SP */
    addr->mailbox = parse_nstring(&str);
    str++; /* skip SP */
    addr->domain = parse_nstring(&str);
}

/*
 * Read an nstring from cached bodystructure.
 * Analog to message_write_nstring().
 * If 'copy' is set, returns a freshly allocated copy of the string,
 * otherwise is returns a pointer to the string which will be overwritten
 * on the next call to message_read_nstring()
 */
static int message_read_nstring(struct protstream *strm, char **str, int copy)
{
    static struct buf buf = BUF_INITIALIZER;
    int c;

    c = getnstring(strm, NULL, &buf);

    if (str) {
        if (!buf.s) *str = NULL;
        else if (copy) *str = xstrdup(buf.s);
        else *str = buf.s;
    }

    return c;
}

/*
 * Read a parameter list from cached bodystructure.
 * If withattr is set, attribute/value pairs will be read,
 * otherwise, just values are read.
 */
static int message_read_params(struct protstream *strm, struct param **paramp,
                               int withattr)
{
    int c;

    if ((c = prot_getc(strm)) == '(') {
        /* parse list */
        struct param *param;

        do {
            *paramp = param = (struct param *) xzmalloc(sizeof(struct param));

            if (withattr) {
                /* attribute */
                c = message_read_nstring(strm, &param->attribute, 1);
            }

            /* value */
            c = message_read_nstring(strm, &param->value, 1);

            /* get ready to append the next parameter */
            paramp = &param->next;

        } while (c == ' ');

        if (c == ')') c = prot_getc(strm);
    }
    else {
        /* NIL */
        prot_ungetc(c, strm);
        c = message_read_nstring(strm, NULL, 0);
    }

    return c;
}

/*
 * Read an address part from cached bodystructure.
 * The string is appended to 'buf' (including NUL).
 */
static int message_read_addrpart(struct protstream *strm,
                                 const char **part, unsigned *off, struct buf *buf)
{
    int c;

    c = message_read_nstring(strm, (char **)part, 0);
    if (*part) {
        *off = buf->len;
        buf_appendmap(buf, *part, strlen(*part)+1);
    }

    return c;
}

/*
 * Read an address list from cached bodystructure.
 * Analog to message_write_address()
 */
static int message_read_address(struct protstream *strm, struct address **addrp)
{
    int c;

    if ((c = prot_getc(strm)) == '(') {
        /* parse list */
        struct address *addr;
        unsigned nameoff = 0, rtoff = 0, mboxoff = 0, domoff = 0;

        do {
            struct buf buf = BUF_INITIALIZER;
            *addrp = addr = (struct address *) xzmalloc(sizeof(struct address));

            /* opening '(' */
            c = prot_getc(strm);

            /* name */
            c = message_read_addrpart(strm, &addr->name, &nameoff, &buf);

            /* route */
            c = message_read_addrpart(strm, &addr->route, &rtoff, &buf);

            /* mailbox */
            c = message_read_addrpart(strm, &addr->mailbox, &mboxoff, &buf);

            /* host */
            c = message_read_addrpart(strm, &addr->domain, &domoff, &buf);

            /* addr parts must now point into our freeme string */
            if (buf.len) {
                char *freeme = addr->freeme = buf_release(&buf);

                if (addr->name) addr->name = freeme+nameoff;
                if (addr->route) addr->route = freeme+rtoff;
                if (addr->mailbox) addr->mailbox = freeme+mboxoff;
                if (addr->domain) addr->domain = freeme+domoff;
            }

            buf_free(&buf);

            /* get ready to append the next address */
            addrp = &addr->next;

        } while (((c = prot_getc(strm)) == '(') && prot_ungetc(c, strm));

        if (c == ')') c = prot_getc(strm);
    }
    else {
        /* NIL */
        prot_ungetc(c, strm);
        c = message_read_nstring(strm, NULL, 0);
    }

    return c;
}

/*
 * Read a cached envelope response.
 * Analog to message_write_envelope()
 */
static int message_read_envelope(struct protstream *strm, struct body *body)
{
    int c;

    /* opening '(' */
    c = prot_getc(strm);

    /* date */
    c = message_read_nstring(strm, &body->date, 1);

    /* subject */
    c = message_read_nstring(strm, &body->subject, 1);

    /* from */
    c = message_read_address(strm, &body->from);

    /* sender */
    c = message_read_address(strm, &body->sender);

    /* reply-to */
    c = message_read_address(strm, &body->reply_to);

    /* to */
    c = message_read_address(strm, &body->to);

    /* cc */
    c = message_read_address(strm, &body->cc);

    /* bcc */
    c = message_read_address(strm, &body->bcc);

    /* in-reply-to */
    c = message_read_nstring(strm, &body->in_reply_to, 1);

    /* message-id */
    c = message_read_nstring(strm, &body->message_id, 1);

    if (c == ')') c = prot_getc(strm);

    return c;
}

/*
 * Read cached bodystructure response.
 * Analog to message_write_body()
 */
static int message_read_body(struct protstream *strm, struct body *body, const char *part_id)
{
    int c;
    struct buf buf = BUF_INITIALIZER;

    /* opening '(' */
    c = prot_getc(strm);
    if (c == EOF) goto done;

    /* check for multipart */
    if ((c = prot_peek(strm)) == '(') {

        body->type = xstrdup("MULTIPART");
        do {
            body->subpart =
                (struct body *)xrealloc((char *)body->subpart,
                                        (body->numparts+1)*sizeof(struct body));
            memset(&body->subpart[body->numparts], 0, sizeof(struct body));
            buf_reset(&buf);
            if (part_id) buf_printf(&buf, "%s.", part_id);
            buf_printf(&buf, "%d", body->numparts + 1);
            struct body *subbody = &body->subpart[body->numparts++];
            subbody->part_id = buf_release(&buf);
            c = message_read_body(strm, subbody, subbody->part_id);
        } while (((c = prot_getc(strm)) == '(') && prot_ungetc(c, strm));

        /* remove the part_id here, you can't address multiparts directly */
        free(body->part_id);
        body->part_id = NULL;

        /* body subtype */
        c = message_read_nstring(strm, &body->subtype, 1);
        if (c == EOF) goto done;

        /* extension data */

        /* body parameters */
        c = message_read_params(strm, &body->params, 1);
        if (c == EOF) goto done;
    }
    else {
        if (!body->part_id) {
            buf_reset(&buf);
            if (part_id) buf_printf(&buf, "%s.", part_id);
            buf_printf(&buf, "%d", 1);
            body->part_id = buf_release(&buf);
        }
        /* non-multipart */

        /* body type */
        c = message_read_nstring(strm, &body->type, 1);
        if (c == EOF) goto done;

        /* body subtype */
        c = message_read_nstring(strm, &body->subtype, 1);
        if (c == EOF) goto done;

        /* body parameters */
        c = message_read_params(strm, &body->params, 1);
        if (c == EOF) goto done;

        /* body id */
        c = message_read_nstring(strm, &body->id, 1);
        if (c == EOF) goto done;

        /* body description */
        c = message_read_nstring(strm, &body->description, 1);
        if (c == EOF) goto done;

        /* body encoding */
        c = message_read_nstring(strm, &body->encoding, 1);
        if (c == EOF) goto done;

        /* body size */
        c = getuint32(strm, &body->content_size);
        if (c == EOF) goto done;

        if (!strcmp(body->type, "TEXT")) {
            /* body lines */
            c = getint32(strm, (int32_t *) &body->content_lines);
            if (c == EOF) goto done;
        }
        else if (!strcmp(body->type, "MESSAGE") &&
                 !strcmp(body->subtype, "RFC822")) {

            body->subpart = (struct body *) xzmalloc(sizeof(struct body));

            /* envelope structure */
            c = message_read_envelope(strm, body->subpart);
            if (c == EOF) goto done;

            /* body structure */
            c = message_read_body(strm, body->subpart, body->part_id);
            if (c == EOF) goto done;
            c = prot_getc(strm); /* trailing SP */
            if (c == EOF) goto done;

            /* body lines */
            c = getint32(strm, (int32_t *) &body->content_lines);
            if (c == EOF) goto done;
        }

        /* extension data */

        /* body MD5 */
        c = message_read_nstring(strm, &body->md5, 1);
        if (c == EOF) goto done;
    }

    /* common extension data */

    /* body disposition */
    if ((c = prot_getc(strm)) == '(') {
        c = message_read_nstring(strm, &body->disposition, 1);
        if (c == EOF) goto done;

        c = message_read_params(strm, &body->disposition_params, 1);
        if (c == ')') c = prot_getc(strm); /* trailing SP */
        if (c == EOF) goto done;
    }
    else {
        /* NIL */
        prot_ungetc(c, strm);
        c = message_read_nstring(strm, &body->disposition, 1);
        if (c == EOF) goto done;
    }

    /* body language */
    if ((c = prot_peek(strm)) == '(') {
        c = message_read_params(strm, &body->language, 0);
        if (c == EOF) goto done;
    }
    else {
        char *lang;

        c = message_read_nstring(strm, &lang, 1);
        if (c == EOF) goto done;
        if (lang) {
            body->language = (struct param *) xzmalloc(sizeof(struct param));
            body->language->value = lang;
        }
    }

    /* body location */
    c = message_read_nstring(strm, &body->location, 1);

    /* XXX  We currently don't store any other extension data.
            MUST keep in sync with message_write_body() */

done:
    buf_free(&buf);
    return c;
}

/*
 * Read cached binary bodystructure.
 * Analog to message_write_section()
 */
static void message_read_binarybody(struct body *body, const char **sect,
                                    uint32_t cache_version)
{
    bit32 n, i;
    const char *p = *sect;
    struct body *subpart;
    size_t len;
    uint32_t cte;

    n = CACHE_ITEM_BIT32(*sect);
    p = *sect += CACHE_ITEM_SIZE_SKIP;
    if (!n) return;

    if (!strcmp(body->type, "MESSAGE") && !strcmp(body->subtype, "RFC822") &&
        body->subpart->numparts) {
        subpart = body->subpart->subpart;
        body = body->subpart;
    }
    else {
        /* If a message/rfc822 contains a non-multipart,
           we don't care about part 0 (message header) */
        subpart = body->subpart;
        body = NULL;
    }

    if (!body) {
        /* skip header part */
        p += 5 * CACHE_ITEM_SIZE_SKIP;
        if (cache_version >= 5)
            p += MESSAGE_GUID_SIZE;
        if (cache_version >= 8)
            p += CACHE_ITEM_SIZE_SKIP;
        if (cache_version >= 9)
            p += CACHE_ITEM_SIZE_SKIP;
    }
    else {
        /* read header part */
        body->header_offset = CACHE_ITEM_BIT32(p);
        p += CACHE_ITEM_SIZE_SKIP;
        body->header_size = CACHE_ITEM_BIT32(p);
        p += CACHE_ITEM_SIZE_SKIP;
        body->content_offset = CACHE_ITEM_BIT32(p);
        p += CACHE_ITEM_SIZE_SKIP;
        body->content_size = CACHE_ITEM_BIT32(p);
        p += CACHE_ITEM_SIZE_SKIP;
        cte = CACHE_ITEM_BIT32(p);
        p += CACHE_ITEM_SIZE_SKIP;

        /* read encoding and charset identifier */
        /* Cache versions <= 3 store charset and encoding in 4 bytes,
         * but the code was broken. Just presume the charset unknown. */
        body->charset_enc = cte & 0xff;
        body->charset_id = NULL;
        if (cache_version >= 4) {
            /* determine the length of the charset identifer */
            len = (cte >> 16) & 0xffff;
            if (len) {
                /* XXX - assert (cte & 0xff00) == 0x100 */
                /* read len bytes as charset id */
                body->charset_id = xstrndup(p, len);
                p += len;
            }
        }
        if (cache_version >= 5)
            p = message_guid_import(&body->content_guid, p);

        if (cache_version >= 8) {
            body->decoded_content_size = CACHE_ITEM_BIT32(p);
            p += CACHE_ITEM_SIZE_SKIP;
        }
        if (cache_version >= 9) {
            body->content_lines = CACHE_ITEM_BIT32(p);
            p += CACHE_ITEM_SIZE_SKIP;
        }
    }

    /* read body parts */
    for (i = 0; i < n-1; i++) {
        subpart[i].header_offset = CACHE_ITEM_BIT32(p);
        p += CACHE_ITEM_SIZE_SKIP;
        subpart[i].header_size = CACHE_ITEM_BIT32(p);
        p += CACHE_ITEM_SIZE_SKIP;
        subpart[i].content_offset = CACHE_ITEM_BIT32(p);
        p += CACHE_ITEM_SIZE_SKIP;
        subpart[i].content_size = CACHE_ITEM_BIT32(p);
        p += CACHE_ITEM_SIZE_SKIP;
        cte = CACHE_ITEM_BIT32(p);
        p += CACHE_ITEM_SIZE_SKIP;

        /* read encoding and charset identifier */
        /* Cache versions <= 3 store charset and encoding in 4 bytes,
         * but the code was broken. Just presume the charset unknown. */
        subpart[i].charset_enc = cte & 0xff;
        subpart[i].charset_id = NULL;
        if (cache_version >= 4) {
            /* determine the length of the charset identifer */
            len = (cte >> 16) & 0xffff;
            if (len) {
                /* XXX - assert (cte & 0xff00) == 0x100 */
                /* read len bytes as charset id */
                subpart[i].charset_id = xstrndup(p, len);
                p += len;
            }
        }
        if (cache_version >= 5)
            p = message_guid_import(&subpart[i].content_guid, p);

        if (cache_version >= 8) {
            subpart[i].decoded_content_size = CACHE_ITEM_BIT32(p);
            p += CACHE_ITEM_SIZE_SKIP;
        }
        if (cache_version >= 9) {
            subpart[i].content_lines = CACHE_ITEM_BIT32(p);
            p += CACHE_ITEM_SIZE_SKIP;
        }
    }

    /* read sub-parts */
    for (*sect = p, i = 0; i < n-1; i++) {
        message_read_binarybody(&subpart[i], sect, cache_version);
    }
}

/*
 * Read cached envelope, binary bodystructure response and binary bodystructure
 * of the specified record.  Populates 'body' which must be freed by the caller.
 */
EXPORTED void message_read_bodystructure(const struct index_record *record, struct body **body)
{
    struct protstream *strm;
    struct body toplevel;
    const char *binbody;

    memset(&toplevel, 0, sizeof(struct body));
    toplevel.type = "MESSAGE";
    toplevel.subtype = "RFC822";
    toplevel.subpart = *body = xzmalloc(sizeof(struct body));

    /* Read envelope response from cache */
    strm = prot_readmap(cacheitem_base(record, CACHE_ENVELOPE),
                        cacheitem_size(record, CACHE_ENVELOPE));
    prot_setisclient(strm, 1);  /* no-sync literals */

    message_read_envelope(strm, *body);
    prot_free(strm);

    /* Read bodystructure response from cache */
    strm = prot_readmap(cacheitem_base(record, CACHE_BODYSTRUCTURE),
                        cacheitem_size(record, CACHE_BODYSTRUCTURE));
    prot_setisclient(strm, 1);  /* no-sync literals */

    message_read_body(strm, *body, NULL);
    prot_free(strm);

    /* Read binary bodystructure from cache */
    binbody = cacheitem_base(record, CACHE_SECTION);
    message_read_binarybody(&toplevel, &binbody, record->cache_version);
}

static void de_nstring_buf(struct buf *src, struct buf *dst)
{
    char *p, *q;

    if (src->s && src->len == 3 && !memcmp(src->s, "NIL", 3)) {
        buf_free(dst);
        return;
    }
    buf_cstring(src); /* ensure nstring parse doesn't overrun */
    q = src->s;
    p = parse_nstring(&q);
    buf_setmap(dst, p, q-p);
    buf_cstring(dst);
}

static void message1_get_subject(const struct index_record *record, struct buf *buf)
{
    struct buf tmp = BUF_INITIALIZER;
    buf_copy(&tmp, cacheitem_buf(record, CACHE_SUBJECT));
    de_nstring_buf(&tmp, buf);
    buf_free(&tmp);
}

/*
 * Generate a conversation id from the given message.
 * The conversation id is derived from the first 64b of
 * the SHA1 of the message, except that an all-zero
 * conversation id is not valid.
 */
static conversation_id_t generate_conversation_id(
                            const struct index_record *record)
{
    conversation_id_t cid = 0;
    size_t i;

    assert(record->guid.status == GUID_NONNULL);

    for (i = 0 ; i < sizeof(cid) ; i++) {
        cid <<= 8;
        cid |= record->guid.value[i];
    }

    // we make sure the cid doesn't look anything like the sha1 so
    // that people don't make assumptions
    cid ^= 0x91f3d9e10b690b12; // chosen by fair dice roll

    /*
     * We carefully avoid returning NULLCONVERSATION as
     * a new cid, as that would confuse matters no end.
     */
    if (cid == NULLCONVERSATION)
        cid = 1;

    return cid;
}

/*
 * In RFC 2822, the In-Reply-To field is explicitly required to contain
 * only message-ids, whitespace and commas.  The old RFC 822 was less
 * well specified and allowed all sorts of stuff.  We used to be equally
 * liberal here in parsing the field.  Sadly some versions of the NMH
 * mailer will generate In-Reply-To containing email addresses which we
 * cannot tell from message-ids, leading to massively confused
 * threading.  So we have to be slightly stricter.
 */
static int is_valid_rfc2822_inreplyto(const char *p)
{
    if (!p)
        return 1;

    /* skip any whitespace */
    while (*p && (isspace(*p) || *p == ','))
        p++;

    return (!*p || *p == '<');
}

/* XXX - refactor this whole thing to an "open or create" API */
static int getconvmailbox(const char *mboxname, struct mailbox **mailboxptr)
{
    int r = mailbox_open_iwl(mboxname, mailboxptr);
    if (r != IMAP_MAILBOX_NONEXISTENT) return r;

    struct mboxlock *namespacelock = mboxname_usernamespacelock(mboxname);

    // try again - maybe we lost the race!
    r = mailbox_open_iwl(mboxname, mailboxptr);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* create the mailbox - it's OK to do as admin because this only ever gets
         * a user subfolder for this conversations.db owner */
        r = mboxlist_createmailbox(mboxname, MBTYPE_COLLECTION, NULL, 1 /* admin */, NULL, NULL,
                                   0, 0, 0, 0, mailboxptr);
    }

    mboxname_release(&namespacelock);

    return r;
}

/*
 * This is the legacy code version to generate conversation subjects.
 * We keep it here to allow matching messages to conversations that
 * already got that oldstyle subject set.
 */
/*
 * Normalise a subject string, to a form which can be used for deciding
 * whether a message belongs in the same conversation as it's antecedent
 * messages.  What we're doing here is the same idea as the "base
 * subject" algorithm described in RFC 5256 but slightly adapted from
 * experience.  Differences are:
 *
 *  - We eliminate all whitespace; RFC 5256 normalises any sequence
 *    of whitespace characters to a single SP.  We do this because
 *    we have observed combinations of buggy client software both
 *    add and remove whitespace around folding points.
 *
 *  - We include the Unicode U+00A0 (non-breaking space) codepoint in our
 *    determination of whitespace (as the UTF-8 sequence \xC2\xA0) because
 *    we have seen it in the wild, but do not currently generalise this to
 *    other Unicode "whitespace" codepoints. (XXX)
 *
 *  - Because we eliminate whitespace entirely, and whitespace helps
 *    delimit some of our other replacements, we do that whitespace
 *    step last instead of first.
 *
 *  - We eliminate leading tokens like Re: and Fwd: using a simpler
 *    and more generic rule than RFC 5256's; this rule catches a number
 *    of semantically identical prefixes in other human languages, but
 *    unfortunately also catches lots of other things.  We think we can
 *    get away with this because the normalised subject is never directly
 *    seen by human eyes, so some information loss is acceptable as long
 *    as the subjects in different messages match correctly.
 *
 *  - We eliminate trailing tokens like [SEC=UNCLASSIFIED],
 *    [DLM=Sensitive], etc which are automatically added by Australian
 *    Government department email systems.  In theory there should be no
 *    more than one of these on an email subject but in practice multiple
 *    have been seen.
 *    http://www.finance.gov.au/files/2012/04/EPMS2012.3.pdf
 */
static void oldstyle_normalise_subject(struct buf *s)
{
    static int initialised_res = 0;
    static regex_t whitespace_re;
    static regex_t relike_token_re;
    static regex_t blob_start_re;
    static regex_t blob_end_re;
    int r;

    if (!initialised_res) {
        r = regcomp(&whitespace_re, "([ \t\r\n]+|\xC2\xA0)", REG_EXTENDED);
        assert(r == 0);
        r = regcomp(&relike_token_re, "^[ \t]*[A-Za-z0-9]+(\\[[0-9]+\\])?:", REG_EXTENDED);
        assert(r == 0);
        r = regcomp(&blob_start_re, "^[ \t]*\\[[^]]+\\]", REG_EXTENDED);
        assert(r == 0);
        r = regcomp(&blob_end_re, "\\[(SEC|DLM)=[^]]+\\][ \t]*$", REG_EXTENDED);
        assert(r == 0);
        initialised_res = 1;
    }

    /* step 1 is to decode any RFC 2047 MIME encoding of the header
     * field, but we assume that has already happened */

    /* step 2 is to eliminate all "Re:"-like tokens and [] blobs
     * at the start, and AusGov [] blobs at the end */
    while (buf_replace_one_re(s, &relike_token_re, NULL) ||
           buf_replace_one_re(s, &blob_start_re, NULL) ||
           buf_replace_one_re(s, &blob_end_re, NULL))
        ;

    /* step 3 is eliminating whitespace. */
    buf_replace_all_re(s, &whitespace_re, NULL);
}

static void extract_convsubject(const struct index_record *record,
                                struct buf *msubject,
                                void (*normalise)(struct buf*))
{
    if (cacheitem_base(record, CACHE_HEADERS)) {
        message1_get_subject(record, msubject);
        normalise(msubject);
    }
}

EXPORTED char *message_extract_convsubject(const struct index_record *record)
{
    if (cacheitem_base(record, CACHE_HEADERS)) {
        struct buf msubject = BUF_INITIALIZER;
        extract_convsubject(record, &msubject, conversation_normalise_subject);
        return buf_release(&msubject);
    }
    return NULL;
}

/*
 * Update the conversations database for the given
 * mailbox, to account for the given message.
 * @body may be NULL, in which case we get everything
 * we need out of the cache item in @record.
 */
EXPORTED int message_update_conversations(struct conversations_state *state,
                                          struct mailbox *mailbox,
                                          struct index_record *record,
                                          conversation_t **convp)
{
    char *hdrs[4];
    char *c_refs = NULL, *c_env = NULL, *c_me_msgid = NULL;
    strarray_t msgidlist = STRARRAY_INITIALIZER;
    arrayu64_t matchlist = ARRAYU64_INITIALIZER;
    arrayu64_t cids = ARRAYU64_INITIALIZER;
    int mustkeep = 0;
    conversation_t *conv = NULL;
    char *msubj = NULL;
    char *msubj_oldstyle = NULL;
    int i;
    size_t j;
    int r = 0;
    struct mailbox *local_mailbox = NULL;

    /*
     * Gather all the msgids mentioned in the message, starting with
     * the oldest message in the References: header, then any mesgids
     * mentioned in the In-Reply-To: header, and finally the message's
     * own Message-Id:.  In general this will result in duplicates (a
     * correct References: header will contain as its last entry the
     * msgid in In-Reply-To:), so we weed those out before proceeding
     * to the database.
     */
    if (cacheitem_base(record, CACHE_HEADERS)) {
        /* we have cache loaded, get what we need there */
        strarray_t want = STRARRAY_INITIALIZER;
        char *envtokens[NUMENVTOKENS];

        /* get References from cached headers */
        c_refs = xstrndup(cacheitem_base(record, CACHE_HEADERS),
                          cacheitem_size(record, CACHE_HEADERS));
        strarray_append(&want, "references");
        message_pruneheader(c_refs, &want, 0);
        hdrs[0] = c_refs;

        /* get In-Reply-To, Message-ID out of the envelope
         *
         * get a working copy; strip outer ()'s
         * +1 -> skip the leading paren
         * -2 -> don't include the size of the outer parens
         */
        c_env = xstrndup(cacheitem_base(record, CACHE_ENVELOPE) + 1,
                         cacheitem_size(record, CACHE_ENVELOPE) - 2);
        parse_cached_envelope(c_env, envtokens, NUMENVTOKENS);
        hdrs[1] = envtokens[ENV_INREPLYTO];
        hdrs[2] = envtokens[ENV_MSGID];

        /* get X-ME-Message-ID from cached headers */
        c_me_msgid = xstrndup(cacheitem_base(record, CACHE_HEADERS),
                              cacheitem_size(record, CACHE_HEADERS));
        strarray_set(&want, 0, "x-me-message-id");
        message_pruneheader(c_me_msgid, &want, 0);
        hdrs[3] = c_me_msgid;

        strarray_fini(&want);

        /* work around stupid message_guid API */
        message_guid_isnull(&record->guid);
    }
    else {
        /* nope, now we're screwed */
        return IMAP_INTERNAL;
    }

    if (!is_valid_rfc2822_inreplyto(hdrs[1]))
        hdrs[1] = NULL;

    /* Note that a NULL subject, e.g. due to a missing Subject: header
     * field in the original message, is normalised to "" not NULL */
    if (cacheitem_base(record, CACHE_HEADERS)) {
        struct buf msubject = BUF_INITIALIZER;
        extract_convsubject(record, &msubject, conversation_normalise_subject);
        msubj = xstrdup(buf_cstring(&msubject));
        buf_reset(&msubject);
        extract_convsubject(record, &msubject, oldstyle_normalise_subject);
        msubj_oldstyle = buf_release(&msubject);
    }

    for (i = 0 ; i < 4 ; i++) {
        int hcount = 0;
        char *msgid = NULL;
        while ((msgid = find_msgid(hdrs[i], &hdrs[i])) != NULL) {
            hcount++;
            if (hcount > 20) {
                free(msgid);
                syslog(LOG_DEBUG, "too many references, skipping the rest");
                break;
            }
            /*
             * The issue of case sensitivity of msgids is curious.
             * RFC 2822 seems to imply they're case-insensitive,
             * without explicitly stating so.  So here we punt
             * on that being the case.
             *
             * Note that the THREAD command elsewhere in Cyrus
             * assumes otherwise.
             */
            msgid = lcase(msgid);

            /* already seen this one? */
            if (strarray_find(&msgidlist, msgid, 0) >= 0) {
                free(msgid);
                continue;
            }

            /* won't be accepted as valid, ignore it! */
            if (conversations_check_msgid(msgid, strlen(msgid))) {
                free(msgid);
                continue;
            }

            strarray_appendm(&msgidlist, msgid);

            /* Lookup the conversations database to work out which
             * conversation ids that message belongs to. */
            r = conversations_get_msgid(state, msgid, &cids);
            if (r) goto out;

            for (j = 0; j < cids.count; j++) {
                conversation_id_t cid = arrayu64_nth(&cids, j);
                conversation_free(conv);
                conv = NULL;
                r = conversation_load(state, cid, &conv);
                if (r) goto out;
                /* [IRIS-1576] if X-ME-Message-ID says the messages are
                * linked, ignore any difference in Subject: header fields. */
                if (!conv || i == 3 || !conv->subject ||
                        !strcmpsafe(conv->subject, msubj) ||
                        !strcmpsafe(conv->subject, msubj_oldstyle)) {
                    arrayu64_add(&matchlist, cid);
                }
            }

            conversation_free(conv);
            conv = NULL;
        }
    }

    /* calculate the CID if needed */
    if (!record->silentupdate) {
        /* match for GUID, it always has the same CID */
        conversation_id_t currentcid = conversations_guid_cid_lookup(state, message_guid_encode(&record->guid));
        if (currentcid) {
            // would love to have this, but might hit bogus broken existing data...
            // assert(record->cid == 0 || record->cid == currentcid);
            record->cid = currentcid;
            mustkeep = 1;
        }
        if (!record->cid) record->cid = arrayu64_max(&matchlist);
        if (!record->cid) {
            record->cid = generate_conversation_id(record);
            if (record->cid) mustkeep = 1;
        }
        if (!mustkeep && !record->basecid) {
            /* try finding a CID in the match list, or if we came in with it */
            struct buf annotkey = BUF_INITIALIZER;
            struct buf annotval = BUF_INITIALIZER;
            buf_printf(&annotkey, "%snewcid/%016llx", IMAP_ANNOT_NS, record->cid);
            r = annotatemore_lookup(state->annotmboxname, buf_cstring(&annotkey), "", &annotval);
            if (annotval.len == 16) {
                const char *p = buf_cstring(&annotval);
                /* we have a new canonical CID */
                record->basecid = record->cid;
                r = parsehex(p, &p, 16, &record->cid);
            }
            else {
                r = 0; /* we're just going to pretend this wasn't found, worst case we split
                        * more than we should */
            }
            buf_free(&annotkey);
            buf_free(&annotval);
            if (r) goto out;
        }
    }

    if (!record->cid) goto out;
    if (!record->basecid) record->basecid = record->cid;

    r = conversation_load(state, record->cid, &conv);
    if (r) goto out;

    if (!conv) conv = conversation_new();

    uint32_t max_thread = config_getint(IMAPOPT_CONVERSATIONS_MAX_THREAD);
    if (conv->exists >= max_thread && !mustkeep && !record->silentupdate) {
        /* time to reset the conversation */
        conversation_id_t was = record->cid;
        record->cid = generate_conversation_id(record);

        syslog(LOG_NOTICE, "splitting conversation for %s %u base:%016llx was:%016llx now:%016llx",
               mailbox_name(mailbox), record->uid, record->basecid, was, record->cid);

        if (!record->basecid) record->basecid = was;

        conversation_free(conv);
        r = conversation_load(state, record->cid, &conv);
        if (r) goto out;
        if (!conv) conv = conversation_new();

        /* and update the pointer for next time */
        if (strcmpsafe(state->annotmboxname, mailbox_name(mailbox))) {
            r = getconvmailbox(state->annotmboxname, &local_mailbox);
            if (r) goto out;
            mailbox = local_mailbox;
        }

        struct annotate_state *astate = NULL;
        r = mailbox_get_annotate_state(mailbox, 0, &astate);
        if (r) goto out;

        struct buf annotkey = BUF_INITIALIZER;
        struct buf annotval = BUF_INITIALIZER;
        buf_printf(&annotkey, "%snewcid/%016llx", IMAP_ANNOT_NS, record->basecid);
        buf_printf(&annotval, "%016llx", record->cid);
        r = annotate_state_write(astate, buf_cstring(&annotkey), "", &annotval);
        buf_free(&annotkey);
        buf_free(&annotval);
        if (r) goto out;
    }

    /* Create the subject header if not already set and this isn't a Draft */
    if (!conv->subject && !(record->system_flags & FLAG_DRAFT))
        conv->subject = xstrdupnull(msubj);

    /*
     * Update the database to add records for all the message-ids
     * not already mentioned.  Note that add_msgid does the right
     * thing[tm] when the cid already exists.
     */

    for (i = 0 ; i < msgidlist.count ; i++) {
        r = conversations_add_msgid(state, strarray_nth(&msgidlist, i), record->basecid);
        if (r) goto out;
    }

    /* mark that it's split so basecid gets saved */
    if (record->basecid != record->cid)
        record->internal_flags |= FLAG_INTERNAL_SPLITCONVERSATION;

out:
    strarray_fini(&msgidlist);
    arrayu64_fini(&matchlist);
    arrayu64_fini(&cids);
    free(c_refs);
    free(c_env);
    free(c_me_msgid);
    free(msubj);
    free(msubj_oldstyle);
    if (local_mailbox)
        mailbox_close(&local_mailbox);

    if (r)
        conversation_free(conv);
    else if (convp)
        *convp = conv;
    else {
        r = conversation_save(state, record->cid, conv);
        conversation_free(conv);
    }

    return r;
}


/*
  Format of the CACHE_SECTION cache item is a binary encoding
  tree of MIME sections.  In something like rpcgen notation
  (see RFC 4506):

    struct part {
        uint32_t header_offset;
        uint32_t header_size;
        uint32_t content_offset;
        uint32_t content_size;

        uint32_t encoding & 0x100 & (len << 16)
                 length of charset identifier in bytes (=len)
        uint8_t[len] charset identifier
    };

    struct section {
        unsigned int numparts;
        struct part parts[numparts];
        struct section[numparts-1];
    };
*/

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

EXPORTED message_t *message_new(void)
{
    message_t *m = xzmalloc(sizeof(*m));

    m->refcount = 1;

    return m;
}

static void message_free(message_t *m)
{
    assert(m->refcount == 0);

    message_yield(m, M_ALL);

    free(m);
}

EXPORTED void message_set_from_data(const char *base, size_t len, message_t *m)
{
    assert(m->refcount == 1);
    message_yield(m, M_ALL);
    memset(m, 0, sizeof(message_t));
    buf_init_ro(&m->map, base, len);
    m->have = m->given = M_MAP;
    m->refcount = 1;
}

EXPORTED message_t *message_new_from_data(const char *base, size_t len)
{
    message_t *m = message_new();
    buf_init_ro(&m->map, base, len);
    m->have = m->given = M_MAP;
    return m;
}

EXPORTED void message_set_from_mailbox(struct mailbox *mailbox, unsigned int recno, message_t *m)
{
    assert(m->refcount == 1);
    message_yield(m, M_ALL);
    memset(m, 0, sizeof(message_t));
    m->mailbox = mailbox;
    m->record.recno = recno;
    m->have = m->given = M_MAILBOX;
    m->refcount = 1;
}

EXPORTED message_t *message_new_from_mailbox(struct mailbox *mailbox, unsigned int recno)
{
    message_t *m = message_new();
    m->mailbox = mailbox;
    m->record.recno = recno;
    m->have = m->given = M_MAILBOX;
    return m;
}

EXPORTED void message_set_from_record(struct mailbox *mailbox,
                                      const struct index_record *record,
                                      message_t *m)
{
    assert(m->refcount == 1);
    message_yield(m, M_ALL);
    memset(m, 0, sizeof(message_t));
    assert(record->uid > 0);
    m->mailbox = mailbox;
    m->record = *record;
    m->have = m->given = M_MAILBOX|M_RECORD|M_UID;
    m->refcount = 1;
}

EXPORTED message_t *message_new_from_record(struct mailbox *mailbox,
                                            const struct index_record *record)
{
    message_t *m = message_new();
    assert(record->uid > 0);
    m->mailbox = mailbox;
    m->record = *record;
    m->have = m->given = M_MAILBOX|M_RECORD|M_UID;
    return m;
}

EXPORTED void message_set_from_index(struct mailbox *mailbox,
                                     const struct index_record *record,
                                     uint32_t msgno,
                                     uint32_t indexflags,
                                     message_t *m)
{
    assert(m->refcount == 1);
    message_yield(m, M_ALL);
    memset(m, 0, sizeof(message_t));
    assert(record->uid > 0);
    m->mailbox = mailbox;
    m->record = *record;
    m->msgno = msgno;
    m->indexflags = indexflags;
    m->have = m->given = M_MAILBOX|M_RECORD|M_UID|M_INDEX;
    m->refcount = 1;
}

EXPORTED message_t *message_new_from_index(struct mailbox *mailbox,
                                           const struct index_record *record,
                                           uint32_t msgno,
                                           uint32_t indexflags)
{
    message_t *m = message_new();
    assert(record->uid > 0);
    m->mailbox = mailbox;
    m->record = *record;
    m->msgno = msgno;
    m->indexflags = indexflags;
    m->have = m->given = M_MAILBOX|M_RECORD|M_UID|M_INDEX;
    return m;
}

EXPORTED message_t *message_new_from_filename(const char *filename)
{
    message_t *m = message_new();
    m->filename = xstrdup(filename);
    m->have = m->given = M_FILENAME;
    return m;
}

EXPORTED message_t *message_ref(message_t *m)
{
    m->refcount++;
    assert(m->refcount >= 1);
    return m;
}

EXPORTED void message_unref(message_t **mp)
{
    message_t *m;

    if (!mp || !(m = *mp)) return;
    assert(m->refcount >= 1);
    if (--m->refcount == 0)
        message_free(m);
    *mp = NULL;
}

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

/*
 * Open or create resources which we need but do not yet have.
 */
static int message_need(const message_t *cm, unsigned int need)
{
#define is_missing(flags)    ((need & ~(m->have)) & (flags))
#define found(flags)         (m->have |= (flags))
    int r = 0;
    message_t *m = (message_t *)cm;

    if (!is_missing(M_ALL))
        return 0;       /* easy, we already have it */

    if (is_missing(M_MAILBOX)) {
        /* We can't get this for ourselves,
         * it needs to be passed in by the caller */
        return IMAP_NOTFOUND;
    }

    if (is_missing(M_FILENAME)) {
        const char *filename;
        r = message_need(m, M_MAILBOX|M_RECORD);
        if (r) return r;
        filename = mailbox_record_fname(m->mailbox, &m->record);
        if (!filename) return IMAP_NOTFOUND;
        m->filename = xstrdup(filename);
        found(M_FILENAME);
    }

    if (is_missing(M_RECORD|M_UID)) {
        r = message_need(m, M_MAILBOX);
        if (r) return r;
        r = mailbox_reload_index_record(m->mailbox, &m->record);
        if (r) return r;
        found(M_RECORD|M_UID);
    }

    if (is_missing(M_MAP)) {
        r = message_need(m, M_FILENAME);
        if (r) return r;
        r = message_map_file(m, m->filename);
        if (r) return r;
        found(M_MAP);
    }

    if (is_missing(M_CACHE)) {
        r = message_need(m, M_MAILBOX|M_RECORD);
        if (r) return r;
        r = mailbox_cacherecord(m->mailbox, &m->record);
        if (r) return r;
        found(M_CACHE);
    }

    if (is_missing(M_CACHEBODY)) {
        if (message_need(m, M_CACHE) == 0) {
            r = message_parse_cbodystructure(m);
            if (r) return r;
            found(M_CACHEBODY);
        }
        else
            return message_need(m, M_FULLBODY);
    }

    if (is_missing(M_FULLBODY)) {
        r = message_need(m, M_MAP);
        if (r) return r;
        m->body = (struct body *)xzmalloc(sizeof(struct body));
        r = message_parse_mapped(m->map.s, m->map.len, m->body, NULL);
        if (r) return r;
        found(M_CACHEBODY|M_FULLBODY);
    }

    /* Check that we got everything we asked for and could get */
    assert(!is_missing(M_ALL));

    return 0;
#undef found
#undef is_missing
}

/*
 * Yield open resources.
 */
static void message_yield(message_t *m, unsigned int yield)
{
    /* Can only yield those resources we have. */
    yield &= m->have;

    /* Do not yield resources we were given at initialisation
     * time, they cannot be rebuilt again later. */
    yield &= ~m->given;

    /* nothing to free for these - they're not constructed
     * or have no dynamically allocated memory */
    yield &= ~(M_MAILBOX|M_RECORD|M_UID|M_CACHE);

    if ((yield & M_MAP)) {
        buf_free(&m->map);
        m->have &= ~M_MAP;
    }

    if ((yield & M_BODY)) {
        message_free_body(m->body);
        free(m->body);
        m->body = NULL;
        m->have &= ~M_BODY;
    }

    if ((yield & M_FILENAME)) {
        free(m->filename);
        m->filename = NULL;
        m->have &= ~M_FILENAME;
    }

    /* Check we yielded everything we could */
    assert((yield & m->have) == 0);
}

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

/*
 * Parse various information out of the cyrus.cache.
 */

/*
 * Skip either a single NIL or a balanced possibly-nested list of
 * nstrings.  Useful for ignoring various constructs from the
 * BODYSTRUCTURE cache.
 */
static int skip_nil_or_nstring_list(struct protstream *prot)
{
    int r = IMAP_MAILBOX_BADFORMAT;
    int c;
    struct buf word = BUF_INITIALIZER;

    c = prot_getc(prot);
    if (c == EOF)
        goto out;   /* ran out of data */
    if (c == '(') {
        /* possibly-nested list of atoms */
        int treedepth = 1;
        do {
            c = prot_getc(prot);
            if (c == ' ')
                c = prot_getc(prot);
            if (c != ')' && c != '(') {
                prot_ungetc(c, prot);
                c = getnstring(prot, NULL, &word);
#if DEBUG
                if (word.len)
                    fprintf(stderr, "%sskipping string \"%s\" at %d\n",
                            indent(depth), word.s, treedepth);
#endif
            }
            if (c == '(')
                treedepth++;
            else if (c == ')')
                treedepth--;
            else if (c == ' ')
                prot_ungetc(c, prot);
            else
                goto out;
        } while (treedepth);
        c = prot_getc(prot);
        if (c != ' ') goto out;
        r = 0;
    }
    else {
        prot_ungetc(c, prot);
        c = getnstring(prot, NULL, &word);
        if (c == ' ' && !word.len) {
            /* 'NIL' */
#if DEBUG
            fprintf(stderr, "%sskipping NIL\n", indent(depth));
#endif
            r = 0;
            goto out;
        }
    }
    /* else, error */

out:
    buf_free(&word);
    return r;
}

static int parse_mime_params(struct protstream *prot, struct param **prev)
{
    int c;
    struct buf key = BUF_INITIALIZER;
    struct buf val = BUF_INITIALIZER;
    struct param *param;

    c = prot_getc(prot);
    if (c != '(') {
        /* must be NIL */
        if (c != 'N') goto err;
        c = prot_getc(prot);
        if (c != 'I') goto err;
        c = prot_getc(prot);
        if (c != 'L') goto err;
        return prot_getc(prot);
    }

    /* otherwise we have a list */
    do {
        c = getnstring(prot, NULL, &key);
        if (c != ' ') goto err;
        c = getnstring(prot, NULL, &val);
        if (c != ' ' && c != ')') goto err;
        param = (struct param *)xzmalloc(sizeof(struct param));
        param->attribute = buf_releasenull(&key);
        param->value = buf_releasenull(&val);
        *prev = param;
        prev = &param->next;
    } while (c == ' ');

    return prot_getc(prot);

err:
    buf_free(&key);
    buf_free(&val);
    return EOF;
}

static int parse_bodystructure_part(struct protstream *prot, struct body *body, const char *part_id)
{
    int c;
    int r = 0;
    struct buf buf = BUF_INITIALIZER;

    memset(body, 0, sizeof(struct body));

    c = prot_getc(prot);
    if (c != '(') {
badformat:
        r = IMAP_MAILBOX_BADFORMAT;
        goto out;
    }

    c = prot_getc(prot);
    prot_ungetc(c, prot);
    if (c == '(') {
        while (c == '(') {
            body->numparts++;
            body->subpart = (struct body *)xrealloc((char *)body->subpart,
                                          body->numparts*sizeof(struct body));

            buf_reset(&buf);
            if (part_id) buf_printf(&buf, "%s.", part_id);
            buf_printf(&buf, "%d", body->numparts);
            char *part_id = buf_release(&buf);
            struct body *subbody = &body->subpart[body->numparts-1];
            r = parse_bodystructure_part(prot, subbody, part_id);
            subbody->part_id = part_id;
            if (r) goto out;

            c = prot_getc(prot);
            prot_ungetc(c, prot);
        }

        c = prot_getc(prot);
        if (c != ' ') goto badformat;

        body->type = xstrdup("MULTIPART");
    }
    else {
        /* parse mime-type */
        c = getnstring(prot, NULL, &buf);
        if (c != ' ') goto badformat;

        body->type = buf_releasenull(&buf);
    }

    /* parse mime-subtype */
    c = getnstring(prot, NULL, &buf);
    if (c != ' ') goto badformat;
    body->subtype = buf_releasenull(&buf);

    /* parse mime-params */
    c = parse_mime_params(prot, &body->params);
    if (c != ' ') goto badformat;

    if (strcmp(body->type, "MULTIPART")) {
        /* msgid */
        c = getnstring(prot, NULL, &buf);
        if (c != ' ') goto badformat;
        body->message_id = buf_releasenull(&buf);

        /* description */
        c = getnstring(prot, NULL, &buf);
        if (c != ' ') goto badformat;
        body->description = buf_releasenull(&buf);

        /* encoding */
        c = getnstring(prot, NULL, &buf);
        if (c != ' ') goto badformat;
        body->encoding = buf_releasenull(&buf);

        /* content-size */
        c = getword(prot, &buf);
        if (c != ' ') goto badformat;
        body->content_size = atoi(buf_cstring(&buf));

        if (!strcmpsafe(body->type, "TEXT")) {
            /* parse content-lines */
            c = getword(prot, &buf);
            if (c != ' ') goto badformat;
            body->content_lines = atoi(buf_cstring(&buf));
        }

        else if (!strcmpsafe(body->type, "MESSAGE") &&
                 !strcmpsafe(body->subtype, "RFC822")) {
            body->numparts = 1;
            body->subpart = xzmalloc(sizeof(struct body));

            /* skip envelope */
            r = skip_nil_or_nstring_list(prot);
            if (r) goto out;

            /* process body */
            r = parse_bodystructure_part(prot, body->subpart, part_id);
            if (r) goto out;

            /* skip trailing space (parse_bs_part doesn't eat it) */
            c = prot_getc(prot);
            if (c != ' ') goto badformat;

            /* parse content-lines */
            c = getword(prot, &buf);
            if (c != ' ') goto badformat;
            body->content_lines = atoi(buf_cstring(&buf));
        }

        /* parse md5sum */
        c = getnstring(prot, NULL, &buf);
        if (c != ' ') goto badformat;
        body->md5 = buf_releasenull(&buf);
    }

    /* skips disposition-and-params */
    r = skip_nil_or_nstring_list(prot);
    if (r) goto out;

    /* parse languages */  /* TODO */
    r = skip_nil_or_nstring_list(prot);
    if (r) goto out;

    /* location */
    c = getnstring(prot, NULL, &buf);
    if (c != ')') goto badformat; /* final field */
    body->location = buf_releasenull(&buf);

    r = 0;
out:
    buf_free(&buf);
    return r;
}

static int parse_bodystructure_sections(const char **cachestrp, const char *cacheend,
                                        struct body *body, uint32_t cache_version,
                                        const char *part_id)
{
    struct body *this;
    int nsubparts;
    int part;
    uint32_t cte;
    struct buf buf = BUF_INITIALIZER;
    int r = 0;

    if (*cachestrp + 4 > cacheend) {
        r = IMAP_MAILBOX_BADFORMAT;
        goto done;
    }

    nsubparts = CACHE_ITEM_BIT32(*cachestrp);
    *cachestrp += 4;

    /* XXX - this size needs increasing for charset sizes and sha1s depending on version,
     * it won't crash, but it may overrun while reading */
    if (*cachestrp + 4*5*nsubparts > cacheend) {
        r = IMAP_MAILBOX_BADFORMAT;
        goto done;
    }

    if (strcmp(body->type, "MESSAGE") == 0
        && strcmp(body->subtype, "RFC822") == 0) {

        if (strcmp(body->subpart->type, "MULTIPART") == 0) {

            /*
             * Part 0 of a message/rfc822 is the message header/text.
             * Nested parts of a message/rfc822 containing a multipart
             * are the sub-parts of the multipart.
             */
            if (body->subpart->numparts + 1 != nsubparts) {
                r = IMAP_MAILBOX_BADFORMAT;
                goto done;
            }

            body->subpart->header_offset = CACHE_ITEM_BIT32(*cachestrp+0*4);
            body->subpart->header_size = CACHE_ITEM_BIT32(*cachestrp+1*4);
            body->subpart->content_offset = CACHE_ITEM_BIT32(*cachestrp+2*4);
            body->subpart->content_size = CACHE_ITEM_BIT32(*cachestrp+3*4);
            // skip cte
            *cachestrp += 5*4;

            if (cache_version >= 5)
                *cachestrp = message_guid_import(&body->subpart->content_guid, *cachestrp);

            if (cache_version >= 8) {
                body->subpart->decoded_content_size = CACHE_ITEM_BIT32(*cachestrp);
                *cachestrp += CACHE_ITEM_SIZE_SKIP;
            }

            if (cache_version >= 9) {
                body->subpart->content_lines = CACHE_ITEM_BIT32(*cachestrp);
                *cachestrp += CACHE_ITEM_SIZE_SKIP;
            }

            for (part = 0; part < body->subpart->numparts; part++) {
                this = &body->subpart->subpart[part];
                this->header_offset = CACHE_ITEM_BIT32(*cachestrp+0*4);
                this->header_size = CACHE_ITEM_BIT32(*cachestrp+1*4);
                this->content_offset = CACHE_ITEM_BIT32(*cachestrp+2*4);
                this->content_size = CACHE_ITEM_BIT32(*cachestrp+3*4);
                cte = CACHE_ITEM_BIT32(*cachestrp+4*4);
                *cachestrp += 5*4;

                /* XXX CACHE_MINOR_VERSION 4 replaces numeric charset
                 * identifiers with variable-length strings. Remove
                 * this conditional once cache versions <= 3 are
                 * deprecated */
                if (cache_version >= 4)
                    *cachestrp += (cte >> 16) & 0xffff;

                /* CACHE_MINOR_VERSION 5 adds a sha1 after the charset */
                if (cache_version >= 5)
                    *cachestrp = message_guid_import(&this->content_guid, *cachestrp);

                /* CACHE_MINOR_VERSION 8 adds the decoded content size after sha1 */
                if (cache_version >= 8) {
                    this->decoded_content_size = CACHE_ITEM_BIT32(*cachestrp);
                    *cachestrp += CACHE_ITEM_SIZE_SKIP;
                }

                /* CACHE_MINOR_VERSION 9 adds the number of content lines after the decoded size */
                if (cache_version >= 9) {
                    this->content_lines = CACHE_ITEM_BIT32(*cachestrp);
                    *cachestrp += CACHE_ITEM_SIZE_SKIP;
                }
            }

            /* and parse subparts */
            for (part = 0; part < body->subpart->numparts; part++) {
                this = &body->subpart->subpart[part];
                buf_reset(&buf);
                if (part_id) buf_printf(&buf, "%s.", part_id);
                buf_printf(&buf, "%d", part + 1);
                if (parse_bodystructure_sections(cachestrp, cacheend, this, cache_version, buf_cstring(&buf))) {
                    r = IMAP_MAILBOX_BADFORMAT;
                    goto done;
                }
            }
        }
        else {
            /*
             * Part 0 of a message/rfc822 is the message header/text.
             * Part 1 of a message/rfc822 containing a non-multipart
             * is the message body.
             */

            if (2 != nsubparts) {
                r = IMAP_MAILBOX_BADFORMAT;
                goto done;
            }

            /* data is the same in body, just grab the first one */
            body->subpart->header_offset = CACHE_ITEM_BIT32(*cachestrp+0*4);
            body->subpart->header_size = CACHE_ITEM_BIT32(*cachestrp+1*4);
            body->subpart->content_offset = CACHE_ITEM_BIT32(*cachestrp+2*4);
            body->subpart->content_size = CACHE_ITEM_BIT32(*cachestrp+3*4);
            // skip cte
            *cachestrp += 5*4;
            if (cache_version >= 5)
                *cachestrp += MESSAGE_GUID_SIZE;
            if (cache_version >= 8)
                *cachestrp += 1*4;
            if (cache_version >= 9)
                *cachestrp += 1*4;
            *cachestrp += 4*4;

            if (strcmp(body->subpart->type, "MULTIPART") == 0) {
                /* Treat 0-part multipart as 0-length text */
                *cachestrp += 1*4;
            }
            else {
                /* Skip charset/encoding identifiers. */
                cte = CACHE_ITEM_BIT32(*cachestrp);
                *cachestrp += 1*4;
                /* XXX CACHE_MINOR_VERSION 4 replaces numeric charset
                 * identifiers with variable-length strings. Remove
                 * this conditional once cache versions <= 3 are
                 * deprecated */
                if (cache_version >= 4)
                    *cachestrp += (cte >> 16) & 0xffff;

                if (!body->subpart->part_id) {
                    buf_reset(&buf);
                    if (part_id) buf_printf(&buf, "%s.", part_id);
                    buf_printf(&buf, "%d", 1);
                    body->subpart->part_id = buf_release(&buf);
                }
            }
            /* CACHE_MINOR_VERSION 5 adds a sha1 after the charset */
            if (cache_version >= 5)
                *cachestrp = message_guid_import(&body->subpart->content_guid, *cachestrp);

            if (cache_version >= 8) {
                body->subpart->decoded_content_size = CACHE_ITEM_BIT32(*cachestrp);
                *cachestrp += CACHE_ITEM_SIZE_SKIP;
            }

            if (cache_version >= 9) {
                body->subpart->content_lines = CACHE_ITEM_BIT32(*cachestrp);
                *cachestrp += CACHE_ITEM_SIZE_SKIP;
            }

            /* and parse subpart */
            if (parse_bodystructure_sections(cachestrp, cacheend, body->subpart, cache_version, body->part_id)) {
                r = IMAP_MAILBOX_BADFORMAT;
                goto done;
            }
        }
    }
    else if (body->numparts) {
        /*
         * Cannot fetch part 0 of a multipart.
         * Nested parts of a multipart are the sub-parts.
         */
        if (body->numparts + 1 != nsubparts) {
            r = IMAP_MAILBOX_BADFORMAT;
            goto done;
        }
        *cachestrp += 5*4;
        if (cache_version >= 5)
            *cachestrp += MESSAGE_GUID_SIZE;
        if (cache_version >= 8)
            *cachestrp += 4;
        if (cache_version >= 9)
            *cachestrp += 4;
        for (part = 0; part < body->numparts; part++) {
            this = &body->subpart[part];
            this->header_offset = CACHE_ITEM_BIT32(*cachestrp+0*4);
            this->header_size = CACHE_ITEM_BIT32(*cachestrp+1*4);
            this->content_offset = CACHE_ITEM_BIT32(*cachestrp+2*4);
            this->content_size = CACHE_ITEM_BIT32(*cachestrp+3*4);
            cte = CACHE_ITEM_BIT32(*cachestrp+4*4);
            *cachestrp += 5*4;

            if (cache_version >= 4)
                *cachestrp += (cte >> 16) & 0xffff;

            if (cache_version >= 5)
                *cachestrp = message_guid_import(&this->content_guid, *cachestrp);

            if (cache_version >= 8) {
                this->decoded_content_size = CACHE_ITEM_BIT32(*cachestrp);
                *cachestrp += CACHE_ITEM_SIZE_SKIP;
            }

            if (cache_version >= 9) {
                this->content_lines = CACHE_ITEM_BIT32(*cachestrp);
                *cachestrp += CACHE_ITEM_SIZE_SKIP;
            }
        }

        for (part = 0; part < body->numparts; part++) {
            this = &body->subpart[part];
            buf_reset(&buf);
            if (part_id) buf_printf(&buf, "%s.", part_id);
            buf_printf(&buf, "%d", part + 1);
            if (parse_bodystructure_sections(cachestrp, cacheend, this, cache_version, buf_cstring(&buf))) {
                r = IMAP_MAILBOX_BADFORMAT;
                goto done;
            }
        }
    }
    else {
        /*
         * Leaf section--no part 0 or nested parts
         */
        if (nsubparts != 0) {
            r = IMAP_MAILBOX_BADFORMAT;
            goto done;
        }
        if (!body->part_id)
            body->part_id = xstrdupnull(part_id);
    }

done:
    buf_free(&buf);
    return r;
}

static int message_parse_cbodystructure(message_t *m)
{
    struct protstream *prot = NULL;
    const char *cachestr = cacheitem_base(&m->record, CACHE_SECTION);
    const char *cacheend = cachestr + cacheitem_size(&m->record, CACHE_SECTION);
    struct body toplevel;
    int r;

    /* We're reading the cache - double check we have it */
    assert(m->have & M_CACHE);

    prot = prot_readmap(cacheitem_base(&m->record, CACHE_BODYSTRUCTURE),
                        cacheitem_size(&m->record, CACHE_BODYSTRUCTURE));
    if (!prot)
        return IMAP_MAILBOX_BADFORMAT;
    prot_setisclient(prot, 1);  /* don't crash parsing literals */

    m->body = xzmalloc(sizeof(struct body));
    r = parse_bodystructure_part(prot, m->body, NULL);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: error parsing body structure",
                         "mailbox=<%s> record_uid=<%u>, cacheitem=<%.*s>",
                         mailbox_name(m->mailbox), m->record.uid,
                         (int)cacheitem_size(&m->record, CACHE_BODYSTRUCTURE),
                         cacheitem_base(&m->record, CACHE_BODYSTRUCTURE));
    }
    if (r) goto done;

    memset(&toplevel, 0, sizeof(struct body));
    toplevel.type = "MESSAGE";
    toplevel.subtype = "RFC822";
    toplevel.subpart = m->body;

    r = parse_bodystructure_sections(&cachestr, cacheend, &toplevel,
                                     m->record.cache_version, NULL);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: error parsing section structure",
                         "mailbox=<%s> record_uid=<%u> cacheitem=<%.*s>",
                         mailbox_name(m->mailbox), m->record.uid,
                         (int)cacheitem_size(&m->record, CACHE_BODYSTRUCTURE),
                         cacheitem_base(&m->record, CACHE_BODYSTRUCTURE));
    }

done:
    prot_free(prot);

    return r;
}

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

static int message_map_file(message_t *m, const char *fname)
{
    int fd;
    struct stat sbuf;

    fd = open(fname, O_RDONLY, 0666);
    if (fd == -1) return errno;

    if (fstat(fd, &sbuf) == -1) {
        xsyslog(LOG_ERR, "IOERROR: fstat failed",
                         "filename=<%s>",
                         fname);
        fatal("can't fstat message file", EX_OSFILE);
    }
    if (!S_ISREG(sbuf.st_mode)) {
        close(fd);
        return EINVAL;
    }
    buf_free(&m->map);
    buf_refresh_mmap(&m->map, /*onceonly*/1, fd, fname, sbuf.st_size,
                  m->mailbox ? mailbox_name(m->mailbox) : NULL);
    close(fd);

    return 0;
}

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

static void body_get_types(struct body *body, strarray_t *types, int leafs_only)
{
    int i;

    if (!leafs_only ||
            (strcmpsafe(body->type, "MULTIPART") &&
             strcmpsafe(body->type, "MESSAGE"))) {
        strarray_append(types, body->type);
        strarray_append(types, body->subtype);
    }

    for (i = 0; i < body->numparts; i++) {
        body_get_types(&body->subpart[i], types, leafs_only);
    }
}

static int body_foreach_section(struct body *body, struct message *message,
                                int (*proc)(int isbody, charset_t charset,
                                    int encoding,
                                    const char *type, const char *subtype,
                                    const struct param *type_params,
                                    const char *disposition,
                                    const struct param *disposition_params,
                                    const struct message_guid *content_guid,
                                    const char *part,
                                    struct buf *data, void *rock),
                                void *rock)
{
    struct buf data = BUF_INITIALIZER;
    int i, r;

    if (body->header_size) {
        struct body *tmpbody = NULL;
        const char *disposition = body->disposition;
        struct param *disposition_params = body->disposition_params;

        if (!disposition) {
            /* XXX hack: body can either be read from the binary cache body
             * or bodystructure, but either misses the contents of the other */
            tmpbody = xzmalloc(sizeof(struct body));
            strarray_t boundaries = STRARRAY_INITIALIZER;
            struct msg msg;

            msg.base = message->map.s + body->header_offset;
            msg.len = body->header_size;
            msg.offset = 0;
            msg.encode = 0;
            message_parse_headers(&msg, tmpbody, "text/plain", &boundaries, NULL);

            disposition = tmpbody->disposition;
            disposition_params = tmpbody->disposition_params;
        }

        buf_init_ro(&data, message->map.s + body->header_offset, body->header_size);
        r = proc(/*isbody*/0, CHARSET_UNKNOWN_CHARSET, 0, body->type, body->subtype,
                 body->params, disposition, disposition_params, &body->content_guid,
                 body->part_id, &data, rock);
        buf_free(&data);

        if (tmpbody) {
            message_free_body(tmpbody);
            free(tmpbody);
        }

        if (r) return r;
    }

    if (!strcmpsafe(body->type, "TEXT")) {
        int encoding;
        charset_t charset = CHARSET_UNKNOWN_CHARSET;
        message_parse_charset(body, &encoding, &charset);
        buf_init_ro(&data, message->map.s + body->content_offset, body->content_size);
        r = proc(/*isbody*/1, charset, encoding, body->type, body->subtype,
                 body->params, NULL, NULL, &body->content_guid, body->part_id,
                 &data, rock);
        buf_free(&data);
        charset_free(&charset);
        if (r) return r;
    } else {
        buf_init_ro(&data, message->map.s + body->content_offset, body->content_size);
        r = proc(/*isbody*/1, CHARSET_UNKNOWN_CHARSET, encoding_lookupname(body->encoding),
                 body->type, body->subtype, body->params, NULL, NULL,
                 &body->content_guid, body->part_id, &data, rock);
        buf_free(&data);
        if (r) return r;
    }

    for (i = 0; i < body->numparts; i++) {
        r = body_foreach_section(&body->subpart[i], message, proc, rock);
        if (r) return r;
    }

    return r;
}


/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

/*
 * Iterate 'proc' over all the MIME header sections and body sections of
 * type TEXT, in the message 'm', preorder.  The 'proc' is called with
 * 'partno' equal to zero for header sections, non-zero for body
 * sections.  If 'proc' returns non-zero, the iteration finishes early
 * and the return value of 'proc' is returned.  Otherwise returns 0.
 */
EXPORTED int message_foreach_section(message_t *m,
                         int (*proc)(int isbody, charset_t charset, int encoding,
                                     const char *type, const char *subtype,
                                     const struct param *type_params,
                                     const char *disposition,
                                     const struct param *disposition_params,
                                     const struct message_guid *content_guid,
                                     const char *part,
                                     struct buf *data,
                                     void *rock),
                         void *rock)
{
    int r = message_need(m, M_CACHEBODY|M_MAP);
    if (r) return r;
    return body_foreach_section(m->body, m, proc, rock);
}

/*
 * Get the MIME content types of all leaf sections, i.e. sections whose
 * type is not multipart or message.  Strings are added to the array in
 * pairs, type first then subtype.
 */
EXPORTED int message_get_leaf_types(message_t *m, strarray_t *types)
{
    int r = message_need(m, M_CACHEBODY);
    if (r) return r;
    body_get_types(m->body, types, 1);
    return 0;
}

EXPORTED int message_get_types(message_t *m, strarray_t *types)
{
    int r = message_need(m, M_CACHEBODY);
    if (r) return r;
    body_get_types(m->body, types, 0);
    return 0;
}

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

EXPORTED int message_get_bcc(message_t *m, struct buf *buf)
{
    return message_get_field(m, "bcc", MESSAGE_RAW, buf);
}

EXPORTED int message_get_deliveredto(message_t *m, struct buf *buf)
{
    int r = message_get_field(m, "X-Original-Delivered-To", MESSAGE_RAW, buf);
    if (!r && buf_len(buf) == 0) {
        r = message_get_field(m, "X-Delivered-To", MESSAGE_RAW, buf);
    }
    return r;
}

EXPORTED int message_get_cc(message_t *m, struct buf *buf)
{
    return message_get_field(m, "cc", MESSAGE_RAW, buf);
}

EXPORTED int message_get_to(message_t *m, struct buf *buf)
{
    return message_get_field(m, "to", MESSAGE_RAW, buf);
}

EXPORTED int message_get_from(message_t *m, struct buf *buf)
{
    return message_get_field(m, "from", MESSAGE_RAW, buf);
}

EXPORTED int message_get_listid(message_t *m, struct buf *buf)
{
    return message_get_field(m, "list-id", MESSAGE_RAW, buf);
}

EXPORTED int message_get_messageid(message_t *m, struct buf *buf)
{
    return message_get_field(m, "message-id", MESSAGE_RAW, buf);
}

EXPORTED int message_get_subject(message_t *m, struct buf *buf)
{
    return message_get_field(m, "subject", MESSAGE_RAW, buf);
}

EXPORTED int message_get_mailinglist(message_t *m, struct buf *buf)
{
    return message_get_field(m, "mailing-list", MESSAGE_RAW, buf);
}

EXPORTED int message_get_priority(message_t *m, struct buf *buf)
{
    /* Only returns priority value "1" or none. */
    int r = message_get_field(m, "X-Priority", MESSAGE_RAW, buf);
    buf_trim(buf);
    if (!r && !strcmp(buf_cstring(buf), "1")) {
        return 0;
    }
    r = message_get_field(m, "Importance", MESSAGE_RAW, buf);
    buf_trim(buf);
    if (!r && !strcmp(buf_cstring(buf), "high")) {
        buf_setcstr(buf, "1");
        return 0;
    }
    buf_reset(buf);
    return r;
}

EXPORTED const struct index_record *msg_record(const message_t *m)
{
    assert(!message_need(m, M_RECORD))
    return &m->record;
}

EXPORTED struct mailbox *msg_mailbox(const message_t *m)
{
    assert(!message_need(m, M_MAILBOX))
    return m->mailbox;
}

EXPORTED int message_get_size(message_t *m, uint32_t *sizep)
{
    int r = message_need(m, M_RECORD);
    if (!r) {
        *sizep = m->record.size;
        return 0;
    }
    r = message_need(m, M_MAP);
    if (!r) {
        *sizep = buf_len(&m->map);
    }
    return r;
}

EXPORTED uint32_t msg_size(const message_t *m)
{
    assert(!message_need(m, M_RECORD))
    return m->record.size;
}

EXPORTED int message_get_uid(message_t *m, uint32_t *uidp)
{
    int r = message_need(m, M_RECORD);
    if (r) return r;
    *uidp = m->record.uid;
    return 0;
}

EXPORTED uint32_t msg_uid(const message_t *m)
{
    assert(!message_need(m, M_RECORD))
    return m->record.uid;
}

EXPORTED int message_get_cid(message_t *m, conversation_id_t *cidp)
{
    int r = message_need(m, M_RECORD);
    if (r) return r;
    *cidp = m->record.cid;
    return 0;
}

EXPORTED conversation_id_t msg_cid(const message_t *m)
{
    assert(!message_need(m, M_RECORD))
    return m->record.cid;
}

EXPORTED int message_get_modseq(message_t *m, modseq_t *modseqp)
{
    int r = message_need(m, M_RECORD);
    if (r) return r;
    *modseqp = m->record.modseq;
    return 0;
}

EXPORTED modseq_t msg_modseq(const message_t *m)
{
    assert(!message_need(m, M_RECORD))
    return m->record.modseq;
}

EXPORTED int message_get_msgno(message_t *m, uint32_t *msgnop)
{
    int r = message_need(m, M_INDEX);
    if (r) return r;
    *msgnop = m->msgno;
    return 0;
}

EXPORTED uint32_t msg_msgno(const message_t *m)
{
    assert(!message_need(m, M_INDEX))
    return m->msgno;
}

EXPORTED int message_get_guid(message_t *m, const struct message_guid **guidp)
{
    int r = message_need(m, M_RECORD);
    if (!r) {
        *guidp = &m->record.guid;
        return 0;
    }
    if (message_guid_isnull(&m->guid)) {
        r = message_need(m, M_MAP);
        if (r) return r;
        message_guid_generate(&m->guid, buf_base(&m->map), buf_len(&m->map));
    }
    *guidp = &m->guid;
    return 0;
}

EXPORTED const struct message_guid *msg_guid(const message_t *m)
{
    assert(!message_need(m, M_RECORD))
    return &m->record.guid;
}

EXPORTED int message_get_userflags(message_t *m, uint32_t *flagsp)
{
    int r = message_need(m, M_RECORD);
    int i;
    if (r) return r;
    for (i = 0; i < MAX_USER_FLAGS/32; i++)
        flagsp[i] = m->record.user_flags[i];
    return 0;
}

EXPORTED int message_get_systemflags(message_t *m, uint32_t *flagsp)
{
    int r = message_need(m, M_RECORD);
    if (r) return r;
    *flagsp = m->record.system_flags;
    return 0;
}

EXPORTED int message_get_internalflags(message_t *m, uint32_t *flagsp)
{
    int r = message_need(m, M_RECORD);
    if (r) return r;
    *flagsp = m->record.internal_flags;
    return 0;
}

EXPORTED int message_get_indexflags(message_t *m, uint32_t *flagsp)
{
    int r = message_need(m, M_INDEX);
    if (r) return r;
    *flagsp = m->indexflags;
    return 0;
}

EXPORTED int message_get_savedate(message_t *m, time_t *datep)
{
    int r = message_need(m, M_RECORD);
    if (r) return r;
    *datep = m->record.savedate;
    if (!*datep) *datep = m->record.internaldate;
    return 0;
}

EXPORTED int message_get_indexversion(message_t *m, uint32_t *versionp)
{
    int r = message_need(m, M_MAILBOX);
    if (r) return r;
    *versionp = m->mailbox->i.minor_version;
    return 0;
}

EXPORTED int message_get_sentdate(message_t *m, time_t *datep)
{
    int r = message_need(m, M_RECORD);
    if (r) return r;
    *datep = m->record.sentdate;
    return 0;
}

EXPORTED int message_get_gmtime(message_t *m, time_t *tp)
{
    int r = message_need(m, M_RECORD);
    if (r) return r;
    *tp = m->record.gmtime;
    return 0;
}

EXPORTED int message_get_internaldate(message_t *m, time_t *datep)
{
    int r = message_need(m, M_RECORD);
    if (r) return r;
    *datep = m->record.internaldate;
    return 0;
}

EXPORTED int message_get_fname(message_t *m, const char **fnamep)
{
    int r = message_need(m, M_FILENAME);
    if (r) return r;
    *fnamep = m->filename;
    return 0;
}

/* XXX despite the name, this actually gives back ALL the values of the
 * XXX named header, unless flags contains MESSAGE_LAST
 */
static void extract_one(struct buf *buf,
                        const char *name,
                        int flags,
                        int has_name,
                        int isutf8,
                        struct buf *raw)
{
    char *p = NULL;

    if (raw->len && (flags & MESSAGE_LAST)) {
        /* Skip all but the last header value */
        const char *q = raw->s;
        const char *last = raw->s;
        while ((p = strnchr(q, '\r', raw->s + raw->len - q))) {
            if (p >= raw->s + raw->len - 2)
                break;
            if (*(p+1) == '\n' && *(p+2) && !isspace(*(p+2)))
                last = p + 2;
            q = p + 1;
        }
        if (last != raw->s)
            buf_remove(raw, 0, last - raw->s);
        p = NULL;
    }

    if (has_name && !(flags & MESSAGE_FIELDNAME)) {
        /* remove the fieldname and colon */
        int pos = buf_findchar(raw, 0, ':');
        assert(pos > 0);
        buf_remove(raw, 0, pos+1);
    }
    else if (!has_name && (flags & MESSAGE_FIELDNAME)) {
        /* insert a fieldname and colon */
        buf_insertcstr(raw, 0, ":");
        buf_insertcstr(raw, 0, name);
    }

    switch (flags & _MESSAGE_FORMAT_MASK) {
    case MESSAGE_RAW:
        /* Logically, we're appending to the resulting buffer.
         * However if the buf is empty we can save a memory copy
         * by setting it up as a CoW buffer.  This means that
         * the caller will need to call buf_cstring() if they
         * need a C string. */
        if (!raw->alloc)
            buf_cowappendmap(buf, raw->s, raw->len);
        else
            buf_append(buf, raw);
        break;
    case MESSAGE_DECODED:
        /* XXX - this is also broken with utf8ness, but the only caller protects agains the fields
         * that could be utf8 (search_header) - so it doesn't matter */
        p = charset_parse_mimeheader(buf_cstring(raw), charset_flags);
        buf_appendcstr(buf, p);
        break;
    case MESSAGE_SNIPPET:
        if (isutf8) {
            charset_t utf8 = charset_lookupname("utf-8");
            p = charset_convert(buf_cstring(raw), utf8, charset_snippet_flags);
            charset_free(&utf8);
        }
        else {
            p = charset_decode_mimeheader(buf_cstring(raw), charset_snippet_flags);
        }
        buf_appendcstr(buf, p);
        break;
    case MESSAGE_SEARCH:
        /* TODO: need a variant of decode_mimeheader() which
         * takes two struct buf* and a search flag */
        if (isutf8) {
            charset_t utf8 = charset_lookupname("utf-8");
            p = charset_convert(buf_cstring(raw), utf8, charset_flags);
            charset_free(&utf8);
        }
        else {
            p = charset_decode_mimeheader(buf_cstring(raw), charset_flags);
        }
        buf_appendcstr(buf, p);
        break;
    }

    if (flags & MESSAGE_TRIM)
        buf_trim(buf);

    free(p);
}

EXPORTED int message_get_spamscore(message_t *m, uint32_t *valp)
{
    struct buf buf = BUF_INITIALIZER;
    int r = message_get_field(m, "X-Spam-score", MESSAGE_RAW, &buf);
    *valp = r ? 0 : (int)((atof(buf_cstring(&buf)) * 100)  + 0.5);
    buf_free(&buf);
    return r;
}

EXPORTED int message_get_field(message_t *m, const char *hdr, int flags, struct buf *buf)
{
    strarray_t want = STRARRAY_INITIALIZER;
    struct buf raw = BUF_INITIALIZER;
    int hasname = 1;
    int isutf8 = 0;

    if (!strcasecmp(hdr, "rawheaders")) {
        int r = message_need(m, M_MAP|M_RECORD);
        if (r) return r;
        buf_setmap(buf, m->map.s, m->record.header_size);
        return 0;
    }

    if (!strcasecmp(hdr, "rawbody")) {
        int r = message_need(m, M_MAP|M_RECORD);
        if (r) return r;
        buf_setmap(buf, m->map.s + m->record.header_size, m->record.size - m->record.header_size);
        return 0;
    }

    if (!(flags & MESSAGE_APPEND))
        buf_reset(buf);

    /* Attempt to read field from the least-cost source available */
    int found_field = 0;

    /* the 5 standalone cache fields */
    if (!strcasecmp(hdr, "from")) {
        int r = message_need(m, M_CACHE);
        if (!r) {
            buf_setmap(&raw, cacheitem_base(&m->record, CACHE_FROM),
                    cacheitem_size(&m->record, CACHE_FROM));
            if (raw.len == 3 && raw.s[0] == 'N' && raw.s[1] == 'I' && raw.s[2] == 'L')
                buf_reset(&raw);
            hasname = 0;
            isutf8 = 1;
            found_field = 1;
        } else if (r != IMAP_NOTFOUND) return r;
    }
    else if (!strcasecmp(hdr, "to")) {
        int r = message_need(m, M_CACHE);
        if (!r) {
            buf_setmap(&raw, cacheitem_base(&m->record, CACHE_TO),
                    cacheitem_size(&m->record, CACHE_TO));
            if (raw.len == 3 && raw.s[0] == 'N' && raw.s[1] == 'I' && raw.s[2] == 'L')
                buf_reset(&raw);
            hasname = 0;
            isutf8 = 1;
            found_field = 1;
        } else if (r != IMAP_NOTFOUND) return r;
    }
    else if (!strcasecmp(hdr, "cc")) {
        int r = message_need(m, M_CACHE);
        if (!r) {
            buf_setmap(&raw, cacheitem_base(&m->record, CACHE_CC),
                    cacheitem_size(&m->record, CACHE_CC));
            if (raw.len == 3 && raw.s[0] == 'N' && raw.s[1] == 'I' && raw.s[2] == 'L')
                buf_reset(&raw);
            hasname = 0;
            isutf8 = 1;
            found_field = 1;
        } else if (r != IMAP_NOTFOUND) return r;
    }
    else if (!strcasecmp(hdr, "bcc")) {
        int r = message_need(m, M_CACHE);
        if (!r) {
            buf_setmap(&raw, cacheitem_base(&m->record, CACHE_BCC),
                    cacheitem_size(&m->record, CACHE_BCC));
            if (raw.len == 3 && raw.s[0] == 'N' && raw.s[1] == 'I' && raw.s[2] == 'L')
                buf_reset(&raw);
            hasname = 0;
            isutf8 = 1;
            found_field = 1;
        } else if (r != IMAP_NOTFOUND) return r;
    }
    else if (!strcasecmp(hdr, "subject")) {
        int r = message_need(m, M_CACHE);
        if (!r) {
            message1_get_subject(&m->record, &raw);
            hasname = 0;
            isutf8 = 1;
            found_field = 1;
        } else if (r != IMAP_NOTFOUND) return r;
    }

    /* message-id is from the envelope */
    else if (!strcasecmp(hdr, "message-id")) {
        char *envtokens[NUMENVTOKENS];
        char *c_env;
        int r = message_need(m, M_CACHE);
        if (!r) {
            c_env = xstrndup(cacheitem_base(&m->record, CACHE_ENVELOPE) + 1,
                    cacheitem_size(&m->record, CACHE_ENVELOPE) - 2);
            parse_cached_envelope(c_env, envtokens, NUMENVTOKENS);
            if (envtokens[ENV_MSGID])
                buf_appendcstr(&raw, envtokens[ENV_MSGID]);
            free(c_env);
            if (raw.len == 3 && raw.s[0] == 'N' && raw.s[1] == 'I' && raw.s[2] == 'L')
                buf_reset(&raw);
            hasname = 0;
            found_field = 1;
        } else if (r != IMAP_NOTFOUND) return r;
    }
    else {
        int r = message_need(m, M_RECORD);
        unsigned cache_version = mailbox_cached_header(hdr);
        if (!r && m->record.cache_version >= cache_version) {
            /* it's in the cache */
            char *headers = NULL;
            int r = message_need(m, M_CACHE);
            if (r) return r;
            headers = xstrndup(cacheitem_base(&m->record, CACHE_HEADERS),
                      cacheitem_size(&m->record, CACHE_HEADERS));
            strarray_append(&want, hdr);
            message_pruneheader(headers, &want, NULL);
            buf_appendcstr(&raw, headers);
            free(headers);
            hasname = 1;
            found_field = 1;
        } else if (r && r != IMAP_NOTFOUND) return r;
    }

    if (!found_field) {
        /* fall back to read field from raw headers */
        char *headers = NULL;
        int r = message_need(m, M_MAP|M_CACHEBODY);
        if (r) return r;
        headers = xstrndup(m->map.s + m->body->header_offset, m->body->header_size);
        strarray_append(&want, hdr);
        message_pruneheader(headers, &want, NULL);
        buf_appendcstr(&raw, headers);
        free(headers);
        hasname = 1;
        found_field = 1;
    }

    if (raw.len)
        extract_one(buf, hdr, flags, hasname, isutf8, &raw);

    buf_free(&raw);
    strarray_fini(&want);

    return 0;
}

EXPORTED int message_foreach_header(const char *headers, size_t len,
                                    int(*cb)(const char*, const char*, void*),
                                    void *rock)
{
    struct buf key = BUF_INITIALIZER;
    struct buf val = BUF_INITIALIZER;
    const char *top = headers + len;
    const char *hdr = headers;
    int r = 0;

    while (hdr < top) {
        /* Look for colon separating header name from value */
        const char *p = memchr(hdr, ':', top - hdr);
        if (!p) {
            r = IMAP_INTERNAL;
            goto done;
        }
        buf_setmap(&key, hdr, p - hdr);
        p++;
        /* Extract raw header value, skipping over folding CRLF */
        const char *q = p;
        while (q < top && (q = memchr(q, '\n', top - q))) {
            if ((++q == top) || (*q != ' ' && *q != '\t'))
                break;
        }
        if (!q) q = top;
        /* Chomp of trailing CRLF */
        buf_setmap(&val, p, q - p >= 2 ? q - p - 2 : 0);
        /* Call callback for header */
        r = cb(buf_cstring(&key), buf_cstring(&val), rock);
        if (r) break;
        /* Prepare next iteration */
        buf_reset(&key);
        buf_reset(&val);
        hdr = q;
    }

done:
    buf_free(&key);
    buf_free(&val);
    return r;
}

EXPORTED int message_get_type(message_t *m, const char **strp)
{
    int r = message_need(m, M_CACHEBODY);
    if (r) return r;
    *strp = m->body->type;
    return 0;
}

EXPORTED int message_get_subtype(message_t *m, const char **strp)
{
    int r = message_need(m, M_CACHEBODY);
    if (r) return r;
    *strp = m->body->subtype;
    return 0;
}

EXPORTED int message_get_encoding(message_t *m, int *encp)
{
    int r = message_need(m, M_CACHEBODY);
    if (r) return r;
    *encp = m->body->charset_enc;
    return 0;
}

EXPORTED int message_get_charset_id(message_t *m, const char **strp)
{
    int r = message_need(m, M_CACHEBODY);
    if (r) return r;
    *strp = m->body->charset_id;
    return 0;
}

EXPORTED int message_get_cachebody(message_t *m, const struct body **bodyp)
{
    int r = message_need(m, M_CACHEBODY);
    if (r) return r;
    *bodyp = m->body;
    return 0;
}

EXPORTED int message_get_body(message_t *m, struct buf *buf)
{
    return message_get_field(m, "rawbody", MESSAGE_RAW, buf);
}

EXPORTED int message_get_headers(message_t *m, struct buf *buf)
{
    return message_get_field(m, "rawheaders", MESSAGE_RAW, buf);
}
