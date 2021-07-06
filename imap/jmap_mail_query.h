/* jmap_mail_query.h -- Helper routines for JMAP Email queries.
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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
 */

#ifndef JMAP_MAIL_QUERY_H
#define JMAP_MAIL_QUERY_H

#include <jansson.h>

#include "strarray.h"

#include "jmap_mail_query_parse.h"
#include "jmap_util.h"

#ifdef WITH_DAV

#include <time.h>

#include "hash.h"
#include "ptrarray.h"

#include "carddav_db.h"
#include "message.h"
#include "xapian_wrap.h"

struct email_contactfilter {
    const char *accountid;
    struct carddav_db *carddavdb;
    char *addrbook;
    hash_table contactgroups; /* maps groupid to emails (strarray) */
};

extern void jmap_email_contactfilter_init(const char *accountid,
                                          const char *addressbookid,
                                          struct email_contactfilter *cfilter);
extern void jmap_email_contactfilter_fini(struct email_contactfilter *cfilter);

extern int jmap_email_contactfilter_from_filtercondition(struct jmap_parser *parser,
                                                         json_t *filter,
                                                         struct email_contactfilter *cfilter);

struct emailbodies {
    ptrarray_t attslist;
    ptrarray_t textlist;
    ptrarray_t htmllist;
};

#define EMAILBODIES_INITIALIZER { \
    PTRARRAY_INITIALIZER, \
    PTRARRAY_INITIALIZER, \
    PTRARRAY_INITIALIZER \
}

extern void jmap_emailbodies_fini(struct emailbodies *bodies);

extern int jmap_emailbodies_extract(const struct body *root,
                                    struct emailbodies *bodies);

extern int jmap_email_hasattachment(const struct body *root,
                                    json_t *imagesize_by_partid);

struct jmap_email_filter_parser_rock {
    struct jmap_parser *parser;
    json_t *unsupported;
};

extern void jmap_filter_parser_invalid(const char *field, void *rock);
extern void jmap_filter_parser_push_index(const char *field, size_t index,
                                          const char *name, void *rock);
extern void jmap_filter_parser_pop(void *rock);
extern void jmap_email_filtercondition_validate(const char *field, json_t *arg,
                                                void *rock);

/* Matches MIME message mime against the JMAP Email query
 * filter.
 *
 * Contact groups are looked up in the default addressbook
 * of accountid. Before/after filters are matched against
 * internaldate.
 *
 * Returns non-zero if filter matches.
 * On error, sets the JMAP error in err. */
struct matchmime {
    char *dbpath;
    xapian_dbw_t *dbw;
    message_t *m;
    const struct buf *mime;
};
typedef struct matchmime matchmime_t;
extern matchmime_t *jmap_email_matchmime_init(const struct buf *buf, json_t **err);
extern void jmap_email_matchmime_free(matchmime_t **matchmimep);
extern int jmap_email_matchmime(matchmime_t *matchmime,
                                json_t *jfilter,
                                const char *accountid,
                                time_t internaldate,
                                json_t **err);

struct jmap_headermatch {
    enum headermatch_op {
        HEADERMATCH_EQUALS,
        HEADERMATCH_STARTS,
        HEADERMATCH_ENDS,
        HEADERMATCH_CONTAINS
    } op;
    char *header;
    char *value;
    size_t len;
    charset_t utf8;
    charset_conv_t *conv;
    struct buf tmp[3];
};

extern struct jmap_headermatch *jmap_headermatch_new(const char *header,
                                                     const char *value,
                                                     const char *strop);

extern void jmap_headermatch_free(struct jmap_headermatch **hmp);

extern struct jmap_headermatch *jmap_headermatch_dup(struct jmap_headermatch *hm);

extern int jmap_headermatch_match(struct jmap_headermatch *hm, message_t *msg);


#endif /* WITH_DAV */

#endif /* JMAP_MAIL_QUERY_H */
