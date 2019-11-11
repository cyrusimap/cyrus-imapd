/* jmap_util.c -- Helper routines for JMAP
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

#include <config.h>

#include <string.h>
#include <syslog.h>

#include "libconfig.h"

#include "jmap_mail_query.h"
#include "jmap_util.h"
#include "json_support.h"

#ifndef JMAP_URN_MAIL
#define JMAP_URN_MAIL                "urn:ietf:params:jmap:mail"
#endif
#ifndef JMAP_MAIL_EXTENSION
#define JMAP_MAIL_EXTENSION          "https://cyrusimap.org/ns/jmap/mail"
#endif
#ifndef JMAP_SEARCH_EXTENSION
#define JMAP_SEARCH_EXTENSION        "https://cyrusimap.org/ns/jmap/search"
#endif

static int _email_threadkeyword_is_valid(const char *keyword)
{
    /* \Seen is always supported */
    if (!strcasecmp(keyword, "$Seen"))
        return 1;

    const char *counted_flags = config_getstring(IMAPOPT_CONVERSATIONS_COUNTED_FLAGS);
    if (!counted_flags)
        return 0;

    /* We really shouldn't do all this string mangling for each keyword */
    strarray_t *flags = strarray_split(counted_flags, " ", STRARRAY_TRIM);
    int i, is_supported = 0;
    for (i = 0; i < flags->count; i++) {
        const char *flag = strarray_nth(flags, i);
        const char *kw = keyword;
        if (*flag == '\\') { // special case \ => $
            flag++;
            if (*kw != '$') continue;
            kw++;
        }
        if (!strcasecmp(flag, kw)) {
            is_supported = 1;
            break;
        }
    }
    strarray_free(flags);

    return is_supported;
}


HIDDEN void jmap_email_filtercondition_parse(struct jmap_parser *parser,
                                             json_t *filter,
                                             json_t *unsupported,
                                             const strarray_t *capabilities)
{
    const char *field, *s = NULL;
    json_t *arg;

    json_object_foreach(filter, field, arg) {
        if (!strcmp(field, "inMailbox")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "inMailboxOtherThan")) {
            if (!json_is_array(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "before") ||
                 !strcmp(field, "after")) {
            if (!json_is_utcdate(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "minSize") ||
                 !strcmp(field, "maxSize")) {
            if (!json_is_integer(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "allInThreadHaveKeyword") ||
                 !strcmp(field, "someInThreadHaveKeyword") ||
                 !strcmp(field, "noneInThreadHaveKeyword")) {
            if (!json_is_string(arg) ||
                !(s = json_string_value(arg)) ||
                !jmap_email_keyword_is_valid(s)) {
                jmap_parser_invalid(parser, field);
            }
            else if (!_email_threadkeyword_is_valid(s)) {
                json_array_append_new(unsupported, json_pack("{s:s}", field, s));
            }
        }
        else if (!strcmp(field, "hasKeyword") ||
                 !strcmp(field, "notKeyword")) {
            if (!json_is_string(arg) ||
                !jmap_email_keyword_is_valid(json_string_value(arg))) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "hasAttachment")) {
            if (!json_is_boolean(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "text") ||
                 !strcmp(field, "from") ||
                 !strcmp(field, "to") ||
                 !strcmp(field, "cc") ||
                 !strcmp(field, "bcc") ||
                 !strcmp(field, "subject") ||
                 !strcmp(field, "body") ||
                 (strarray_find(capabilities, JMAP_MAIL_EXTENSION, 0) >= 0 &&
                  (!strcmp(field, "attachmentName") ||    /* FM-specific */
                   !strcmp(field, "attachmentType"))) ||  /* FM-specific */
                 (strarray_find(capabilities, JMAP_SEARCH_EXTENSION, 0) >= 0 &&
                   !strcmp(field, "attachmentBody"))) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "header")) {
            if (!json_is_array(arg)) {
                jmap_parser_invalid(parser, field);
            }
            else {
                switch (json_array_size(arg)) {
                case 2:
                    s = json_string_value(json_array_get(arg, 1));
                    if (!s || !strlen(s)) {
                        jmap_parser_push_index(parser, field, 1, s);
                        jmap_parser_invalid(parser, NULL);
                        jmap_parser_pop(parser);
                    }

                    GCC_FALLTHROUGH

                case 1:
                    s = json_string_value(json_array_get(arg, 0));
                    if (!s || !strlen(s)) {
                        jmap_parser_push_index(parser, field, 0, s);
                        jmap_parser_invalid(parser, NULL);
                        jmap_parser_pop(parser);
                    }
                    break;

                default:
                    jmap_parser_invalid(parser, field);
                }
            }
        }
        else if (strarray_find(capabilities, JMAP_MAIL_EXTENSION, 0) >= 0 &&
                 (!strcmp(field, "fromContactGroupId") ||
                  !strcmp(field, "toContactGroupId") ||
                  !strcmp(field, "ccContactGroupId") ||
                  !strcmp(field, "bccContactGroupId"))) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else {
            jmap_parser_invalid(parser, field);
        }
    }
}

HIDDEN void jmap_email_filter_parse(struct jmap_parser *parser,
                                    json_t *filter,
                                    json_t *unsupported,
                                    const strarray_t *capabilities)
{
    if (!JNOTNULL(filter) || json_typeof(filter) != JSON_OBJECT) {
        jmap_parser_invalid(parser, NULL);
        return;
    }
    json_t *jop = json_object_get(filter, "operator");
    if (json_is_string(jop)) {
        const char *op = json_string_value(jop);
        if (strcmp("AND", op) && strcmp("OR", op) && strcmp("NOT", op)) {
            jmap_parser_invalid(parser, "operator");
        }
        json_t *jconds = json_object_get(filter, "conditions");
        if (!json_array_size(jconds)) {
            jmap_parser_invalid(parser, "conditions");
        }
        size_t i;
        json_t *jcond;
        json_array_foreach(jconds, i, jcond) {
            jmap_parser_push_index(parser, "conditions", i, NULL);
            jmap_email_filter_parse(parser, jcond, unsupported, capabilities);
            jmap_parser_pop(parser);
        }
    } else if (jop) {
        jmap_parser_invalid(parser, "operator");
    } else {
        jmap_email_filtercondition_parse(parser, filter, unsupported, capabilities);
    }
}

#ifdef WITH_DAV

#include "annotate.h"
#include "carddav_db.h"
#include "global.h"
#include "hash.h"
#include "index.h"
#include "search_query.h"
#include "times.h"
#include "xapian_wrap.h"

HIDDEN void jmap_email_contactfilter_init(const char *accountid,
                                          const char *addressbookid,
                                          struct email_contactfilter *cfilter)
{
    memset(cfilter, 0, sizeof(struct email_contactfilter));
    cfilter->accountid = accountid;
    if (addressbookid) {
        cfilter->addrbook = carddav_mboxname(accountid, addressbookid);
    }
}

HIDDEN void jmap_email_contactfilter_fini(struct email_contactfilter *cfilter)
{
    if (cfilter->carddavdb) {
        carddav_close(cfilter->carddavdb);
    }
    free(cfilter->addrbook);
    free_hash_table(&cfilter->contactgroups, (void(*)(void*))strarray_free);
}

HIDDEN int jmap_email_contactfilter_from_filtercondition(struct jmap_parser *parser,
                                                         json_t *filter,
                                                         struct email_contactfilter *cfilter)
{
    const char *field;
    json_t *arg;

    json_object_foreach(filter, field, arg) {
        if ((!strcmp(field, "fromContactGroupId") ||
             !strcmp(field, "toContactGroupId") ||
             !strcmp(field, "ccContactGroupId") ||
             !strcmp(field, "bccContactGroupId"))) {
            const char *groupid = json_string_value(arg);
            if (groupid) {
                if (!cfilter->contactgroups.size) {
                    /* Initialize groups lookup table */
                    construct_hash_table(&cfilter->contactgroups, 32, 0);
                }
                if (!hash_lookup(groupid, &cfilter->contactgroups)) {
                    if (!cfilter->carddavdb) {
                        /* Open CardDAV db first time we need it */
                        cfilter->carddavdb = carddav_open_userid(cfilter->accountid);
                        if (!cfilter->carddavdb) {
                            syslog(LOG_ERR, "jmap: carddav_open_userid(%s) failed",
                                    cfilter->accountid);
                            return CYRUSDB_INTERNAL;
                        }
                    }
                    /* Lookup group member email addresses */
                    strarray_t *members = carddav_getgroup(cfilter->carddavdb, cfilter->addrbook, groupid);
                    if (!members || !strarray_size(members)) {
                        jmap_parser_invalid(parser, field);
                    }
                    else {
                        hash_insert(groupid, members, &cfilter->contactgroups);
                    }
                }
            }
        }
    }

    return 0;
}

HIDDEN void jmap_emailbodies_fini(struct emailbodies *bodies)
{
    ptrarray_fini(&bodies->attslist);
    ptrarray_fini(&bodies->textlist);
    ptrarray_fini(&bodies->htmllist);
}

static int _email_extract_bodies_internal(const struct body *parts,
                                          int nparts,
                                          const char *multipart_type,
                                          int in_alternative,
                                          ptrarray_t *textlist,
                                          ptrarray_t *htmllist,
                                          ptrarray_t *attslist)
{
    int i;

    enum parttype { OTHER, PLAIN, HTML, MULTIPART, INLINE_MEDIA, MESSAGE };

    int textlist_count = textlist ? textlist->count : -1;
    int htmllist_count = htmllist ? htmllist->count : -1;

    for (i = 0; i < nparts; i++) {
        const struct body *part = parts + i;

        /* Determine part type */
        enum parttype parttype = OTHER;
        if (!strcmp(part->type, "TEXT") && !strcmp(part->subtype, "PLAIN"))
            parttype = PLAIN;
        else if (!strcmp(part->type, "TEXT") && !strcmp(part->subtype, "RICHTEXT"))
            parttype = PLAIN; // RFC 1341
        else if (!strcmp(part->type, "TEXT") && !strcmp(part->subtype, "ENRICHED"))
            parttype = PLAIN; // RFC 1563
        else if (!strcmp(part->type, "TEXT") && !strcmp(part->subtype, "HTML"))
            parttype = HTML;
        else if (!strcmp(part->type, "MULTIPART"))
            parttype = MULTIPART;
        else if (!strcmp(part->type, "IMAGE") || !strcmp(part->type, "AUDIO") || !strcmp(part->type, "VIDEO"))
            parttype = INLINE_MEDIA;

        /* Determine disposition name, if any. */
        const char *dispname = NULL;
        struct param *param;
        for (param = part->disposition_params; param; param = param->next) {
            if (!strncasecmp(param->attribute, "filename", 8)) {
                dispname = param->value;
                break;
            }
        }
        if (!dispname) {
            for (param = part->params; param; param = param->next) {
                if (!strncasecmp(param->attribute, "name", 4)) {
                    dispname = param->value;
                    break;
                }
            }
        }
        /* Determine if it's an inlined part */
        int is_inline =
            (!part->disposition || strcmp(part->disposition, "ATTACHMENT")) &&
            /* Must be one of the allowed body types */
            (parttype == PLAIN || parttype == HTML || parttype == INLINE_MEDIA) &&
             /* If multipart/related, only the first part can be inline
              * If a text part with a filename, and not the first item in the
              * multipart, assume it is an attachment */
             (i == 0 || (strcmp(multipart_type, "RELATED") &&
                         (parttype == INLINE_MEDIA || !dispname)));
        /* Handle by part type */
        if (parttype == MULTIPART) {
            _email_extract_bodies_internal(part->subpart, part->numparts,
                    part->subtype,
                    in_alternative || !strcmp(part->subtype, "ALTERNATIVE"),
                    textlist, htmllist, attslist);
        }
        else if (is_inline) {
            if (!strcmp(multipart_type, "ALTERNATIVE")) {
                switch (parttype) {
                    case PLAIN:
                        ptrarray_append(textlist, (void*) part);
                        break;
                    case HTML:
                        ptrarray_append(htmllist, (void*) part);
                        break;
                    default:
                        ptrarray_append(attslist, (void*) part);
                }
                continue;
            }
            else if (in_alternative) {
                if (parttype == PLAIN)
                    htmllist = NULL;
                if (parttype == HTML)
                    textlist = NULL;
            }
            if (textlist)
                ptrarray_append(textlist, (void*) part);
            if (htmllist)
                ptrarray_append(htmllist, (void*) part);
            if ((!textlist || !htmllist) && parttype == INLINE_MEDIA)
                ptrarray_append(attslist, (void*) part);
        }
        else {
            ptrarray_append(attslist, (void*) part);
        }
    }

    if (!strcmp(multipart_type, "ALTERNATIVE")) {
        int j;
        /* Found HTML part only */
        if (textlist && textlist_count == textlist->count) {
            for (j = htmllist_count; j < htmllist->count; j++)
                ptrarray_append(textlist, ptrarray_nth(htmllist, j));
        }
        /* Found TEXT part only */
        if (htmllist && htmllist_count == htmllist->count) {
            for (j = textlist_count; j < textlist->count; j++)
                ptrarray_append(htmllist, ptrarray_nth(textlist, j));
        }
    }

    return 0;
}

HIDDEN int jmap_emailbodies_extract(const struct body *root,
                                     struct emailbodies *bodies)
{
    return _email_extract_bodies_internal(root, 1, "MIXED", 0,
            &bodies->textlist, &bodies->htmllist,
            &bodies->attslist);
}

struct matchmime_receiver {
    struct search_text_receiver super;
    xapian_dbw_t *dbw;
    struct buf buf;
};

static int _matchmime_tr_begin_mailbox(search_text_receiver_t *rx __attribute__((unused)),
                                       struct mailbox *mailbox __attribute__((unused)),
                                       int incremental __attribute__((unused)))
{
    return 0;
}

static uint32_t _matchmime_tr_first_unindexed_uid(search_text_receiver_t *rx __attribute__((unused)))
{
    return 1;
}

static int _matchmime_tr_is_indexed(search_text_receiver_t *rx __attribute__((unused)),
                                    message_t *msg __attribute__((unused)))
{
    return 0;
}

static int _matchmime_tr_begin_message(search_text_receiver_t *rx, message_t *msg)
{
    const struct message_guid *guid;
    int r = message_get_guid(msg, &guid);
    if (r) return r;

    struct matchmime_receiver *tr = (struct matchmime_receiver *) rx;
    return xapian_dbw_begin_doc(tr->dbw, guid, 'G');
}

static void _matchmime_tr_begin_part(search_text_receiver_t *rx __attribute__((unused)),
                                     int part __attribute__((unused)),
                                     const struct message_guid *content_guid __attribute__((unused)))
{
}

static void _matchmime_tr_append_text(search_text_receiver_t *rx,
                                      const struct buf *text)
{
    struct matchmime_receiver *tr = (struct matchmime_receiver *) rx;
    buf_append(&tr->buf, text);
}

static void _matchmime_tr_end_part(search_text_receiver_t *rx, int part)
{
    struct matchmime_receiver *tr = (struct matchmime_receiver *) rx;
    xapian_dbw_doc_part(tr->dbw, &tr->buf, part);
    buf_reset(&tr->buf);
}

static int _matchmime_tr_end_message(search_text_receiver_t *rx)
{
    struct matchmime_receiver *tr = (struct matchmime_receiver *) rx;
    return xapian_dbw_end_doc(tr->dbw);
}

static int _matchmime_tr_end_mailbox(search_text_receiver_t *rx __attribute__((unused)),
                                     struct mailbox *mailbox __attribute__((unused)))
{
    return 0;
}

static int _matchmime_tr_flush(search_text_receiver_t *rx __attribute__((unused)))
{
    return 0;
}

static int _matchmime_tr_audit_mailbox(search_text_receiver_t *rx __attribute__((unused)),
                                       bitvector_t *unindexed __attribute__((unused)))
{
    return 0;
}

static int _matchmime_tr_index_charset_flags(int base_flags)
{
    return base_flags | CHARSET_KEEPCASE;
}

static int _email_matchmime_evaluate_xcb(const void *data __attribute__((unused)),
                                         size_t n, void *rock)
{
    int *matches = rock;
    /* There's just a single message in the in-memory database,
     * so no need to check the message guid in the search result. */
    *matches = n > 0;
    return 0;
}

static xapian_query_t *_email_matchmime_contactgroup(const char *groupid,
                                                     int part,
                                                     xapian_db_t *db,
                                                     struct email_contactfilter *cfilter)
{
    if (!cfilter->contactgroups.size) return NULL;

    xapian_query_t *xq = NULL;
    strarray_t *members = hash_lookup(groupid, &cfilter->contactgroups);
    if (members && strarray_size(members)) {
        ptrarray_t xsubqs = PTRARRAY_INITIALIZER;
        int i;
        for (i = 0; i < strarray_size(members); i++) {
            const char *member = strarray_nth(members, i);
            xapian_query_t *xsubq = xapian_query_new_match(db, part, member);
            if (xsubq) ptrarray_append(&xsubqs, xsubq);
        }
        if (ptrarray_size(&xsubqs)) {
            xq = xapian_query_new_compound(db, /*is_or*/1,
                    (xapian_query_t **) xsubqs.data, xsubqs.count);
        }
        ptrarray_fini(&xsubqs);
    }
    return xq;
}

static int _email_matchmime_evaluate(json_t *filter,
                                     message_t *m,
                                     xapian_db_t *db,
                                     struct email_contactfilter *cfilter,
                                     time_t internaldate)
{
    json_t *conditions = json_object_get(filter, "conditions");
    if (json_is_array(conditions)) {

        /* Evaluate FilterOperator */

        const char *strop = json_string_value(json_object_get(filter, "operator"));
        enum search_op op = SEOP_UNKNOWN;
        int matches;

        if (!strcasecmpsafe(strop, "AND")) {
            op = SEOP_AND;
            matches = 1;
        }
        else if (!strcasecmpsafe(strop, "OR")) {
            op = SEOP_OR;
            matches = json_array_size(conditions) == 0;
        }
        else if (!strcasecmpsafe(strop, "NOT")) {
            op = SEOP_NOT;
            matches = json_array_size(conditions) != 0;
        }
        else return 0;

        json_t *condition;
        size_t i;
        json_array_foreach(conditions, i, condition) {
            int cond_matches = _email_matchmime_evaluate(condition, m, db, cfilter, internaldate);
            if (op == SEOP_AND && !cond_matches) {
                return 0;
            }
            if (op == SEOP_OR && cond_matches) {
                return 1;
            }
            if (op == SEOP_NOT && cond_matches) {
                return 0;
            }
        }

        return matches;
    }

    /* Evaluate FilterCondition */

    int matches = 1;

    /* Xapian-backed criteria */
    ptrarray_t xqs = PTRARRAY_INITIALIZER;
    const char *match;
    if ((match = json_string_value(json_object_get(filter, "text")))) {
        ptrarray_t childqueries = PTRARRAY_INITIALIZER;
        int i;
        for (i = 0 ; i < SEARCH_NUM_PARTS ; i++) {
            if (i == SEARCH_PART_ATTACHMENTBODY)
                continue;
            void *xq = xapian_query_new_match(db, i, match);
            if (xq) ptrarray_push(&childqueries, xq);
        }
        xapian_query_t *xq = xapian_query_new_compound(db, /*is_or*/1,
                                       (xapian_query_t **)childqueries.data,
                                       childqueries.count);
        if (xq) ptrarray_append(&xqs, xq);
        ptrarray_fini(&childqueries);
    }
    if ((match = json_string_value(json_object_get(filter, "from")))) {
        xapian_query_t *xq = xapian_query_new_match(db, SEARCH_PART_FROM, match);
        if (xq) ptrarray_append(&xqs, xq);
    }
    if ((match = json_string_value(json_object_get(filter, "to")))) {
        xapian_query_t *xq = xapian_query_new_match(db, SEARCH_PART_TO, match);
        if (xq) ptrarray_append(&xqs, xq);
    }
    if ((match = json_string_value(json_object_get(filter, "cc")))) {
        xapian_query_t *xq = xapian_query_new_match(db, SEARCH_PART_CC, match);
        if (xq) ptrarray_append(&xqs, xq);
    }
    if ((match = json_string_value(json_object_get(filter, "bcc")))) {
        xapian_query_t *xq = xapian_query_new_match(db, SEARCH_PART_BCC, match);
        if (xq) ptrarray_append(&xqs, xq);
    }
    if ((match = json_string_value(json_object_get(filter, "subject")))) {
        xapian_query_t *xq = xapian_query_new_match(db, SEARCH_PART_SUBJECT, match);
        if (xq) ptrarray_append(&xqs, xq);
    }
    if ((match = json_string_value(json_object_get(filter, "body")))) {
        xapian_query_t *xq = xapian_query_new_match(db, SEARCH_PART_BODY, match);
        if (xq) ptrarray_append(&xqs, xq);
    }
    if ((match = json_string_value(json_object_get(filter, "fromContactGroupId")))) {
        xapian_query_t *xq = _email_matchmime_contactgroup(match, SEARCH_PART_FROM, db, cfilter);
        if (xq) ptrarray_append(&xqs, xq);
    }
    if ((match = json_string_value(json_object_get(filter, "toContactGroupId")))) {
        xapian_query_t *xq = _email_matchmime_contactgroup(match, SEARCH_PART_TO, db, cfilter);
        if (xq) ptrarray_append(&xqs, xq);
    }
    if ((match = json_string_value(json_object_get(filter, "ccContactGroupId")))) {
        xapian_query_t *xq = _email_matchmime_contactgroup(match, SEARCH_PART_CC, db, cfilter);
        if (xq) ptrarray_append(&xqs, xq);
    }
    if ((match = json_string_value(json_object_get(filter, "bccContactGroupId")))) {
        xapian_query_t *xq = _email_matchmime_contactgroup(match, SEARCH_PART_BCC, db, cfilter);
        if (xq) ptrarray_append(&xqs, xq);
    }
    if (xqs.count) {
        matches = 0;
        xapian_query_t *xq = xapian_query_new_compound(db, /*is_or*/0,
                (xapian_query_t **) xqs.data, xqs.count);
        xapian_query_run(db, xq, 0, _email_matchmime_evaluate_xcb, &matches);
        xapian_query_free(xq);
    }
    ptrarray_fini(&xqs);
    if (!matches) return 0;

    /* size */
    if (json_object_get(filter, "minSize") || json_object_get(filter, "maxSize")) {
        uint32_t size;
        if (message_get_size(m, &size) == 0) {
            json_int_t jint;
            if ((jint = json_integer_value(json_object_get(filter, "minSize"))) > 0) {
                if (size < jint) return 0;
            }
            if ((jint = json_integer_value(json_object_get(filter, "maxSize"))) > 0) {
                if (size > jint) return 0;
            }
        }
    }

    json_t *jval;

    /* hasAttachment */
    if (JNOTNULL(jval = json_object_get(filter, "hasAttachment"))) {
        const struct body *body;
        if (message_get_cachebody(m, &body) == 0) {
            struct emailbodies bodies = EMAILBODIES_INITIALIZER;
            if (jmap_emailbodies_extract(body, &bodies) == 0) {
                int have = ptrarray_size(&bodies.attslist) > 0;
                int want = jval == json_true();
                if (have != want) {
                    matches = 0;
                }
            }
            jmap_emailbodies_fini(&bodies);
        }
    }

    /* header */
    if (JNOTNULL((jval = json_object_get(filter, "header")))) {
        const char *hdr, *val;

        if (json_array_size(jval) == 2) {
            hdr = json_string_value(json_array_get(jval, 0));
            val = json_string_value(json_array_get(jval, 1));
        } else {
            hdr = json_string_value(json_array_get(jval, 0));
            val = NULL; // match any value
        }

        matches = 0;

        /* Replicate match_header logic in search_expr.c */
        char *lhdr = lcase(xstrdup(hdr));
        struct buf buf = BUF_INITIALIZER;
        int r = message_get_field(m, lhdr,
                MESSAGE_DECODED|MESSAGE_APPEND|MESSAGE_MULTIPLE, &buf);
        if (!r) {
            if (val) {
                charset_t utf8 = charset_lookupname("utf-8");
                char *v = NULL;
                if ((v = charset_convert(val, utf8, charset_flags))) {
                    comp_pat *pat = charset_compilepat(v);
                    if (pat) {
                        matches = charset_searchstring(v, pat, buf.s, buf.len,
                                                       charset_flags);
                    }
                    charset_freepat(pat);
                }
                free(v);
                charset_free(&utf8);
            }
            else {
                matches = buf_len(&buf) > 0;
            }
        }
        buf_free(&buf);
        free(lhdr);

        if (!matches) return 0;
    }

    /* before */
    if (JNOTNULL(jval = json_object_get(filter, "before"))) {
        time_t t;
        time_from_iso8601(json_string_value(jval), &t);
        if (internaldate >= t) return 0;
    }
    /* after */
    if (JNOTNULL(jval = json_object_get(filter, "after"))) {
        time_t t;
        time_from_iso8601(json_string_value(jval), &t);
        if (internaldate < t) return 0;
    }

    return matches;
}

HIDDEN int jmap_email_matchmime(struct buf *mime,
                                json_t *jfilter,
                                const char *accountid,
                                time_t internaldate,
                                json_t **err)
{
    int r = 0;
    xapian_dbw_t *dbw = NULL;
    message_t *m = NULL;
    int matches = 0;

    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    strarray_t capabilities = STRARRAY_INITIALIZER;
    struct email_contactfilter cfilter;

    json_t *unsupported = json_array();

    /* Parse filter */
    strarray_append(&capabilities, JMAP_URN_MAIL);
    strarray_append(&capabilities, JMAP_MAIL_EXTENSION);
    jmap_email_filter_parse(&parser, jfilter, unsupported, &capabilities);

    /* Gather contactgroup ids */
    jmap_email_contactfilter_init(accountid, /*addressbookid*/NULL, &cfilter);
    ptrarray_t work = PTRARRAY_INITIALIZER;
    ptrarray_push(&work, jfilter);
    json_t *jf;
    while ((jf = ptrarray_pop(&work))) {
        size_t i;
        json_t *jval;
        json_array_foreach(json_object_get(jf, "conditions"), i, jval) {
            ptrarray_push(&work, jval);
        }
        r = jmap_email_contactfilter_from_filtercondition(&parser, jf, &cfilter);
        if (r) break;

    }
    ptrarray_fini(&work);
    if (r) {
        syslog(LOG_ERR, "jmap_matchmime: can't load contactgroups from filter: %s",
                error_message(r));
        *err = jmap_server_error(r);
        goto done;
    }
    else if (json_array_size(parser.invalid)) {
        *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                "arguments", parser.invalid);
        goto done;
    }
    else if (json_array_size(unsupported)) {
        *err = json_pack("{s:s s:O}", "type", "unsupportedFilter",
                         "filters", unsupported);
        goto done;
    }

    /* Parse message into memory */
    m = message_new_from_data(buf_base(mime), buf_len(mime));
    if (!m) {
        syslog(LOG_ERR, "jmap_matchmime: can't create Cyrus message");
        *err = jmap_server_error(r);
        goto done;
    }

    /* Open in-memory search index */
    r = xapian_dbw_openmem(&dbw);
    if (r) {
        syslog(LOG_ERR, "jmap_matchmime: can't open in-memory search backend: %s",
                error_message(r));
        *err = jmap_server_error(r);
        goto done;
    }

    /* Index message bodies in-memory */
    struct matchmime_receiver tr = {
        {
            _matchmime_tr_begin_mailbox,
            _matchmime_tr_first_unindexed_uid,
            _matchmime_tr_is_indexed,
            _matchmime_tr_begin_message,
            _matchmime_tr_begin_part,
            _matchmime_tr_append_text,
            _matchmime_tr_end_part,
            _matchmime_tr_end_message,
            _matchmime_tr_end_mailbox,
            _matchmime_tr_flush,
            _matchmime_tr_audit_mailbox,
            _matchmime_tr_index_charset_flags,
        },
        dbw, BUF_INITIALIZER
    };
    r = index_getsearchtext(m, NULL, (struct search_text_receiver*) &tr, /*snippet*/0);
    if (r) {
        syslog(LOG_ERR, "jmap_matchmime: can't index MIME message: %s",
                error_message(r));
        *err = jmap_server_error(r);
        goto done;
    }
    buf_free(&tr.buf);

    /* Evaluate filter */
    xapian_db_t *db = NULL;
    r = xapian_db_opendbw(dbw, &db);
    if (r) {
        syslog(LOG_ERR, "jmap_matchmime: can't open query backend: %s",
                error_message(r));
        *err = jmap_server_error(r);
        goto done;
    }
    matches = _email_matchmime_evaluate(jfilter, m, db, &cfilter, internaldate);
    xapian_db_close(db);

done:
    jmap_email_contactfilter_fini(&cfilter);
    jmap_parser_fini(&parser);
    strarray_fini(&capabilities);
    json_decref(unsupported);
    xapian_dbw_close(dbw);
    message_unref(&m);
    return matches;
}

#endif /* WITH_DAV */

