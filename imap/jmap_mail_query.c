/* jmap_mail_query.c -- Helper routines for JMAP Email/query
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
#include <errno.h>

#include "libconfig.h"

#include "jmap_mail_query.h"
#include "jmap_util.h"
#include "json_support.h"
#include "search_engines.h"
#include "xapian_wrap.h"

#include "imap/imap_err.h"

#ifndef JMAP_URN_MAIL
#define JMAP_URN_MAIL                "urn:ietf:params:jmap:mail"
#endif
#ifndef JMAP_MAIL_EXTENSION
#define JMAP_MAIL_EXTENSION          "https://cyrusimap.org/ns/jmap/mail"
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


#ifdef WITH_DAV

#include "annotate.h"
#include "carddav_db.h"
#include "global.h"
#include "hash.h"
#include "index.h"
#include "search_query.h"
#include "times.h"

HIDDEN void jmap_email_contactfilter_init(const char *accountid,
                                          const struct auth_state *authstate,
                                          const struct namespace *namespace,
                                          const char *addressbookid,
                                          struct email_contactfilter *cfilter)
{
    memset(cfilter, 0, sizeof(struct email_contactfilter));
    cfilter->accountid = accountid;
    cfilter->authstate = authstate;
    cfilter->namespace = namespace;
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


static int _get_sharedaddressbook_cb(struct findall_data *data, void *rock)
{
    mbentry_t **mbentryp = rock;
    if (!data || !data->mbentry) return 0;
    *mbentryp = mboxlist_entry_copy(data->mbentry);
    return CYRUSDB_DONE;
}

static mbentry_t *_get_sharedaddressbook(const char *userid,
                                         const struct auth_state *authstate,
                                         const struct namespace *namespace)
{
    mbentry_t *res = NULL;

    strarray_t patterns = STRARRAY_INITIALIZER;
    struct buf pattern = BUF_INITIALIZER;
    buf_setcstr(&pattern, "user");
    buf_putc(&pattern, namespace->hier_sep);
    buf_putc(&pattern, '*');
    buf_putc(&pattern, namespace->hier_sep);
    buf_appendcstr(&pattern, config_getstring(IMAPOPT_ADDRESSBOOKPREFIX));
    buf_putc(&pattern, namespace->hier_sep);
    buf_appendcstr(&pattern, "Shared");
    buf_cstring(&pattern);
    strarray_appendm(&patterns, buf_release(&pattern));
    mboxlist_findallmulti((struct namespace*)namespace, &patterns, 0, userid,
            authstate, _get_sharedaddressbook_cb, &res);
    strarray_fini(&patterns);

    return res;
}

static const struct contactfilters_t {
    const char *field;
    int isany;
} contactfilters[] = {
  { "fromContactGroupId", 0 },
  { "toContactGroupId", 0 },
  { "ccContactGroupId", 0 },
  { "bccContactGroupId", 0 },
  { "fromAnyContact", 1 },
  { "toAnyContact", 1 },
  { "ccAnyContact", 1 },
  { "bccAnyContact", 1 },
  { NULL, 0 }
};

HIDDEN int jmap_email_contactfilter_from_filtercondition(struct jmap_parser *parser,
                                                         json_t *filter,
                                                         struct email_contactfilter *cfilter)
{
    int havefield = 0;
    const struct contactfilters_t *c;
    mbentry_t *othermb = NULL;
    int r = 0;

    /* prefilter to see if there are any fields that we will need to look up */
    for (c = contactfilters; c->field; c++) {
        json_t *arg = json_object_get(filter, c->field);
        if (!arg) continue;
        const char *groupid = c->isany ? (json_is_true(arg) ? "" : NULL) : json_string_value(arg);
        if (!groupid) continue; // avoid looking up if invalid!
        havefield = 1;
        break;
    }
    if (!havefield) goto done;

    /* ensure we have preconditions for lookups */
    if (!cfilter->contactgroups.size) {
        /* Initialize groups lookup table */
        construct_hash_table(&cfilter->contactgroups, 32, 0);
    }

    if (!cfilter->carddavdb) {
        /* Open CardDAV db first time we need it */
        cfilter->carddavdb = carddav_open_userid(cfilter->accountid);
        if (!cfilter->carddavdb) {
            syslog(LOG_ERR, "jmap: carddav_open_userid(%s) failed",
                   cfilter->accountid);
            r = CYRUSDB_INTERNAL;
            goto done;
        }
    }

    othermb = _get_sharedaddressbook(cfilter->accountid, cfilter->authstate, cfilter->namespace);
    if (othermb) {
        mbname_t *mbname = mbname_from_intname(othermb->name);
        int r2 = carddav_set_otheruser(cfilter->carddavdb, mbname_userid(mbname));
        if (r2) syslog(LOG_NOTICE, "DBNOTICE: failed to open otheruser %s contacts for %s",
                 mbname_userid(mbname), cfilter->accountid);
        mbname_free(&mbname);
    }

    /* fetch members for each filter referenced */

    for (c = contactfilters; c->field; c++) {
        json_t *arg = json_object_get(filter, c->field);
        if (!arg) continue;
        const char *groupid = c->isany ? (json_is_true(arg) ? "" : NULL) : json_string_value(arg);
        if (!groupid) continue;
        if (hash_lookup(groupid, &cfilter->contactgroups)) continue;

        /* Lookup group member email addresses */
        mbentry_t *mbentry = NULL;
        strarray_t *members = NULL;
        if (!cfilter->addrbook ||
            !mboxlist_lookup(cfilter->addrbook, &mbentry, NULL)) {
            members = carddav_getgroup(cfilter->carddavdb, mbentry, groupid, othermb);
        }
        mboxlist_entry_free(&mbentry);
        if (!members) {
            jmap_parser_invalid(parser, c->field);
        }
        else {
            hash_insert(groupid, members, &cfilter->contactgroups);
        }
    }

done:
    mboxlist_entry_free(&othermb);
    return r;
}

HIDDEN int jmap_email_hasattachment(const struct body *part,
                                    json_t *imagesize_by_partid)
{
    if (!part) return 0;

    if (!strcmp(part->type, "MULTIPART")) {
        int i;
        for (i = 0; i < part->numparts; i++) {
            if (jmap_email_hasattachment(part->subpart + i, imagesize_by_partid)) {
                return 1;
            }
        }
        return 0;
    }

    if (!strcmp(part->type, "IMAGE")) {
        if (!strcmpsafe(part->disposition, "ATTACHMENT")) {
            return 1;
        }
        /* Check image dimensions, if available. Fall back to false positive. */
        ssize_t dim1 = SSIZE_MAX, dim2 = SSIZE_MAX;
        if (part->part_id) {
            json_t *imagesize = json_object_get(imagesize_by_partid, part->part_id);
            if (json_array_size(imagesize) >= 2) {
                dim1 = json_integer_value(json_array_get(imagesize, 0));
                dim2 = json_integer_value(json_array_get(imagesize, 1));
            }
        }
        return dim1 >= 256 && dim2 >= 256;
    }


    /* Determine file name, if any. */
    const char *filename = NULL;
    struct param *param;
    for (param = part->disposition_params; param; param = param->next) {
        if (!strncasecmp(param->attribute, "filename", 8)) {
            filename = param->value;
            break;
        }
    }
    if (!filename) {
        for (param = part->params; param; param = param->next) {
            if (!strncasecmp(param->attribute, "name", 4)) {
                filename = param->value;
                break;
            }
        }
    }
    if (filename) return 1;

    /* Signatures are no attachments */
    if (!strcmp(part->type, "APPLICATION") &&
            (!strcmp(part->subtype, "PGP-KEYS") ||
             !strcmp(part->subtype, "PGP-SIGNATURE") ||
             !strcmp(part->subtype, "PKCS7-SIGNATURE") ||
             !strcmp(part->subtype, "X-PKCS7-SIGNATURE"))) {
        return 0;
    }

    /* Unnamed octet streams are no attachments */
    if (!strcmp(part->type, "APPLICATION") &&
            !strcmp(part->subtype, "OCTET-STREAM")) {
        return 0;
    }

    /* All of the following are attachments */
    if ((!strcmp(part->type, "APPLICATION") &&
                !strcmp(part->subtype, "PDF"))) {
        return 1;
    }
    else if (!strcmp(part->type, "MESSAGE")) {
        // any message/* is an attachment
        return 1;
    }
    else if ((!strcmp(part->type, "TEXT") &&
                !strcmp(part->subtype, "RFC822"))) {
        return 1;
    }
    else if ((!strcmp(part->type, "TEXT") &&
                !strcmp(part->subtype, "CALENDAR"))) {
        return 1;
    }

    return !strcmpsafe(part->disposition, "ATTACHMENT");
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
                if (parttype == PLAIN && textlist) {
                    ptrarray_append(textlist, (void*) part);
                }
                else if (parttype == HTML && htmllist) {
                    ptrarray_append(htmllist, (void*) part);
                }
                else {
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
        if (textlist && htmllist && textlist_count == textlist->count) {
            for (j = htmllist_count; j < htmllist->count; j++)
                ptrarray_append(textlist, ptrarray_nth(htmllist, j));
        }
        /* Found TEXT part only */
        if (htmllist && textlist && htmllist_count == htmllist->count) {
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

struct matchmime {
    char *dbpath;
    xapian_dbw_t *dbw;
    message_t *m;
    const struct buf *mime;
    void *convmatch;
    uint8_t indexlevel;
};

struct matchmime_receiver {
    struct search_text_receiver super;
    struct matchmime *matchmime;
    struct buf buf;
    enum search_part part;
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

static uint8_t _matchmime_tr_is_indexed(search_text_receiver_t *rx __attribute__((unused)),
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
    return xapian_dbw_begin_doc(tr->matchmime->dbw, guid, 'G');
}

static int _matchmime_tr_begin_bodypart(search_text_receiver_t *rx __attribute__((unused)),
                                        const char *partid __attribute__((unused)),
                                        const struct message_guid *content_guid __attribute__((unused)),
                                        const char *type __attribute__((unused)),
                                        const char *subtype __attribute__((unused)))

{
    return 0;
}

static void _matchmime_tr_begin_part(search_text_receiver_t *rx, enum search_part part)
{
    struct matchmime_receiver *tr = (struct matchmime_receiver *) rx;
    tr->part = part;
}

static int _matchmime_tr_append_text(search_text_receiver_t *rx,
                                      const struct buf *text)
{
    struct matchmime_receiver *tr = (struct matchmime_receiver *) rx;

    if (config_search_maxsize) {
        if (buf_len(&tr->buf) >= config_search_maxsize) {
            return IMAP_MESSAGE_TOO_LARGE;
        }

        size_t n = config_search_maxsize - buf_len(&tr->buf);
        if (n > buf_len(text)) {
            n = buf_len(text);
        }
        buf_appendmap(&tr->buf, buf_base(text), n);
    }
    else {
        buf_append(&tr->buf, text);
    }

    return 0;
}

static void _matchmime_tr_end_part(search_text_receiver_t *rx)
{
    struct matchmime_receiver *tr = (struct matchmime_receiver *) rx;
    xapian_dbw_doc_part(tr->matchmime->dbw, &tr->buf, tr->part);
    buf_reset(&tr->buf);
    tr->part = SEARCH_PART_NONE;
}

static void _matchmime_tr_end_bodypart(search_text_receiver_t *rx __attribute__((unused)))
{
}

static int _matchmime_tr_end_message(search_text_receiver_t *rx, uint8_t indexlevel)
{
    struct matchmime_receiver *tr = (struct matchmime_receiver *) rx;
    tr->matchmime->indexlevel = indexlevel;
    return xapian_dbw_end_doc(tr->matchmime->dbw, indexlevel);
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
    return xapian_charset_flags(base_flags);
}

static int _matchmime_tr_index_message_format(int format __attribute__((unused)),
                                              int is_snippet __attribute__((unused)))
{
    return MESSAGE_SNIPPET;
}

static int _matchmime_eval_xcb(void *data __attribute__((unused)),
                                         size_t n, void *rock)
{
    bool *matches = rock;
    /* There's just a single message in the in-memory database,
     * so no need to check the message guid in the search result. */
    *matches = n > 0;
    return 0;
}

static xapian_query_t *_matchmime_query_new_contactgroup(const char *groupid,
                                                     int part,
                                                     xapian_db_t *db,
                                                     struct email_contactfilter *cfilter)
{
    xapian_query_t *xq = NULL;

    if (cfilter->contactgroups.size) {
        strarray_t *members = hash_lookup(groupid, &cfilter->contactgroups);
        if (members && strarray_size(members)) {
            ptrarray_t xsubqs = PTRARRAY_INITIALIZER;
            int i;
            for (i = 0; i < strarray_size(members); i++) {
                const char *member = strarray_nth(members, i);
                if (!strchr(member, '@')) continue;
                xapian_query_t *xsubq = xapian_query_new_match(db, part, member);
                if (xsubq) ptrarray_append(&xsubqs, xsubq);
            }
            if (ptrarray_size(&xsubqs)) {
                xq = xapian_query_new_compound(db, /*is_or*/1,
                        (xapian_query_t **) xsubqs.data, xsubqs.count);
            }
            ptrarray_fini(&xsubqs);
        }
    }
    if (!xq) {
        xq = xapian_query_new_not(db, xapian_query_new_matchall(db));
    }

    return xq;
}

static xapian_query_t *build_type_query(xapian_db_t *db, const char *type)
{
    strarray_t types = STRARRAY_INITIALIZER;
    ptrarray_t xqs = PTRARRAY_INITIALIZER;

    /* Handle type wildcards */
    if (!strcasecmp(type, "image")) {
        strarray_append(&types, "image/gif");
        strarray_append(&types, "image/jpeg");
        strarray_append(&types, "image/pjpeg");
        strarray_append(&types, "image/jpg");
        strarray_append(&types, "image/png");
        strarray_append(&types, "image/bmp");
        strarray_append(&types, "image/tiff");
    }
    else if (!strcasecmp(type, "document")) {
        strarray_append(&types, "application/msword");
        strarray_append(&types, "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
        strarray_append(&types, "application/vnd.openxmlformats-officedocument.wordprocessingml.template");
        strarray_append(&types, "application/vnd.sun.xml.writer");
        strarray_append(&types, "application/vnd.sun.xml.writer.template");
        strarray_append(&types, "application/vnd.oasis.opendocument.text");
        strarray_append(&types, "application/vnd.oasis.opendocument.text-template");
        strarray_append(&types, "application/x-iwork-pages-sffpages");
        strarray_append(&types, "application/vnd.apple.pages");
    }
    else if (!strcasecmp(type, "spreadsheet")) {
        strarray_append(&types, "application/vnd.ms-excel");
        strarray_append(&types, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        strarray_append(&types, "application/vnd.openxmlformats-officedocument.spreadsheetml.template");
        strarray_append(&types, "application/vnd.sun.xml.calc");
        strarray_append(&types, "application/vnd.sun.xml.calc.template");
        strarray_append(&types, "application/vnd.oasis.opendocument.spreadsheet");
        strarray_append(&types, "application/vnd.oasis.opendocument.spreadsheet-template");
        strarray_append(&types, "application/x-iwork-numbers-sffnumbers");
        strarray_append(&types, "application/vnd.apple.numbers");
    }
    else if (!strcasecmp(type, "presentation")) {
        strarray_append(&types, "application/vnd.ms-powerpoint");
        strarray_append(&types, "application/vnd.openxmlformats-officedocument.presentationml.presentation");
        strarray_append(&types, "application/vnd.openxmlformats-officedocument.presentationml.template");
        strarray_append(&types, "application/vnd.openxmlformats-officedocument.presentationml.slideshow");
        strarray_append(&types, "application/vnd.sun.xml.impress");
        strarray_append(&types, "application/vnd.sun.xml.impress.template");
        strarray_append(&types, "application/vnd.oasis.opendocument.presentation");
        strarray_append(&types, "application/vnd.oasis.opendocument.presentation-template");
        strarray_append(&types, "application/x-iwork-keynote-sffkey");
        strarray_append(&types, "application/vnd.apple.keynote");
    }
    else if (!strcasecmp(type, "email")) {
        strarray_append(&types, "message/rfc822");
    }
    else if (!strcasecmp(type, "pdf")) {
        strarray_append(&types, "application/pdf");
    }
    else {
        strarray_append(&types, type);
    }

    /* Build expression */
    int i;
    for (i = 0; i < strarray_size(&types); i++) {
        const char *t = strarray_nth(&types, i);
        xapian_query_t *xq = xapian_query_new_match(db, SEARCH_PART_TYPE, t);
        if (xq) ptrarray_append(&xqs, xq);
    }
    xapian_query_t *xq = xapian_query_new_compound(db, /*is_or*/1,
                          (xapian_query_t **) xqs.data, xqs.count);

    ptrarray_fini(&xqs);
    strarray_fini(&types);
    return xq;
}

enum matchmime_op {
    MATCHMIME_OP_AND = 1,
    MATCHMIME_OP_OR,
    MATCHMIME_OP_NOT,
    MATCHMIME_OP_MATCHALL,
    MATCHMIME_OP_MATCHNONE,

    MATCHMIME_OP_XAPIAN = 32,
    MATCHMIME_OP_MINSIZE,
    MATCHMIME_OP_MAXSIZE,
    MATCHMIME_OP_HASATTACH,
    MATCHMIME_OP_HEADER,
    MATCHMIME_OP_BEFORE,
    MATCHMIME_OP_AFTER,
    MATCHMIME_OP_CONVKEYWORD_ALL,
    MATCHMIME_OP_CONVKEYWORD_SOME,
    MATCHMIME_OP_CONVKEYWORD_NONE,
};

typedef struct matchmime_query {
    enum matchmime_op op;
    union {
        ptrarray_t elems;
        xapian_query_t *xq;
        uint32_t u32;
        struct jmap_headermatch *hm;
        time_t time;
        char *string;
        bool boolean;
    } v;
} matchmime_query_t;

static void _matchmime_query_free(matchmime_query_t **qptr)
{
    if (!qptr || !*qptr) return;

    matchmime_query_t *q = *qptr;
    switch (q->op) {
    case MATCHMIME_OP_AND:
    case MATCHMIME_OP_OR:
    case MATCHMIME_OP_NOT: {
        for (int i = 0; i < ptrarray_size(&q->v.elems); i++) {
            matchmime_query_t *subq = ptrarray_nth(&q->v.elems, i);
            _matchmime_query_free(&subq);
        }
        ptrarray_fini(&q->v.elems);
        break;
    }
    case MATCHMIME_OP_XAPIAN:
        xapian_query_free(q->v.xq);
        break;
    case MATCHMIME_OP_HEADER:
        jmap_headermatch_free(&q->v.hm);
        break;
    case MATCHMIME_OP_CONVKEYWORD_ALL:
    case MATCHMIME_OP_CONVKEYWORD_SOME:
    case MATCHMIME_OP_CONVKEYWORD_NONE:
        free(q->v.string);
        break;
    default:
        ; // do nothing
    }

    free(q);
    *qptr = NULL;
}

__attribute__((unused))
static void _matchmime_query_serialize(matchmime_query_t *q, struct buf *buf)
{
    switch (q->op) {
    case MATCHMIME_OP_AND:
    case MATCHMIME_OP_OR:
    case MATCHMIME_OP_NOT: {
        if (q->op == MATCHMIME_OP_AND)
            buf_appendcstr(buf, "AND");
        else if (q->op == MATCHMIME_OP_OR)
            buf_appendcstr(buf, "OR");
        else if (q->op == MATCHMIME_OP_NOT)
            buf_appendcstr(buf, "NOT");
        buf_putc(buf, '(');
        for (int i = 0; i < ptrarray_size(&q->v.elems); i++) {
            if (i) buf_putc(buf, ',');
            matchmime_query_t *subq = ptrarray_nth(&q->v.elems, i);
            _matchmime_query_serialize(subq, buf);
        }
        buf_putc(buf, ')');
        break;
    }
    case MATCHMIME_OP_MATCHALL:
        buf_appendcstr(buf, "MATCHALL");
        break;
    case MATCHMIME_OP_MATCHNONE:
        buf_appendcstr(buf, "MATCHNONE");
        break;
    case MATCHMIME_OP_XAPIAN:
        buf_appendcstr(buf, "XAPIAN");
        buf_putc(buf, '{');
        xapian_query_serialize(q->v.xq, buf);
        buf_putc(buf, '}');
        break;
    case MATCHMIME_OP_MINSIZE:
    case MATCHMIME_OP_MAXSIZE: {
        if (q->op == MATCHMIME_OP_MINSIZE)
            buf_appendcstr(buf, "MINSIZE");
        else if (q->op == MATCHMIME_OP_MAXSIZE)
            buf_appendcstr(buf, "MAXSIZE");
        buf_printf(buf, "{%u}", q->v.u32);
        break;
    }
    case MATCHMIME_OP_HASATTACH: {
        buf_appendcstr(buf, "HASATTACH");
        buf_printf(buf, "{%s}", q->v.boolean ? "true" : "false");
        break;
    }
    case MATCHMIME_OP_HEADER:
        buf_appendcstr(buf, "HEADER");
        buf_putc(buf, '{');
        jmap_headermatch_serialize(q->v.hm, buf);
        buf_putc(buf, '}');
        break;
    case MATCHMIME_OP_BEFORE:
        buf_appendcstr(buf, "BEFORE");
        buf_printf(buf, "{%ld}", q->v.time);
        break;
    case MATCHMIME_OP_AFTER:
        buf_appendcstr(buf, "AFTER");
        buf_printf(buf, "{%ld}", q->v.time);
        break;
    case MATCHMIME_OP_CONVKEYWORD_ALL:
        buf_appendcstr(buf, "CONVKEYWORD_ALL");
        buf_printf(buf, "{%s}", q->v.string);
        break;
    case MATCHMIME_OP_CONVKEYWORD_SOME:
        buf_appendcstr(buf, "CONVKEYWORD_SOME");
        buf_printf(buf, "{%s}", q->v.string);
        break;
    case MATCHMIME_OP_CONVKEYWORD_NONE:
        buf_appendcstr(buf, "CONVKEYWORD_NONE");
        buf_printf(buf, "{%s}", q->v.string);
        break;
    }
}

static matchmime_query_t *_matchmime_query_new_xq(xapian_query_t *xq)
{
    matchmime_query_t *q = xzmalloc(sizeof(matchmime_query_t));
    q->op = MATCHMIME_OP_XAPIAN;
    q->v.xq = xq;
    return q;
}

static matchmime_query_t *matchmime_query_new_u32(enum matchmime_op op, uint32_t u32)
{
    matchmime_query_t *expr = xzmalloc(sizeof(matchmime_query_t));
    expr->op = op;
    expr->v.u32 = u32;
    return expr;
}

static matchmime_query_t *matchmime_query_new_time(enum matchmime_op op, time_t t)
{
    matchmime_query_t *expr = xzmalloc(sizeof(matchmime_query_t));
    expr->op = op;
    expr->v.time = t;
    return expr;
}

static matchmime_query_t *matchmime_query_new_string(enum matchmime_op op, const char *s)
{
    matchmime_query_t *expr = xzmalloc(sizeof(matchmime_query_t));
    expr->op = op;
    expr->v.string = xstrdup(s);
    return expr;
}

static matchmime_query_t *_matchmime_query_new_internal(json_t *filter,
                                                        xapian_db_t *xdb,
                                                        struct email_contactfilter *cfilter)
{
    if (!json_object_size(filter)) {
        matchmime_query_t *q = xzmalloc(sizeof(matchmime_query_t));
        q->op = MATCHMIME_OP_MATCHALL;
        return q;
    }

    json_t *conditions = json_object_get(filter, "conditions");
    if (json_is_array(conditions)) {
        // Build query for FilterOperator.
        enum matchmime_op op;
        const char *strop = json_string_value(json_object_get(filter, "operator"));
        if (!strcasecmpsafe(strop, "AND"))
            op = MATCHMIME_OP_AND;
        else if (!strcasecmpsafe(strop, "OR"))
            op = MATCHMIME_OP_OR;
        else if (!strcasecmpsafe(strop, "NOT"))
            op = MATCHMIME_OP_NOT;
        else
            return NULL;

        matchmime_query_t *q = xzmalloc(sizeof(matchmime_query_t));
        q->op = op;

        json_t *condition;
        size_t i;
        ptrarray_t xap_queries = PTRARRAY_INITIALIZER;
        json_array_foreach(conditions, i, condition) {
            matchmime_query_t *subq =
                _matchmime_query_new_internal(condition, xdb, cfilter);
            if (subq && subq->op == MATCHMIME_OP_XAPIAN)
                ptrarray_append(&xap_queries, subq);
            else if (subq)
                ptrarray_append(&q->v.elems, subq);
        }

        if (q->op == MATCHMIME_OP_AND || q->op == MATCHMIME_OP_OR) {
            bool is_or = q->op == MATCHMIME_OP_OR;

            if (ptrarray_size(&xap_queries)) {
                // Combine Xapian queries into a single Xapian query.
                xapian_query_t **xqs = xmalloc(sizeof(xapian_query_t *)
                                               * ptrarray_size(&xap_queries));
                for (int i = 0; i < ptrarray_size(&xap_queries); i++) {
                    matchmime_query_t *xap_query =
                        ptrarray_nth(&xap_queries, i);
                    xqs[i] = xap_query->v.xq; // move
                    free(xap_query);
                }

                xapian_query_t *xq = xapian_query_new_compound(
                    xdb, is_or, xqs, ptrarray_size(&xap_queries));

                if (ptrarray_size(&q->v.elems)) {
                    // AND/OR node consists of both Xapian queries and
                    // non-Xapian queries. Add the compound Xapian query.
                    matchmime_query_t *xap_query = _matchmime_query_new_xq(xq);
                    ptrarray_unshift(&q->v.elems, xap_query);
                }
                else {
                    // Replace AND/OR node with compound Xapian query.
                    q->op = MATCHMIME_OP_XAPIAN;
                    q->v.xq = xq;
                }

                free(xqs);
            }
            else if (!ptrarray_size(&q->v.elems)) {
                // Empty AND/OR, this must be due the subterm
                // of this query isn't supported by Xapian.
                q->op = MATCHMIME_OP_XAPIAN;
                q->v.xq = xapian_query_new_compound(
                    xdb, q->op == MATCHMIME_OP_OR, NULL, 0);
            }
        }
        else {
            for (int i = 0; i < ptrarray_size(&xap_queries); i++) {
                matchmime_query_t *xap_query = ptrarray_nth(&xap_queries, i);
                ptrarray_append(&q->v.elems, xap_query);
            }
        }

        ptrarray_fini(&xap_queries);
        return q;
    }

    // Build query for FilterCondition.

    ptrarray_t queries = PTRARRAY_INITIALIZER;
    json_t *jval;

    /* Xapian-backed criteria */
    const char *match;
    if ((match = json_string_value(json_object_get(filter, "text")))) {
        ptrarray_t childqueries = PTRARRAY_INITIALIZER;
        int i;
        for (i = 0 ; i < SEARCH_NUM_PARTS ; i++) {
            switch (i) {
                case SEARCH_PART_ANY:
                case SEARCH_PART_LISTID:
                case SEARCH_PART_TYPE:
                case SEARCH_PART_LANGUAGE:
                case SEARCH_PART_PRIORITY:
                    continue;
            }
            void *xq = xapian_query_new_match(xdb, i, match);
            if (xq) ptrarray_push(&childqueries, xq);
        }
        xapian_query_t *xq = xapian_query_new_compound(xdb, /*is_or*/1,
                                       (xapian_query_t **)childqueries.data,
                                       childqueries.count);

        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
        ptrarray_fini(&childqueries);
    }

    if ((match = json_string_value(json_object_get(filter, "from")))) {
        xapian_query_t *xq =
            xapian_query_new_match(xdb, SEARCH_PART_FROM, match);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match = json_string_value(json_object_get(filter, "to")))) {
        xapian_query_t *xq = xapian_query_new_match(xdb, SEARCH_PART_TO, match);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match = json_string_value(json_object_get(filter, "cc")))) {
        xapian_query_t *xq = xapian_query_new_match(xdb, SEARCH_PART_CC, match);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match = json_string_value(json_object_get(filter, "bcc")))) {
        xapian_query_t *xq = xapian_query_new_match(xdb, SEARCH_PART_BCC, match);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match = json_string_value(json_object_get(filter, "deliveredTo")))) {
        xapian_query_t *xq =
            xapian_query_new_match(xdb, SEARCH_PART_DELIVEREDTO, match);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match = json_string_value(json_object_get(filter, "subject")))) {
        xapian_query_t *xq =
            xapian_query_new_match(xdb, SEARCH_PART_SUBJECT, match);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match = json_string_value(json_object_get(filter, "body")))) {
        xapian_query_t *xq =
            xapian_query_new_match(xdb, SEARCH_PART_BODY, match);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match =
             json_string_value(json_object_get(filter, "fromContactGroupId"))))
    {
        xapian_query_t *xq = _matchmime_query_new_contactgroup(
            match, SEARCH_PART_FROM, xdb, cfilter);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match =
             json_string_value(json_object_get(filter, "toContactGroupId")))) {
        xapian_query_t *xq = _matchmime_query_new_contactgroup(
            match, SEARCH_PART_TO, xdb, cfilter);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match =
             json_string_value(json_object_get(filter, "ccContactGroupId")))) {
        xapian_query_t *xq = _matchmime_query_new_contactgroup(
            match, SEARCH_PART_CC, xdb, cfilter);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match =
             json_string_value(json_object_get(filter, "bccContactGroupId")))) {
        xapian_query_t *xq = _matchmime_query_new_contactgroup(
            match, SEARCH_PART_BCC, xdb, cfilter);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((json_is_true(json_object_get(filter, "fromAnyContact")))) {
        xapian_query_t *xq = _matchmime_query_new_contactgroup(
            "", SEARCH_PART_FROM, xdb, cfilter);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((json_is_true(json_object_get(filter, "toAnyContact")))) {
        xapian_query_t *xq = _matchmime_query_new_contactgroup(
            "", SEARCH_PART_TO, xdb, cfilter);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((json_is_true(json_object_get(filter, "ccAnyContact")))) {
        xapian_query_t *xq = _matchmime_query_new_contactgroup(
            "", SEARCH_PART_CC, xdb, cfilter);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((json_is_true(json_object_get(filter, "bccAnyContact")))) {
        xapian_query_t *xq = _matchmime_query_new_contactgroup(
            "", SEARCH_PART_BCC, xdb, cfilter);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match = json_string_value(json_object_get(filter, "attachmentName"))))
    {
        xapian_query_t *xq =
            xapian_query_new_match(xdb, SEARCH_PART_ATTACHMENTNAME, match);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match = json_string_value(json_object_get(filter, "attachmentType"))))
    {
        xapian_query_t *xq = build_type_query(xdb, match);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match = json_string_value(json_object_get(filter, "attachmentBody"))))
    {
        xapian_query_t *xq =
            xapian_query_new_match(xdb, SEARCH_PART_ATTACHMENTBODY, match);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match = json_string_value(json_object_get(filter, "inReplyTo")))) {
        xapian_query_t *xq =
            xapian_query_new_match(xdb, SEARCH_PART_INREPLYTO, match);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match = json_string_value(json_object_get(filter, "listId")))) {
        xapian_query_t *xq =
            xapian_query_new_match(xdb, SEARCH_PART_LISTID, match);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match = json_string_value(json_object_get(filter, "messageId")))) {
        xapian_query_t *xq =
            xapian_query_new_match(xdb, SEARCH_PART_MESSAGEID, match);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if ((match = json_string_value(json_object_get(filter, "references")))) {
        xapian_query_t *xq =
            xapian_query_new_match(xdb, SEARCH_PART_REFERENCES, match);
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    if (JNOTNULL(jval = json_object_get(filter, "isHighPriority"))) {
        xapian_query_t *xq =
            xapian_query_new_match(xdb, SEARCH_PART_PRIORITY, "1");
        if (xq && !json_boolean_value(jval)) {
            xq = xapian_query_new_not(xdb, xq);
        }
        if (xq) ptrarray_append(&queries, _matchmime_query_new_xq(xq));
    }
    // ignore attachmentBody

    /* size */
    if (JNOTNULL(jval = json_object_get(filter, "minSize"))) {
        json_int_t val = json_integer_value(jval);
        val = (val > UINT32_MAX) ? UINT32_MAX : val < 0 ? 0 : val;
        ptrarray_append(&queries, matchmime_query_new_u32(MATCHMIME_OP_MINSIZE, val));
    }
    if (JNOTNULL(jval = json_object_get(filter, "maxSize"))) {
        json_int_t val = json_integer_value(jval);
        val = (val > UINT32_MAX) ? UINT32_MAX : val < 0 ? 0 : val;
        ptrarray_append(&queries, matchmime_query_new_u32(MATCHMIME_OP_MAXSIZE, val));
    }

    /* hasAttachment */
    if (JNOTNULL(jval = json_object_get(filter, "hasAttachment"))) {
        matchmime_query_t *q = xzmalloc(sizeof(matchmime_query_t));
        q->op = MATCHMIME_OP_HASATTACH;
        q->v.boolean = json_boolean_value(jval);
        ptrarray_append(&queries, q);
    }

    /* header */
    if (JNOTNULL((jval = json_object_get(filter, "header")))) {
        const char *hdr = NULL, *val = "", *cmp = NULL;

        switch (json_array_size(jval)) {
            case 3:
                cmp = json_string_value(json_array_get(jval, 2));
                GCC_FALLTHROUGH
            case 2:
                val = json_string_value(json_array_get(jval, 1));
                GCC_FALLTHROUGH
            case 1:
                hdr = json_string_value(json_array_get(jval, 0));
                break;
            default:
                return 0;
        }

        matchmime_query_t *q = xzmalloc(sizeof(matchmime_query_t));
        q->op = MATCHMIME_OP_HEADER;
        q->v.hm = jmap_headermatch_new(hdr, val, cmp);
        ptrarray_append(&queries, q);
    }

    /* before */
    if (JNOTNULL(jval = json_object_get(filter, "before"))) {
        time_t t;
        time_from_iso8601(json_string_value(jval), &t);
        ptrarray_append(&queries, matchmime_query_new_time(MATCHMIME_OP_BEFORE, t));
    }
    /* after */
    if (JNOTNULL(jval = json_object_get(filter, "after"))) {
        time_t t;
        time_from_iso8601(json_string_value(jval), &t);
        ptrarray_append(&queries, matchmime_query_new_time(MATCHMIME_OP_AFTER, t));
    }

    /* allInThreadHaveKeyword */
    if (JNOTNULL(jval = json_object_get(filter, "allInThreadHaveKeyword"))) {
        const char *s = json_string_value(jval);
        matchmime_query_t *q =
            matchmime_query_new_string(MATCHMIME_OP_CONVKEYWORD_ALL, s);
        ptrarray_append(&queries, q);
    }

    /* someInThreadHaveKeyword */
    if (JNOTNULL(jval = json_object_get(filter, "someInThreadHaveKeyword"))) {
        const char *s = json_string_value(jval);
        matchmime_query_t *q =
            matchmime_query_new_string(MATCHMIME_OP_CONVKEYWORD_SOME, s);
        ptrarray_append(&queries, q);
    }

    /* noneInThreadHaveKeyword */
    if (JNOTNULL(jval = json_object_get(filter, "noneInThreadHaveKeyword"))) {
        const char *s = json_string_value(jval);
        matchmime_query_t *q =
            matchmime_query_new_string(MATCHMIME_OP_CONVKEYWORD_NONE, s);
        ptrarray_append(&queries, q);
    }

    if (ptrarray_size(&queries) == 1) {
        matchmime_query_t *q = ptrarray_pop(&queries);
        ptrarray_fini(&queries);
        return q;
    }
    else if (ptrarray_size(&queries)) {
        matchmime_query_t *q = xzmalloc(sizeof(matchmime_query_t));
        q->op = MATCHMIME_OP_AND;
        q->v.elems = queries; // move
        return q;
    }
    else {
        // The filter condition contains at least one query criteria
        // but we could not convert any of them. This happens for
        // text-search criteria, for which Xapian did not generate
        // any query term for. For compatibility with Email/query,
        // we neither return MatchAll or MatchNone, but rather let
        // the parent expression ignore this unsupported search text.
        return NULL;
    }
}

static matchmime_query_t *_matchmime_buildquery(json_t *filter,
                                                xapian_db_t *xdb,
                                                struct email_contactfilter *cfilter)
{
    matchmime_query_t *q = _matchmime_query_new_internal(filter, xdb, cfilter);
    if (!q) {
        // This filter only contains criteria for which the Xapian
        // backend does not include the required search terms. For
        // compatibility with Email/query, this filter converts to
        // MatchNone.
        matchmime_query_t *q = xzmalloc(sizeof(matchmime_query_t));
        q->op = MATCHMIME_OP_MATCHNONE;
        return q;
    }
    return q;
}

struct convmatch {
    struct conversations_state *cstate;
    arrayu64_t cids;
    dynarray_t convs;
    int in_state; // -1: error, 0: need to load cids, 1: cids loaded
};

static void convmatch_reset(struct convmatch *convmatch,
                            struct conversations_state *cstate)
{
    if (!convmatch) return;

    int i;
    for (i = 0; i < dynarray_size(&convmatch->convs); i++) {
        conversation_t *conv = dynarray_nth(&convmatch->convs, i);
        conversation_fini(conv);
    }
    dynarray_fini(&convmatch->convs);
    arrayu64_fini(&convmatch->cids);
    convmatch->in_state = 0;

    convmatch->cstate = cstate;
    dynarray_init(&convmatch->convs, sizeof(conversation_t));
}

static bool _matchmime_eval_convkeyword(matchmime_query_t *q,
                                           struct convmatch *convmatch,
                                           message_t *m)
{
    assert(q->op == MATCHMIME_OP_CONVKEYWORD_ALL
           || q->op == MATCHMIME_OP_CONVKEYWORD_SOME
           || q->op == MATCHMIME_OP_CONVKEYWORD_NONE);

    const char *flag = jmap_keyword_to_imap(q->v.string);
    int num;
    if (!strcasecmp(flag, "\\Seen")) {
        num = 0;
    }
    else if (!convmatch->cstate || !convmatch->cstate->counted_flags) {
        num = -1;
    }
    else {
        num = strarray_find_case(convmatch->cstate->counted_flags, flag, 0);
        /* num might be -1 invalid */
        if (num >= 0)
            num++;
    }
    if (num < 0)
        return false;

    if (convmatch->in_state == 0) {
        /* First conv keyword to match, initialize matcher */
        int r = message_extract_cids(m, convmatch->cstate, &convmatch->cids);
        if (r) {
            xsyslog(LOG_ERR, "message_extract_cids", "err=<%s>",
                    error_message(r));
            convmatch->in_state = -1;
            return false;
        }
        uint64_t i;
        for (i = 0; i < arrayu64_size(&convmatch->cids); i++) {
            conversation_id_t cid = arrayu64_nth(&convmatch->cids, i);
            conversation_t conv = CONVERSATION_INIT;
            r = conversation_load_advanced(convmatch->cstate, cid, &conv, 0);
            if (r) {
                xsyslog(LOG_ERR, "conversation_load_advanced",
                        "cid=<%s> err=<%s>",
                        conversation_id_encode(convmatch->cstate->version, cid),
                        error_message(r));
                convmatch->in_state = -1;
                return 0;
            }
            dynarray_append(&convmatch->convs, &conv);
        }
        convmatch->in_state = 1;
    }

    if (!arrayu64_size(&convmatch->cids)) {
        return q->op == MATCHMIME_OP_CONVKEYWORD_NONE;
    }

    bool matches = q->op == MATCHMIME_OP_CONVKEYWORD_NONE ? 1 : 0;;
    int i;
    for (i = 0; i < dynarray_size(&convmatch->convs); i++) {
        conversation_t *conv = dynarray_nth(&convmatch->convs, i);
        /*
         * 0: no message has flag set
         * 1: some, but not all, messages have flag set
         * 2: all messages have flag set
         */
        int flagmatch = 0;
        if (num == 0 && conv->unseen != conv->exists)
            flagmatch = conv->unseen > 0 ? 1 : 2;
        else if (num > 0 && conv->counts[num-1])
            flagmatch = conv->exists > conv->counts[num-1] ? 1 : 2;

        if (flagmatch && q->op == MATCHMIME_OP_CONVKEYWORD_SOME) {
            matches = true;
            break;
        }
        if (flagmatch && q->op == MATCHMIME_OP_CONVKEYWORD_NONE) {
            matches = 0;
            break;
        }
        if (q->op == MATCHMIME_OP_CONVKEYWORD_ALL) {
            if (flagmatch < 2) {
                matches = false;
                break;
            }
            else {
                matches = true; // may get reset in next iteration
            }
        }
    }

    return matches;
}


static bool _matchmime_eval(matchmime_query_t *q,
                            message_t *m,
                            xapian_db_t *db,
                            struct convmatch *convmatch,
                            struct email_contactfilter *cfilter,
                            time_t internaldate)
{
    if (!q) return false;

    bool matches = false;

    switch (q->op) {
    case MATCHMIME_OP_AND:
    case MATCHMIME_OP_OR:
    case MATCHMIME_OP_NOT: {
        matches = q->op != MATCHMIME_OP_OR;
        for (int i = 0; i < ptrarray_size(&q->v.elems); i++) {
            matchmime_query_t *subq = ptrarray_nth(&q->v.elems, i);
            int cond_matches = _matchmime_eval(
                subq, m, db, convmatch, cfilter, internaldate);
            if (q->op == MATCHMIME_OP_AND && !cond_matches)
                return false;
            else if (q->op == MATCHMIME_OP_OR && cond_matches)
                return true;
            else if (q->op == MATCHMIME_OP_NOT && cond_matches)
                return false;
        }
        break;
    }
    case MATCHMIME_OP_MATCHALL:
        matches = true;
        break;
    case MATCHMIME_OP_MATCHNONE:
        matches = false;
        break;
    case MATCHMIME_OP_XAPIAN:
        xapian_query_run(db, q->v.xq, _matchmime_eval_xcb, &matches);
        break;
    case MATCHMIME_OP_MINSIZE:
    case MATCHMIME_OP_MAXSIZE: {
        uint32_t size;
        if (message_get_size(m, &size) == 0) {
            if (q->op == MATCHMIME_OP_MINSIZE && size >= q->v.u32)
                matches = true;
            else if (q->op == MATCHMIME_OP_MAXSIZE && size < q->v.u32)
                matches = true;
        }
        break;
    }
    case MATCHMIME_OP_HASATTACH: {
        const struct body *body;
        if (message_get_cachebody(m, &body) == 0) {
            bool has_att = jmap_email_hasattachment(body, NULL);
            matches = has_att == q->v.boolean;
        }
        break;
    }
    case MATCHMIME_OP_HEADER:
        matches = jmap_headermatch_match(q->v.hm, m);
        break;
    case MATCHMIME_OP_BEFORE:
        matches = internaldate < q->v.time;
        break;
    case MATCHMIME_OP_AFTER:
        matches = internaldate >= q->v.time;
        break;
    case MATCHMIME_OP_CONVKEYWORD_ALL:
    case MATCHMIME_OP_CONVKEYWORD_SOME:
    case MATCHMIME_OP_CONVKEYWORD_NONE:
        matches = _matchmime_eval_convkeyword(q, convmatch, m);
    }

    return matches;
}

HIDDEN void jmap_filter_parser_invalid(const char *field, void *rock)
{
    struct jmap_email_filter_parser_rock *frock =
        (struct jmap_email_filter_parser_rock *) rock;

    jmap_parser_invalid(frock->parser, field);
}

HIDDEN void jmap_filter_parser_push_index(const char *field, size_t index,
                                          const char *name, void *rock)
{
    struct jmap_email_filter_parser_rock *frock =
        (struct jmap_email_filter_parser_rock *) rock;

    jmap_parser_push_index(frock->parser, field, index, name);
}

HIDDEN void jmap_filter_parser_pop(void *rock)
{
    struct jmap_email_filter_parser_rock *frock =
        (struct jmap_email_filter_parser_rock *) rock;

    jmap_parser_pop(frock->parser);
}

HIDDEN void jmap_email_filtercondition_validate(const char *field, json_t *arg,
                                                void *rock)
{
    struct jmap_email_filter_parser_rock *frock =
        (struct jmap_email_filter_parser_rock *) rock;

    if (!strcmp(field, "inMailbox")) {
        if (!json_is_string(arg)) {
            jmap_parser_invalid(frock->parser, field);
        }
    }
    else if (!strcmp(field, "inMailboxOtherThan")) {
        if (!json_is_array(arg)) {
            jmap_parser_invalid(frock->parser, field);
        }
    }
    else if (!strcmp(field, "allInThreadHaveKeyword") ||
             !strcmp(field, "someInThreadHaveKeyword") ||
             !strcmp(field, "noneInThreadHaveKeyword")) {
        const char *s;

        if (!json_is_string(arg) ||
            !(s = json_string_value(arg)) ||
            !jmap_email_keyword_is_valid(s)) {
            jmap_parser_invalid(frock->parser, field);
        }
        else if (!_email_threadkeyword_is_valid(s)) {
            json_array_append_new(frock->unsupported,
                                  json_pack("{s:s}", field, s));
        }
    }
    else if (!strcmp(field, "hasKeyword") ||
             !strcmp(field, "notKeyword")) {
        if (!json_is_string(arg) ||
            !jmap_email_keyword_is_valid(json_string_value(arg))) {
            jmap_parser_invalid(frock->parser, field);
        }
    }
    else {
        jmap_parser_invalid(frock->parser, field);
    }
}

static int _matchmime_need_attachextract(json_t *jfilter)
{
    if (!jfilter) return 0;

    const char *criteria;
    json_t *jval;
    json_object_foreach(jfilter, criteria, jval) {
        if (!strcmp("text", criteria) ||
            !strcmp("attachmentBody", criteria)) {
            return 1;
        }
    }

    size_t i;
    json_array_foreach(json_object_get(jfilter, "conditions"), i, jval) {
        if (_matchmime_need_attachextract(jval))
            return 1;
    }

    return 0;
}

static int _matchmime_index_message(matchmime_t *matchmime, json_t *jfilter)
{
    if (matchmime->indexlevel &&
            !(matchmime->indexlevel & SEARCH_INDEXLEVEL_PARTIAL)) {
        /* This message already got fully indexed */
        return 0;
    }

    struct matchmime_receiver tr = {
        {
            _matchmime_tr_begin_mailbox,
            _matchmime_tr_first_unindexed_uid,
            _matchmime_tr_is_indexed,
            _matchmime_tr_begin_message,
            _matchmime_tr_begin_bodypart,
            _matchmime_tr_begin_part,
            _matchmime_tr_append_text,
            _matchmime_tr_end_part,
            _matchmime_tr_end_bodypart,
            _matchmime_tr_end_message,
            _matchmime_tr_end_mailbox,
            _matchmime_tr_flush,
            _matchmime_tr_audit_mailbox,
            _matchmime_tr_index_charset_flags,
            _matchmime_tr_index_message_format
        },
        matchmime, BUF_INITIALIZER,
        SEARCH_PART_NONE
    };

    /* Determine if we need to extract text from attachments for this
     * filter. Since matchmime may evaluate multiple filters for the
     * same message, we may end up indexing the same message twice:
     * first without calling the attachment extractor, then again with
     * calling it. This may result in two documents being indexed
     * for the same MIME message in the throwaway Xapian database. */
    int need_attachextract = _matchmime_need_attachextract(jfilter);
    int flags = INDEX_GETSEARCHTEXT_ALLOW_PARTIALS|
                INDEX_GETSEARCHTEXT_NOLOG_PARTIALS;
    if (!need_attachextract) {
        // suppress calling the attachment extractor
        flags |= INDEX_GETSEARCHTEXT_NOCALL_ATTACHEXTRACT;
    }

    int r = index_getsearchtext(matchmime->m, NULL,
            (struct search_text_receiver*) &tr, flags);
    buf_free(&tr.buf);
    return r;
}

HIDDEN matchmime_t *jmap_email_matchmime_new(const struct buf *mime, json_t **err)
{
    matchmime_t *matchmime = xzmalloc(sizeof(matchmime_t));
    int r = 0;

    matchmime->mime = mime;

    /* Parse message into memory */
    matchmime->m = message_new_from_data(buf_base(mime), buf_len(mime));
    if (!matchmime->m) {
        syslog(LOG_ERR, "jmap_matchmime: can't create Cyrus message");
        *err = jmap_server_error(r);
        jmap_email_matchmime_free(&matchmime);
        return NULL;
    }

    /* Open temporary database */
    matchmime->dbpath = create_tempdir(config_getstring(IMAPOPT_TEMP_PATH), "matchmime");
    if (!matchmime->dbpath) {
        syslog(LOG_ERR, "jmap_matchmime: can't create tempdir: %s", strerror(errno));
        *err = jmap_server_error(IMAP_INTERNAL);
        jmap_email_matchmime_free(&matchmime);
        return NULL;
    }

    /* Open search index in temp directory */
    const char *paths[2];
    paths[0] = matchmime->dbpath;
    paths[1] = NULL;
    r = xapian_dbw_open(paths, &matchmime->dbw, XAPIAN_DBW_NOSYNC);
    if (r) {
        syslog(LOG_ERR, "jmap_matchmime: can't open search backend: %s",
                error_message(r));
        *err = jmap_server_error(r);
        jmap_email_matchmime_free(&matchmime);
        return NULL;
    }

    matchmime->convmatch = xzmalloc(sizeof(struct convmatch));

    return matchmime;
}

HIDDEN void jmap_email_matchmime_free(matchmime_t **matchmimep)
{
    matchmime_t *matchmime = *matchmimep;
    if (!matchmime) return;

    if (matchmime->m) message_unref(&matchmime->m);
    if (matchmime->dbw) xapian_dbw_close(matchmime->dbw);
    if (matchmime->dbpath) removedir(matchmime->dbpath);
    free(matchmime->dbpath);

    struct convmatch *convmatch = matchmime->convmatch;
    convmatch_reset(convmatch, NULL);
    free(convmatch);

    free(matchmime);
    *matchmimep = NULL;
}

HIDDEN int jmap_email_matchmime(matchmime_t *matchmime,
                                json_t *jfilter,
                                struct conversations_state *cstate,
                                const char *accountid,
                                const struct auth_state *authstate,
                                const struct namespace *namespace,
                                time_t internaldate,
                                json_t **err)
{
    int r = 0;
    int matches = 0;

    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    strarray_t capabilities = STRARRAY_INITIALIZER;
    struct email_contactfilter cfilter;
    json_t *unsupported = json_array();
    struct jmap_email_filter_parser_rock frock = { &parser, unsupported } ;
    jmap_email_filter_parse_ctx_t parse_ctx = {
        &jmap_email_filtercondition_validate,
        &jmap_filter_parser_invalid,
        &jmap_filter_parser_push_index,
        &jmap_filter_parser_pop,
        &capabilities,
        &frock
    };

    /* Parse filter */
    strarray_append(&capabilities, JMAP_URN_MAIL);
    strarray_append(&capabilities, JMAP_MAIL_EXTENSION);
    jmap_email_filter_parse(jfilter, &parse_ctx);

    /* Gather contactgroup ids */
    jmap_email_contactfilter_init(accountid, authstate, namespace, NULL, &cfilter);
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

    /* Make sure the index is set up for this filter */
    r = _matchmime_index_message(matchmime, jfilter);
    if (r) {
        syslog(LOG_ERR, "jmap_matchmime: can't index MIME message: %s",
                error_message(r));
        *err = jmap_server_error(r);
        goto done;
    }

    /* Build filter */
    xapian_db_t *xdb = NULL;
    r = xapian_db_opendbw(matchmime->dbw, &xdb);
    if (r) {
        syslog(LOG_ERR, "jmap_matchmime: can't open query backend: %s",
                error_message(r));
        *err = jmap_server_error(r);
        goto done;
    }
    matchmime_query_t *q = _matchmime_buildquery(jfilter, xdb, &cfilter);

    /* Evaluate filter */
    struct convmatch *convmatch = matchmime->convmatch;
    if (!convmatch->cstate || convmatch->cstate != cstate || convmatch->in_state < 0) {
        convmatch_reset(convmatch, cstate);
    }
    matches = _matchmime_eval(q, matchmime->m, xdb,
            convmatch, &cfilter, internaldate);

    _matchmime_query_free(&q);
    xapian_db_close(xdb);

done:
    jmap_email_contactfilter_fini(&cfilter);
    jmap_parser_fini(&parser);
    strarray_fini(&capabilities);
    json_decref(unsupported);
    return matches ? 1 : 0;
}

#endif /* WITH_DAV */

static void headermatch_normalize(struct jmap_headermatch *hm, struct buf *val)
{
    if (!buf_len(val)) return;

    buf_cstring(val);
    buf_trim(val);

    /* Fast-path ASCII without consecutive whitespace */
    char *s;
    for (s = val->s; *s; s++) {
        if (!isascii(*s)) {
            break;
        }
        if (isspace(s[0]) && isspace(s[1])) {
            break;
        }
        *s = toupper(*s);
    }
    if (!*s) return;

    /* Convert value */
    buf_setcstr(val, charset_conv_convert(hm->conv, buf_cstring(val)));
}

static void jmap_headermatch_init(struct jmap_headermatch *hm)
{
    hm->utf8 = charset_lookupname("utf8");
    hm->conv = charset_conv_new(hm->utf8,
            CHARSET_SKIPDIACRIT|
            CHARSET_MERGESPACE|
            CHARSET_TRIMWS|
            CHARSET_UNORM_NFC);
}

HIDDEN struct jmap_headermatch *jmap_headermatch_new(const char *header,
                                                     const char *value,
                                                     const char *strop)
{
    struct jmap_headermatch *hm = xzmalloc(sizeof(struct jmap_headermatch));
    jmap_headermatch_init(hm);

    struct buf *val = &hm->tmp[0];

    if (!strcmpsafe(strop, "equals")) {
        hm->op = HEADERMATCH_EQUALS;
    }
    else if (!strcmpsafe(strop, "startsWith")) {
        hm->op = HEADERMATCH_STARTS;
    }
    else if (!strcmpsafe(strop, "endsWith")) {
        hm->op = HEADERMATCH_ENDS;
    }
    else {
        hm->op = HEADERMATCH_CONTAINS;
    }
    hm->header = lcase(xstrdup(header));
    buf_setcstr(val, value);
    headermatch_normalize(hm, val);
    hm->len = buf_len(val);
    hm->value = xstrdup(buf_cstring(val));

    buf_reset(&hm->tmp[1]);
    buf_reset(&hm->tmp[0]);
    return hm;
}

HIDDEN void jmap_headermatch_free(struct jmap_headermatch **hmp)
{
    if (!hmp || !*hmp) return;

    struct jmap_headermatch *hm = *hmp;

    free(hm->header);
    free(hm->value);
    buf_free(&hm->tmp[0]);
    buf_free(&hm->tmp[1]);
    buf_free(&hm->tmp[2]);
    charset_conv_free(&hm->conv);
    charset_free(&hm->utf8);
    free(hm);
    *hmp = NULL;
}

HIDDEN struct jmap_headermatch *jmap_headermatch_dup(struct jmap_headermatch *hm)
{
    if (!hm) return NULL;

    struct jmap_headermatch *hm2 = xzmalloc(sizeof(struct jmap_headermatch));
    jmap_headermatch_init(hm2);
    hm2->op = hm->op;
    hm2->header = xstrdup(hm->header);
    hm2->value = xstrdup(hm->value);
    hm2->len = hm->len;
    return hm2;
}

HIDDEN int jmap_headermatch_match(struct jmap_headermatch *hm, message_t *msg)
{
    int match = 0;

    struct buf *msgbuf = &hm->tmp[0];

    if (!message_get_field(msg, hm->header,
                MESSAGE_RAW|MESSAGE_APPEND|MESSAGE_MULTIPLE, msgbuf)) {

        if (!buf_len(msgbuf)) {
            match = 0;
            goto done;
        }
        else if (!*hm->value) {
            match = 1;
            goto done;
        }

        /* Iterate header values until match found */
        const char *p = buf_cstring(msgbuf);
        do {
            struct buf *val = &hm->tmp[1];

            /* Extract value, including optional line folds */
            const char *q;
            for (q = p; *q; q++) {
                if (*q == '\r') {
                    if (q[1] == '\n' && (q[2] == '\t' || q[2] == ' ')) {
                        q++;
                    }
                    else {
                        break;
                    }
                }
            }
            buf_setmap(val, p, q - p);

            /* Match header value */
            headermatch_normalize(hm, val);
            if (buf_len(val) >= hm->len) {
                const char *v = buf_cstring(val);
                switch (hm->op) {
                    case HEADERMATCH_EQUALS:
                        match = !strcmp(v, hm->value);
                        break;
                    case HEADERMATCH_STARTS:
                        match = !strncmp(v, hm->value, hm->len);
                        break;
                    case HEADERMATCH_ENDS:
                        match = !strcmp(v + buf_len(val) - hm->len, hm->value);
                        break;
                    default:
                        match = strstr(v, hm->value) != NULL;
                }
            }

            /* Find next header value, if any */
            if (*q) q += (q[1] == '\n') ? 2 : 1;
            p = q;
            q = strchr(p, ':');
            if (q) p = q + 1;
        } while(!match && *p);
    }

done:
    buf_reset(&hm->tmp[0]);
    buf_reset(&hm->tmp[1]);
    buf_reset(&hm->tmp[2]);
    return match;
}

HIDDEN void jmap_headermatch_serialize(struct jmap_headermatch *hm, struct buf *buf)
{
    buf_appendcstr(buf, hm->header);
    buf_putc(buf, ';');
    buf_appendcstr(buf, hm->value);
    buf_putc(buf, ';');
    switch (hm->op) {
    case HEADERMATCH_EQUALS:
        buf_appendcstr(buf, "equals");
        break;
    case HEADERMATCH_STARTS:
        buf_appendcstr(buf, "starts");
        break;
    case HEADERMATCH_ENDS:
        buf_appendcstr(buf, "ends");
        break;
    case HEADERMATCH_CONTAINS:
        buf_appendcstr(buf, "contains");
        break;
    }
}
