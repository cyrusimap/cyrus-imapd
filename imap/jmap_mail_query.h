/* jmap_mail_query.h - Helper routines for JMAP Email queries. */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef JMAP_MAIL_QUERY_H
#define JMAP_MAIL_QUERY_H

#include <jansson.h>

#include "strarray.h"

#include "jmap_mail_query_parse.h"
#include "jmap_util.h"

#ifdef WITH_DAV

#include <time.h>

#include "auth.h"
#include "hash.h"
#include "ptrarray.h"

#include "carddav_db.h"
#include "message.h"

struct email_contactfilter {
    const char *accountid;
    const struct auth_state *authstate;
    const struct namespace *namespace;
    hash_table contactgroups; /* maps groupid to emails (strarray) */
};

extern void jmap_email_contactfilter_init(const char *accountid,
                                          const struct auth_state *authstate,
                                          const struct namespace *namespace,
                                          struct email_contactfilter *cfilter);
extern void jmap_email_contactfilter_fini(struct email_contactfilter *cfilter);

extern int jmap_email_contactfilter_from_filtercondition(json_t *filter,
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
typedef struct matchmime matchmime_t;
extern matchmime_t *jmap_email_matchmime_new(const struct buf *buf, json_t **err);
extern void jmap_email_matchmime_free(matchmime_t **matchmimep);
extern int jmap_email_matchmime(matchmime_t *matchmime,
                                json_t *jfilter,
                                struct conversations_state *cstate,
                                const char *accountid,
                                const struct auth_state *authstate,
                                const struct namespace *ns,
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

extern void jmap_headermatch_serialize(struct jmap_headermatch*, struct buf*);


/* Set of addressbooks owned by userid and accessible by accountId */
struct abook_set {
    char *userid;
    struct carddav_db *carddavdb;  // DAV DB for userid
    ptrarray_t mbentrys;           // NULL = ALL abooks owned by userid
};

/* Given an 'accountid', along with its 'authstate', 'namespace', 'carddavdb',
   return an array of 'abook_sets' corresponding to ALL addressbooks
   to which accountid has access.
*/
extern ptrarray_t *jmap_get_accessible_addressbooks(const char *accountid,
                                                    const struct auth_state *authstate,
                                                    const struct namespace *namespace,
                                                    struct carddav_db *carddavdb);

/* Free an array of 'abook_sets' */
extern void jmap_free_abook_sets(ptrarray_t *abook_sets);

/* Lookup 'card_uids' of 'card_kind' in the array of 'abook_sets'
   and return an array of 'emails' contained in those cards, and optionally
   return an array of 'member_uids' contained in any group cards. */
extern void jmap_get_card_emails(strarray_t *card_uids, unsigned card_kind,
                                 ptrarray_t *abook_sets,
                                 strarray_t *emails, strarray_t **member_uids);

#endif /* WITH_DAV */

#endif /* JMAP_MAIL_QUERY_H */
