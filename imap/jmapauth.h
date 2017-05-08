/* jmapauth.h -- Routines for JMAP authentication
 *
 * Copyright (c) 1994-2016 Carnegie Mellon University.  All rights reserved.
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

#ifndef JMAPAUTH_H
#define JMAPAUTH_H

#include "cyrusdb.h"

#define JMAPAUTH_SESSIONID_LEN  16   /* byte lenth of random session id */
#define JMAPAUTH_SECRET_LEN 16       /* server secret to sign token */

#define JMAPAUTH_LOGINID_KIND 'L'    /* token kind for login ids */
#define JMAPAUTH_ACCESS_KIND 'A'     /* token kind for access tokens */

#define JMAPAUTH_TOKEN_TTL_WINDOW 60 /* grace-period in seconds until the
                                        user-configured ttl of access tokens
                                        is enforced. This parameter allows to
                                        avoid db-writes for every token use */

struct jmapauth_token {
    /* Client-facing identifier */
    char version;
    char kind;
    char sessionid[JMAPAUTH_SESSIONID_LEN];

    /* Server-only session data */
    char *userid;
    time_t lastuse;
    char flags;
    const void *data; /* ONLY valid until the next database operation */
    size_t datalen;

    char secret[JMAPAUTH_SECRET_LEN];
};

extern int jmapauth_open(struct db **dbptr, int db_flags, const char *fname);

#define JMAPAUTH_FETCH_LOCK    1<<1

extern int jmapauth_fetch(struct db *db, const char *tokenid,
                          struct jmapauth_token **tokptr, int fetch_flags,
                          struct txn **tidptr);
extern int jmapauth_store(struct db *db, struct jmapauth_token *tok, struct txn **tidptr);
extern int jmapauth_delete(struct db *db, const char *tokenid, struct txn **tidptr);
extern int jmapauth_close(struct db *db);

typedef int (*jmapauth_find_proc_t)(struct db *db, struct jmapauth_token *tok,
                                    void* rock, struct txn **tidptr);

extern int jmapauth_find(struct db *db,
                         const char *userid, int expired,
                         time_t lastuse, char kind,
                         jmapauth_find_proc_t proc, void *rock,
                         struct txn **tidptr);

extern struct jmapauth_token* jmapauth_token_new(const char *userid,
                                                 char kind,
                                                 const void *data,
                                                 size_t datalen);
extern void jmapauth_token_free(struct jmapauth_token *tok);
extern char* jmapauth_tokenid(const struct jmapauth_token *tok);
extern int jmapauth_is_expired(struct jmapauth_token *tok);


#endif /* JMAPAUTH_H */
