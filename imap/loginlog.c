/* loginlog - login logging API
 *
 * Copyright (c) 1994-2025 Carnegie Mellon University.  All rights reserved.
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

#include "imap/loginlog.h"

#include "lib/logfmt.h"
#include "lib/sessionid.h"

#include <syslog.h>

static void loginlog_good_begin(struct logfmt *lf,
                                const char *clienthost,
                                const char *username,
                                const char *mech,
                                bool tls)
{
    logfmt_init(lf, "login.good");
    logfmt_push_session(lf);

    logfmt_push(lf, "r.clienthost", clienthost);

    if (username)
        logfmt_push(lf, "u.username", username);

    if (mech)
        logfmt_push(lf, "login.mech", mech);

    logfmt_push(lf, "login.tls", tls ? "1" : "0");
}

static void loginlog_good_finish(struct logfmt *lf)
{
    syslog(LOG_NOTICE, "%s", logfmt_cstring(lf));
    logfmt_fini(lf);
}

EXPORTED void loginlog_good(const char *clienthost,
                            const char *username,
                            const char *mech,
                            bool tls)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    loginlog_good_begin(&lf, clienthost, username, mech, tls);
    loginlog_good_finish(&lf);
}

EXPORTED void loginlog_good_imap(const char *clienthost,
                                 const char *username,
                                 const char *mech,
                                 bool tls,
                                 const char *magicplus,
                                 bool nopassword)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    loginlog_good_begin(&lf, clienthost, username, mech, tls);

    logfmt_push(&lf, "login.magic", magicplus);

    if (nopassword)
        logfmt_push(&lf, "login.nopassword", "1");

    loginlog_good_finish(&lf);
}

EXPORTED void loginlog_good_pop(const char *clienthost,
                                const char *username,
                                const char *mech,
                                bool tls,
                                const char *subfolder)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    loginlog_good_begin(&lf, clienthost, username, mech, tls);

    logfmt_push(&lf, "pop.subfolder", subfolder);

    loginlog_good_finish(&lf);
}

EXPORTED void loginlog_anon(const char *clienthost,
                            const char *mech,
                            bool tls,
                            const char *password)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    loginlog_good_begin(&lf, clienthost, NULL, mech, tls);

    logfmt_push(&lf, "login.anonymous", "1");

    if (password)
        logfmt_push(&lf, "login.password", password);

    loginlog_good_finish(&lf);
}

EXPORTED void loginlog_bad(const char *clienthost,
                           const char *username,
                           const char *mech,
                           const char *scheme,
                           const char *error)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    logfmt_init(&lf, "login.bad");

    logfmt_push(&lf, "r.clienthost", clienthost);
    logfmt_push(&lf, "u.username", username);

    /* only log mech if it's set */
    if (mech)
        logfmt_push(&lf, "login.mech", mech);

    /* only log scheme if it's set */
    if (scheme)
        logfmt_push(&lf, "login.scheme", scheme);

    logfmt_push(&lf, "error", error);

    syslog(LOG_NOTICE, "%s", logfmt_cstring(&lf));
    logfmt_fini(&lf);
}
