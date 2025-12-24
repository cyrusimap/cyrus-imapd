/* loginlog - login logging API */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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

EXPORTED void loginlog_good_http(const char *clienthost,
                                 const char *username,
                                 const char *scheme,
                                 bool tls)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    loginlog_good_begin(&lf, clienthost, username, NULL, tls);

    logfmt_push(&lf, "login.scheme", scheme);

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
