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

EXPORTED void loginlog_good_full(const char *clienthost,
                                 sasl_conn_t *saslconn,
                                 const char *scheme,
                                 const char *override_username,
                                 const char *override_mech,
                                 loginlog_extras *extras)
{
    struct logfmt lf = LOGFMT_INITIALIZER;
    const char *username = override_username;
    const char *mech = override_mech;

    if (saslconn) {
        if (!username)
            sasl_getprop(saslconn, SASL_USERNAME, (const void **) &username);

        if (!mech)
            sasl_getprop(saslconn, SASL_MECHNAME, (const void **) &mech);
    }

    logfmt_begin(&lf, "login.good");
    logfmt_push(&lf, "session_id", session_id());

    logfmt_push(&lf, "r.clienthost", clienthost);
    logfmt_push(&lf, "u.username", username);

    /* only log anonymous login details if it was an anonymous login */
    if (extras && extras->is_anonymous) {
        logfmt_push(&lf, "login.anonymous", "1");
        if (extras->anonpassword)
            logfmt_push(&lf, "login.password", extras->anonpassword);
    }

    /* only log nopassword flag if it's true */
    if (extras && extras->is_nopassword)
        logfmt_push(&lf, "login.nopassword", "1");

    /* only log magicplus if it's set */
    if (extras && extras->magicplus)
        logfmt_push(&lf, "login.magic", extras->magicplus);

    logfmt_push(&lf, "login.mech", mech);

    /* only log scheme if it's set */
    if (scheme)
        logfmt_push(&lf, "login.scheme", scheme);

    /* always log tls flag */
    logfmt_push(&lf, "login.tls", extras && extras->is_tls ? "1" : "0");

    /* only log popsubfolder if it's set */
    if (extras && extras->popsubfolder)
        logfmt_push(&lf, "pop.subfolder", extras->popsubfolder);

    syslog(LOG_NOTICE, "%s", logfmt_cstring(&lf));
    logfmt_finish(&lf);
}

EXPORTED void loginlog_bad_full(const char *clienthost,
                                sasl_conn_t *saslconn,
                                const char *scheme,
                                const char *override_username,
                                const char *override_mech,
                                const char *override_error)
{
    struct logfmt lf = LOGFMT_INITIALIZER;
    const char *username = override_username;
    const char *mech = override_mech;
    const char *error = override_error;

    if (saslconn) {
        if (!username)
            sasl_getprop(saslconn, SASL_USERNAME, (const void **) &username);

        if (!mech)
            sasl_getprop(saslconn, SASL_MECHNAME, (const void **) &mech);

        if (!error)
            error = sasl_errdetail(saslconn);
    }

    logfmt_begin(&lf, "login.bad");

    logfmt_push(&lf, "r.clienthost", clienthost);
    logfmt_push(&lf, "u.username", username);

    logfmt_push(&lf, "login.mech", mech);

    /* only log scheme if it's set */
    if (scheme)
        logfmt_push(&lf, "login.scheme", scheme);

    logfmt_push(&lf, "error", error);

    syslog(LOG_NOTICE, "%s", logfmt_cstring(&lf));
    logfmt_finish(&lf);
}
