/* auditlog - audit logging API
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

#include "imap/auditlog.h"

#include "lib/sessionid.h"

#include <syslog.h>

static inline void auditlog_begin(struct buf *buf, const char *action)
{
    const char *traceid = trace_id();

    buf_reset(buf);
    buf_printf(buf, "auditlog: %s", action);

    if (session_have_id()) {
        buf_appendmap(buf, " sessionid=<", 12);
        buf_appendcstr(buf, session_id());
        buf_putc(buf, '>');
    }
    if (traceid) {
        buf_appendmap(buf, " r.tid=<", 8);
        buf_appendcstr(buf, traceid);
        buf_putc(buf, '>');
    }
}

static inline void auditlog_push(struct buf *buf,
                                 const char *key,
                                 const char *value)
{
    buf_printf(buf, " %s=<%s>", key, value);
}

static inline void auditlog_finish(struct buf *buf)
{
    syslog(LOG_NOTICE, "%s", buf_cstring(buf));
    buf_free(buf);
}

/*
 * Partially-exposed internals for cunit tests
 */

HIDDEN void hidden_auditlog_begin(struct buf *buf, const char *action)
{
    return auditlog_begin(buf, action);
}

HIDDEN void hidden_auditlog_push(struct buf *buf,
                                 const char *key,
                                 const char *value)
{
    return auditlog_push(buf, key, value);
}

HIDDEN void hidden_auditlog_finish(struct buf *buf)
{
    return auditlog_finish(buf);
}

/*
 * Public API
 */

EXPORTED void auditlog_mboxname(const char *action,
                                const char *userid,
                                const char *mboxname)
{
    struct buf buf = BUF_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&buf, action);

    if (userid) {
        auditlog_push(&buf, "userid", userid);
    }

    if (mboxname) {
        /* XXX convert to consistent namespace? */
        auditlog_push(&buf, "mailbox", mboxname);
    }

    auditlog_finish(&buf);
}

EXPORTED void auditlog_quota(const char *action,
                             const char *root,
                             const quota_t *oldquotas,
                             const quota_t *newquotas)
{
    struct buf buf = BUF_INITIALIZER;
    int resource;

    if (!config_auditlog) return;

    auditlog_begin(&buf, action);
    auditlog_push(&buf, "root", root);

    for (resource = 0; resource < QUOTA_NUMRESOURCES; resource++) {
        if (oldquotas) {
            buf_printf(&buf, " old%s=<%lld>",
                             quota_names[resource],
                             oldquotas[resource]);
        }

        if (newquotas) {
            buf_printf(&buf, " new%s=<%lld>",
                             quota_names[resource],
                             newquotas[resource]);
        }
    }

    auditlog_finish(&buf);
}

EXPORTED void auditlog_traffic(uint64_t bytes_in, uint64_t bytes_out)
{
    struct buf buf = BUF_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&buf, "traffic");
    buf_printf(&buf, " bytes_in=<%" PRIu64 ">"
                     " bytes_out=<%" PRIu64 ">",
                     bytes_in, bytes_out);
    auditlog_finish(&buf);
}
